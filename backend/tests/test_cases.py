"""Case persistence, reports, review jobs and provider-cache integration tests."""
import asyncio
import json
from unittest.mock import patch
import httpx
import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.audit import get_audit_entries, verify_audit_chain
from backend.cases import get_case
from backend.database import init_db, get_db
from backend.ingest import ingest_and_process_alert
from backend.maintenance import run_next_review
from backend.approval import process_analyst_decision
from backend.providers import reputation
from backend.reports import render_pdf
from backend.security import create_analyst_token
from backend.storage import get_proposal, get_pending_proposals
from backend.tests.test_ingest import make_test_llm
from tests.fakes import reply, tool_call


@pytest.fixture
def case_db(tmp_path, monkeypatch):
    path = str(tmp_path / 'cases.sqlite')
    monkeypatch.setattr('backend.database.DATABASE_PATH', path)
    monkeypatch.setenv('SOC_DATA_MODE', 'fixture')
    init_db(path)
    return path


def alert():
    return dict(alert_id='durable', timestamp='2026-11-14T12:00:00Z', source_ip='198.51.100.23',
                rule_name='SSH brute force', host='server-01', severity='high', log_text='<script>alert(1)</script> Failed password')


def attack_llm():
    return make_test_llm(json.dumps(dict(label='true_attack', confidence=.95, reasoning='Repeated failures', explanation='Review attacker')),
        reply(None, [tool_call('search_logs', {'ip': '198.51.100.23'})]), reply('Investigation complete'),
        json.dumps(dict(action='block_ip', target='198.51.100.23', reason='Repeated attack', explanation='Propose containment')))


def ingest_attack():
    return asyncio.run(ingest_and_process_alert(alert(), llm=attack_llm()))


def test_persistent_case_report_and_tool_audit(case_db):
    result = ingest_attack()
    case = get_case('durable')
    assert case['findings'] and case['tools']
    assert case['runs'][0]['alert']['log_text'].startswith('<script>')
    from agents.investigation import clear_findings
    clear_findings()
    assert get_case('durable')['findings'] == case['findings']
    actions = [entry['action'] for entry in get_audit_entries()]
    assert 'tool.completed' in actions and 'finding.recorded' in actions
    assert verify_audit_chain()[0]
    headers = {'Authorization': 'Bearer ' + create_analyst_token('analyst.demo')}
    with TestClient(app) as client:
        assert client.get('/api/cases/durable/report?format=pdf').status_code == 401
        text = client.get('/api/cases/durable/report', headers=headers)
        assert 'No recorded firewall application' in text.text
        assert '<script>alert(1)</script>' in text.text
        pdf = client.get('/api/cases/durable/report?format=pdf', headers=headers)
        assert pdf.content.startswith(b'%PDF-1.4') and pdf.content.endswith(b'%%EOF\n')
        assert pdf.headers['content-type'] == 'application/pdf'
        assert client.get('/api/cases/missing', headers=headers).status_code == 404
        assert client.get('/api/metrics', headers=headers).json()['alerts_handled'] == 1
        assert client.get('/api/session', headers=headers).json()['analyst_id'] == 'analyst.demo'
    assert result['proposal']['status'] == 'pending'


def test_review_creates_fresh_proposal_without_approval(case_db):
    first = ingest_attack()['proposal']
    result = process_analyst_decision(first['proposal_id'], 'investigate_more', 'analyst.demo', 'review-nonce-first')
    assert result['proposal']['status'] == 'investigating'
    assert result['signed_token'] is None
    assert asyncio.run(run_next_review(llm=attack_llm()))
    latest = get_case('durable')
    assert len(latest['runs']) == 2
    pending = get_pending_proposals()
    assert len(pending) == 1 and pending[0]['proposal_id'] != first['proposal_id']
    assert get_proposal(first['proposal_id'])['status'] == 'rejected'
    assert not asyncio.run(run_next_review(llm=attack_llm()))


def test_failed_review_is_visible_and_retryable(case_db):
    first = ingest_attack()['proposal']
    process_analyst_decision(first['proposal_id'], 'investigate_more', 'analyst.demo', 'review-nonce-failure')
    with patch('backend.maintenance.ingest_and_process_alert', side_effect=RuntimeError('unavailable')):
        asyncio.run(run_next_review())
    with get_db() as conn:
        assert conn.execute('SELECT status FROM investigation_jobs').fetchone()[0] == 'failed'
    from backend.app import retry_review
    assert retry_review(first['proposal_id'], 'analyst.demo') == {'status': 'queued'}
    assert asyncio.run(run_next_review(llm=attack_llm()))


def test_websocket_subprotocol_authentication(case_db):
    protocol = 'soc.auth.' + create_analyst_token('analyst.demo')
    with TestClient(app) as client:
        with client.websocket_connect('/ws/analyst', subprotocols=[protocol]) as ws:
            assert ws.accepted_subprotocol == protocol
            ws.send_json({'type': 'ping'})
            assert ws.receive_json()['type'] == 'pong'


def test_pdf_paginates_and_escapes_untrusted_text():
    pdf = render_pdf(') Tj /JavaScript (\\\n' * 150)
    assert b'/Count 4' in pdf
    assert b'\\) Tj /JavaScript \\(' in pdf
    assert b'/OpenAction' not in pdf


def test_provider_cache_and_private_ip_policy(case_db, monkeypatch):
    monkeypatch.setenv('ABUSEIPDB_API_KEY', 'test-only-key')
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(200, json={'data': {'abuseConfidenceScore': 90, 'totalReports': 12}})
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        assert reputation('10.0.0.1', client=client)['reputation'] == 'unknown'
        assert calls == []
        assert reputation('8.8.8.8', client=client)['score'] == 90
        assert reputation('8.8.8.8', client=client)['providers'][0]['cached']
        assert len(calls) == 1
        with get_db() as conn:
            conn.execute('UPDATE intel_cache SET fetched_at=0')
        with patch.object(client, 'get', side_effect=httpx.ConnectError('offline')):
            result = reputation('8.8.8.8', client=client)
            assert result['providers'][0]['stale']


def test_cleanup_is_scheduled_without_http_request(case_db, monkeypatch):
    from backend.maintenance import maintenance_loop
    monkeypatch.setenv('SOC_REAPER_INTERVAL_SECONDS', '1')
    async def scenario():
        from contextlib import suppress
        with patch('backend.maintenance.expire_active_blocks', return_value=[]) as cleanup:
            task = asyncio.create_task(maintenance_loop())
            for _ in range(100):
                if cleanup.called:
                    break
                await asyncio.sleep(.01)
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            assert cleanup.called
    asyncio.run(scenario())


def test_execution_on_approval_requires_explicit_setting(case_db, monkeypatch):
    from backend.app import publish_decision
    proposal = ingest_attack()['proposal']
    decision = process_analyst_decision(proposal['proposal_id'], 'approve', 'analyst.demo', 'optional-execution-nonce')
    monkeypatch.setenv('SOC_EXECUTE_ON_APPROVAL', 'false')
    with patch('backend.app.execute_approved_action', return_value={'status': 'success'}) as execute:
        asyncio.run(publish_decision(decision))
        execute.assert_not_called()
        monkeypatch.setenv('SOC_EXECUTE_ON_APPROVAL', 'true')
        asyncio.run(publish_decision(decision))
        execute.assert_called_once_with(decision['signed_token'])


def test_live_benchmark_counts_unsafe_auto_closes():
    from backend.benchmark import summarize
    rows = [dict(expected='true_attack', predicted='false_positive', seconds=1, action='none', executed=False),
            dict(expected='false_positive', predicted='false_positive', seconds=2, action='none', executed=False),
            dict(expected='suspicious', predicted='suspicious', seconds=3, action='escalate', executed=False)]
    result = summarize(rows, 'live')
    assert result['unsafe_auto_close_count'] == 1
    assert result['false_positive_auto_close_rate'] == 1
    assert result['measured_model_accuracy'] == .6667
    assert result['median_alert_to_proposal_seconds'] == 3
    assert summarize(rows, 'offline')['measured_model_accuracy'] is None


def test_log_feed_parses_only_supported_authentication_lines():
    from backend.feed import auth_alert
    assert auth_alert('sshd: Failed password for root from 192.0.2.1 port 555 ssh2', 'target')['source_ip'] == '192.0.2.1'
    assert auth_alert('sshd: Failed password for root from 999.0.2.1 port 555 ssh2', 'target') is None
    assert auth_alert('Unrelated kernel message', 'target') is None
