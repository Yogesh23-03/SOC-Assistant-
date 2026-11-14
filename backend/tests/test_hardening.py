"""Regression coverage for the M2 approval-chain security findings."""
import concurrent.futures
import sqlite3
from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.app import app
from backend.database import init_db, get_db
from backend.executor import execute_approved_action, global_rate_limiter, expire_active_blocks, list_active_blocks, TokenReplayError
from backend.security import create_analyst_token, generate_signed_approval_token, verify_approval_token, verify_and_consume_nonce
from backend.storage import save_proposal, update_proposal_status


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = str(tmp_path / 'security.sqlite')
    monkeypatch.setattr('backend.database.DATABASE_PATH', path)
    init_db(path)
    global_rate_limiter.reset()
    yield path
    global_rate_limiter.reset()


@pytest.fixture
def token(database):
    proposal = save_proposal('regression', 'alert', 'block_ip', '198.51.100.42', 'test', ttl_seconds=3600)
    update_proposal_status('regression', 'approved', 'analyst.test')
    return generate_signed_approval_token(proposal, 'decision-nonce-123')


def test_all_api_routes_require_auth(database):
    with TestClient(app) as client:
        for route in app.routes:
            if route.path.startswith('/api/'):
                for method in route.methods:
                    for headers in ({}, {'Authorization': 'Bearer bogus'}, {'Authorization': 'Basic bogus'}):
                        response = client.request(method, route.path.replace('{proposal_id}', 'x').replace('{index}', '0'), headers=headers)
                        assert response.status_code == 401, (method, route.path, response.text)
        assert client.post('/auth/token', json={'analyst_id': 'attacker'}).status_code == 401
        headers = {'Authorization': 'Bearer ' + create_analyst_token('analyst.test')}
        assert client.get('/api/proposals/pending', headers=headers).status_code == 200
        assert client.post('/auth/token', headers=headers, json={'analyst_id': 'someone.else'}).status_code == 403


def test_websocket_auth_and_identity(database):
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect('/ws/analyst'):
                pass
        with client.websocket_connect('/ws/analyst?token=' + create_analyst_token('analyst.test')) as ws:
            ws.send_json({'type': 'decision', 'analyst_id': 'attacker'})
            assert ws.receive_json()['status_code'] == 403


def test_ttl_is_signed_and_required(token):
    assert verify_approval_token(token)[0]
    assert not verify_approval_token(dict(token, ttl_seconds=2000000000))[0]
    del token['ttl_seconds']
    assert not verify_approval_token(token)[0]


def test_proposal_ttl(database):
    proposal = save_proposal('ttl', 'alert', 'block_ip', '198.51.100.10', 'test', ttl_seconds=3600)
    assert (datetime.fromisoformat(proposal['expires_at']) - datetime.fromisoformat(proposal['created_at'])).total_seconds() == 3600


def test_replay_returns_409_without_extending_block(database, token):
    headers = {'Authorization': 'Bearer ' + create_analyst_token('analyst.test')}
    with TestClient(app) as client, patch('backend.executor.apply_iptables_block', return_value=(True, 'applied')) as apply:
        assert client.post('/api/executor/apply', headers=headers, json=token).status_code == 200
        before = list_active_blocks()
        assert client.post('/api/executor/apply', headers=headers, json=token).status_code == 409
        assert list_active_blocks() == before
        assert apply.call_count == 1


def test_concurrent_execution_is_once(database, token):
    def execute():
        try:
            return execute_approved_action(token)['status']
        except TokenReplayError:
            return 'replay'
    with patch('backend.executor.apply_iptables_block', return_value=(True, 'applied')) as apply:
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            assert sorted(pool.map(lambda _: execute(), range(2))) == ['replay', 'success']
        assert apply.call_count == 1


def test_proposal_must_remain_approved(database, token):
    update_proposal_status('regression', 'rejected', 'analyst.test')
    with patch('backend.executor.apply_iptables_block') as apply:
        with pytest.raises(PermissionError):
            execute_approved_action(token)
        apply.assert_not_called()


def test_windows_returns_explicit_503(database, token):
    with TestClient(app) as client, patch('backend.executor.platform.system', return_value='Windows'):
        response = client.post('/api/executor/apply', json=token, headers={'Authorization': 'Bearer ' + create_analyst_token('analyst.test')})
        assert response.status_code == 503
        assert 'unsupported platform' in response.text.lower()
        assert list_active_blocks() == []


def test_simulation_has_no_active_block(database, token):
    assert execute_approved_action(token, dry_run=True)['status'] == 'simulated'
    assert list_active_blocks() == []
    with get_db() as conn:
        assert not conn.execute("SELECT 1 FROM used_nonces WHERE nonce LIKE 'executor:%'").fetchone()
        actions = [r['action'] for r in conn.execute('SELECT action FROM audit_log')]
    assert 'firewall.simulated' in actions
    assert 'firewall.rule_applied' not in actions


def test_nonce_infrastructure_error_propagates(database):
    with patch('backend.security.get_db', side_effect=sqlite3.OperationalError('locked')):
        with pytest.raises(sqlite3.OperationalError):
            verify_and_consume_nonce('nonce-123456', 'proposal')


def test_reaper_preserves_failed_deletion(database):
    with get_db() as conn:
        conn.execute("INSERT INTO active_blocks VALUES ('198.51.100.1', 'old', '2020', '2020', 'active')")
    with patch('backend.executor.remove_iptables_block', return_value=(False, 'sudo denied')):
        assert expire_active_blocks() == []
    assert len(list_active_blocks()) == 1
    with patch('backend.executor.remove_iptables_block', return_value=(True, 'removed')):
        assert expire_active_blocks() == ['198.51.100.1']


@pytest.mark.parametrize('secret_value', ['', 'soc-insecure-dev-jwt-key-change-in-production'])
def test_startup_rejects_unsafe_secrets(secret_value):
    import os
    import subprocess
    import sys
    env = dict(os.environ, SOC_JWT_SECRET=secret_value)
    result = subprocess.run([sys.executable, '-c', 'import backend.config'], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert 'Set SOC_JWT_SECRET' in result.stderr


def test_firewall_failure_is_503_and_rate_limit_is_429(database, token):
    headers = {'Authorization': 'Bearer ' + create_analyst_token('analyst.test')}
    with TestClient(app) as client, patch('backend.executor.apply_iptables_block', return_value=(False, 'sudo denied')):
        response = client.post('/api/executor/apply', headers=headers, json=token)
        assert response.status_code == 503
        assert 'sudo denied' in response.text
        # Even rate-limited replays are identified as spent.
        with patch.object(global_rate_limiter, 'allow_request', return_value=(False, 'rate limit')):
            assert client.post('/api/executor/apply', headers=headers, json=token).status_code == 409
    second = save_proposal('second', 'alert', 'block_ip', '198.51.100.43', 'test')
    update_proposal_status('second', 'approved', 'analyst.test')
    with TestClient(app) as client, patch.object(global_rate_limiter, 'allow_request', return_value=(False, 'rate limit')):
        assert client.post('/api/executor/apply', headers=headers, json=generate_signed_approval_token(second, 'second-nonce')).status_code == 429
