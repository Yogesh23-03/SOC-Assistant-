"""Durable case runs, evidence and report data. No model-written HTML."""
import json
from uuid import uuid4
from backend.audit import get_utc_timestamp, log_audit_event
from backend.database import get_db


def start_run(alert, db_path=None):
    run_id = uuid4().hex
    with get_db(db_path) as conn:
        conn.execute('INSERT INTO case_runs (run_id, alert_id, alert_json, status, started_at) VALUES (?, ?, ?, ?, ?)',
                     (run_id, alert['alert_id'], json.dumps(alert), 'analyzing', get_utc_timestamp()))
    return run_id


def observe_tool(run_id, alert_id, tool, arguments, result, db_path=None):
    details = dict(run_id=run_id, alert_id=alert_id, tool=tool, arguments=arguments, result=result)
    with get_db(db_path) as conn:
        conn.execute('INSERT INTO tool_observations (run_id, alert_id, tool, arguments, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                     (run_id, alert_id, tool, arguments, json.dumps(result), get_utc_timestamp()))
    log_audit_event('agent.investigation', 'tool.completed', details, db_path=db_path)


def finish_run(run_id, result, db_path=None):
    with get_db(db_path) as conn:
        conn.execute('UPDATE case_runs SET result_json=?, status=?, finished_at=? WHERE run_id=?',
                     (json.dumps(result), result['status'], get_utc_timestamp(), run_id))
    for finding in result.get('findings', []):
        log_audit_event('agent.investigation', 'finding.recorded', dict(run_id=run_id, **finding), db_path=db_path)


def fail_run(run_id, db_path=None):
    with get_db(db_path) as conn:
        conn.execute("UPDATE case_runs SET status='failed', error='Analysis failed; review server logs', finished_at=? WHERE run_id=?",
                     (get_utc_timestamp(), run_id))


def get_case(alert_id, db_path=None):
    with get_db(db_path) as conn:
        runs = [dict(r) for r in conn.execute('SELECT * FROM case_runs WHERE alert_id=? ORDER BY started_at, rowid', (alert_id,))]
        if not runs:
            return None
        proposals = [dict(r) for r in conn.execute('SELECT * FROM proposals WHERE alert_id=? ORDER BY created_at', (alert_id,))]
        tools = [dict(r) for r in conn.execute('SELECT * FROM tool_observations WHERE alert_id=? ORDER BY observation_id', (alert_id,))]
        jobs = [dict(r) for r in conn.execute('SELECT * FROM investigation_jobs WHERE alert_id=? ORDER BY created_at', (alert_id,))]
        blocks = [dict(r) for r in conn.execute('SELECT * FROM active_blocks WHERE proposal_id IN (SELECT proposal_id FROM proposals WHERE alert_id=?)', (alert_id,))]
    for run in runs:
        run['alert'] = json.loads(run.pop('alert_json'))
        run['result'] = json.loads(run.pop('result_json') or '{}')
    for tool in tools:
        tool['result'] = json.loads(tool.pop('result_json'))
    latest = runs[-1]
    return dict(alert_id=alert_id, alert=latest['alert'], status=latest['status'],
                verdict=latest['result'].get('verdict'), findings=latest['result'].get('findings', []),
                runs=runs, tools=tools, proposals=proposals, blocks=blocks, reviews=jobs,
                review_status=jobs[-1]['status'] if jobs else None,
                report_url=f'/api/cases/{alert_id}/report', generated_at=get_utc_timestamp())


def list_cases(limit=100, offset=0, db_path=None):
    with get_db(db_path) as conn:
        ids = [r['alert_id'] for r in conn.execute('SELECT alert_id FROM case_runs GROUP BY alert_id ORDER BY MAX(started_at) DESC LIMIT ? OFFSET ?', (limit, offset))]
    return [get_case(alert_id, db_path) for alert_id in ids]


def metrics(db_path=None):
    with get_db(db_path) as conn:
        counts = {r['status']: r['n'] for r in conn.execute('SELECT status, COUNT(*) n FROM proposals GROUP BY status')}
        handled = conn.execute('SELECT COUNT(DISTINCT alert_id) FROM case_runs').fetchone()[0]
        auto_closed = conn.execute("SELECT COUNT(*) FROM case_runs WHERE status='auto_closed'").fetchone()[0]
        jobs = {r['status']: r['n'] for r in conn.execute('SELECT status, COUNT(*) n FROM investigation_jobs GROUP BY status')}
    return dict(alerts_handled=handled, auto_closed_runs=auto_closed, proposals=counts, investigation_jobs=jobs)
