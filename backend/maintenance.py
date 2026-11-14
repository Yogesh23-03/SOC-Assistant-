"""Resumable investigation jobs and periodic firewall cleanup (single backend worker)."""
import asyncio
import logging
import os
from backend.audit import get_utc_timestamp, log_audit_event
from backend.cases import get_case
from backend.database import get_db
from backend.executor import expire_active_blocks
from backend.ingest import ingest_and_process_alert
from backend.storage import get_proposal
from backend.websocket_manager import ws_manager

logger = logging.getLogger('soc_backend.maintenance')


def recover_jobs(db_path=None):
    with get_db(db_path) as conn:
        conn.execute("UPDATE investigation_jobs SET status='queued' WHERE status='running'")
        conn.execute("UPDATE case_runs SET status='failed', error='Analysis interrupted by server restart', finished_at=? WHERE status='analyzing'", (get_utc_timestamp(),))


async def run_next_review(db_path=None, llm=None):
    with get_db(db_path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute("SELECT * FROM investigation_jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
        if not row:
            return False
        job = dict(row)
        conn.execute("UPDATE investigation_jobs SET status='running' WHERE proposal_id=?", (job['proposal_id'],))
    try:
        case = get_case(job['alert_id'], db_path)
        if not case:
            raise RuntimeError('Original alert unavailable')
        await ws_manager.broadcast('case.investigating', {'alert_id': job['alert_id']}, db_path=db_path)
        result = await ingest_and_process_alert(case['alert'], llm=llm, db_path=db_path, offload=True)
        with get_db(db_path) as conn:
            conn.execute("UPDATE investigation_jobs SET status='done', finished_at=?, error=NULL WHERE proposal_id=?", (get_utc_timestamp(), job['proposal_id']))
            conn.execute("UPDATE proposals SET status='rejected' WHERE proposal_id=? AND status='investigating'", (job['proposal_id'],))
        log_audit_event(job['analyst_id'], 'investigation.repeated',
                        {'alert_id': job['alert_id'], 'previous_proposal_id': job['proposal_id'], 'status': result['status']}, db_path=db_path)
    except Exception:
        logger.exception('Review failed for proposal %s', job['proposal_id'])
        with get_db(db_path) as conn:
            conn.execute("UPDATE investigation_jobs SET status='failed', finished_at=?, error='Investigation failed; retry from the case' WHERE proposal_id=?", (get_utc_timestamp(), job['proposal_id']))
        log_audit_event('system.review', 'investigation.failed', {'alert_id': job['alert_id'], 'proposal_id': job['proposal_id']}, db_path=db_path)
        await ws_manager.broadcast('case.review_failed', {'alert_id': job['alert_id']}, db_path=db_path)
    await ws_manager.broadcast('proposal.updated', get_proposal(job['proposal_id'], db_path), db_path=db_path)
    return True


async def maintenance_loop():
    interval = max(1, int(os.getenv('SOC_REAPER_INTERVAL_SECONDS', '30')))
    next_cleanup = 0
    while True:
        try:
            await run_next_review()
            if asyncio.get_running_loop().time() >= next_cleanup:
                expired = await asyncio.to_thread(expire_active_blocks)
                if expired:
                    await ws_manager.broadcast('firewall.expired', {'targets': expired})
                next_cleanup = asyncio.get_running_loop().time() + interval
        except Exception:
            logger.exception('Maintenance failed; will retry')
        await asyncio.sleep(1)
