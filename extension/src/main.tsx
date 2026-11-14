import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { send, downloadReport } from './bridge';
import { emptyState, stateSchema, type Case, type Command, type Decision, type Proposal, type State } from './contracts';
import { pendingProposals } from './state';
import './style.css';

function actionName(action: string) { return action === 'block_ip' ? 'Block IP address' : action === 'escalate' ? 'Escalate for review' : 'No action'; }
function time(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? 'Unknown time' : date.toLocaleString(); }

function App() {
  const [state, setState] = useState<State>(emptyState);
  const [tab, setTab] = useState<'queue' | 'cases' | 'settings'>('queue');
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ proposal: Proposal; decision: Decision } | null>(null);
  const [now, setNow] = useState(Date.now());
  const [backend, setBackend] = useState('http://localhost:8000');
  const [accessToken, setAccessToken] = useState('');
  const [notifications, setNotifications] = useState(true);

  async function run(command: Command) {
    setBusy(true); setError(null); setNotice(null);
    try {
      const next = await send(command); setState(next);
      if (command.type === 'decision') {
        setConfirm(null);
        setNotice(command.decision === 'approve' ? 'Approval recorded. Check the case report for execution results.' : command.decision === 'investigate_more' ? 'Investigation queued. Fresh evidence and a new proposal will appear when analysis finishes.' : 'Proposal rejected.');
      }
      if (command.type === 'login') setAccessToken('');
      if (command.type === 'settings') setNotice('Connection settings saved.');
      return next;
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Request failed. Please retry.'); return null; }
    finally { setBusy(false); }
  }

  useEffect(() => {
    void send({ type: 'state' }).then(next => { setState(next); setBackend(next.settings.backend); setNotifications(next.settings.notifications); }).catch(cause => setError(String(cause.message)));
    const listener = (message: unknown) => {
      if (typeof message !== 'object' || !message || !('type' in message) || message.type !== 'state.changed' || !('state' in message)) return;
      const parsed = stateSchema.safeParse(message.state); if (parsed.success) setState(parsed.data);
    };
    if (globalThis.chrome?.runtime?.id) chrome.runtime.onMessage.addListener(listener);
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => { clearInterval(timer); if (globalThis.chrome?.runtime?.id) chrome.runtime.onMessage.removeListener(listener); };
  }, []);

  const pending = pendingProposals(state, now);
  const proposal = selected ? state.proposals[selected] : undefined;
  const selectedCase = selected ? state.cases[proposal?.alert_id ?? selected] : undefined;
  const connected = state.connection === 'live' || state.connection === 'polling';
  const enabled = connected && !!state.analyst && !busy;

  function exportCase(item: Case | undefined, itemProposal: Proposal | undefined) {
    const report = [
      '# SOC investigation summary', `Generated: ${new Date().toISOString()}`, `Case: ${item?.alert_id ?? itemProposal?.alert_id ?? 'Unknown'}`,
      `Rule: ${item?.rule_name ?? 'Unknown'}`, `Host: ${item?.host ?? 'Unknown'}`, `Source: ${item?.source_ip ?? 'Unknown'}`,
      `Verdict: ${item?.verdict?.label ?? 'Unavailable'}`, item?.verdict?.reasoning ?? '',
      '\n## Evidence', ...(item?.findings.map(f => `${f.source}: ${f.detail}`) ?? []), item?.log_text ?? '',
      '\n## Proposal', itemProposal ? `${actionName(itemProposal.action)}: ${itemProposal.target}\n${itemProposal.reason}\nStatus: ${itemProposal.status}\nAnalyst: ${itemProposal.decision_by ?? 'Pending'}` : 'No proposal',
      '\nApproval status is not proof of execution. This summary reflects the extension cache; the backend audit ledger is authoritative.',
    ].join('\n\n');
    const url = URL.createObjectURL(new Blob([report], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = `soc-case-${(item?.alert_id ?? itemProposal?.alert_id ?? 'summary').replace(/[^a-zA-Z0-9_-]/g, '_')}.txt`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return <>
    <header><div className="identity"><svg width="27" height="30" viewBox="0 0 27 30" fill="none" aria-hidden="true"><path d="M13.5 2 24 6v8c0 7-6 11-10.5 14C9 25 3 21 3 14V6L13.5 2Z" stroke="currentColor" strokeWidth="2"/><path d="m8 14 4 4 7-8" stroke="currentColor" strokeWidth="2"/></svg><div><strong>SOC Assistant</strong><span>Analyst workspace</span></div></div><button className="icon-button" aria-label="Connection settings" onClick={() => { setTab('settings'); setSelected(null); }}>Connection</button></header>
    <div className="connection"><span className={`dot ${state.connection}`} aria-hidden="true"/><span>{({ signed_out: 'Session required', connecting: 'Connecting', live: 'Live connection', polling: 'Connected · polling', offline: 'Backend unavailable' })[state.connection]}</span><span className="sync-time">{state.last_sync ? `Synced ${new Date(state.last_sync).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'No sync yet'}</span></div>
    <nav aria-label="Workspace"><button aria-current={tab === 'queue' ? 'page' : undefined} onClick={() => { setTab('queue'); setSelected(null); }}>Approvals <span className="count">{pending.length}</span></button><button aria-current={tab === 'cases' ? 'page' : undefined} onClick={() => { setTab('cases'); setSelected(null); }}>Cases</button><button className="refresh" disabled={busy || !state.analyst} onClick={() => void run({ type: 'sync' })} aria-label="Refresh queue">Refresh</button></nav>
    <main>{state.metrics && <div className="metrics" aria-label="Case counters"><span>Handled <strong>{state.metrics.alerts_handled}</strong></span><span>Auto-closed runs <strong>{state.metrics.auto_closed_runs}</strong></span><span>Approved <strong>{state.metrics.proposals.approved ?? 0}</strong></span><span>Rejected <strong>{state.metrics.proposals.rejected ?? 0}</strong></span></div>}
      {(error || state.error) && <div className="message error" role="alert">{error || state.error}</div>}
      {notice && <div className="message success" role="status">{notice}</div>}
      {tab === 'settings' ? <section className="settings"><h1>Connection</h1><p>Connect to the M2 lab backend. Your analyst token stays in browser session storage.</p><form onSubmit={event => { event.preventDefault(); void run({ type: 'settings', settings: { backend: backend.replace(/\/$/, ''), notifications } }); }}><label>Backend URL<input required type="url" value={backend} onChange={e => setBackend(e.target.value)} /></label><p className="hint">Localhost HTTP or https://soc-backend.lab.local. Other hosts require updating the manifest.</p><label className="checkbox"><input type="checkbox" checked={notifications} onChange={e => setNotifications(e.target.checked)} /> Notify me about new proposals</label><button className="secondary" disabled={busy}>Save connection</button></form><hr/><h2>Lab session</h2><p className="hint">Paste the short-lived session token issued from your trusted backend terminal. Your identity is verified by the backend.</p>{state.analyst ? <><p>Signed in as <strong>{state.analyst}</strong></p><button className="secondary" disabled={busy} onClick={() => void run({ type: 'logout' })}>End session</button></> : <form onSubmit={event => { event.preventDefault(); void run({ type: 'login', access_token: accessToken }); }}><label>Session token<input required type="password" autoComplete="off" minLength={16} value={accessToken} onChange={e => setAccessToken(e.target.value)}/></label><button className="primary" disabled={busy}>{busy ? 'Connecting…' : 'Start lab session'}</button></form>}</section> : selected && (proposal || selectedCase) ? <article className="case-detail"><button className="back" onClick={() => { setSelected(null); setConfirm(null); }}>Back to {tab === 'queue' ? 'approvals' : 'cases'}</button><div className="case-heading"><span className={`severity ${selectedCase?.severity ?? 'medium'}`}>{selectedCase?.severity ?? 'Review'}</span><code>{proposal?.alert_id ?? selectedCase?.alert_id}</code></div>{selectedCase?.investigating && <p role="status">Investigation is queued or running. Refresh to see new evidence.</p>}{selectedCase?.review_failed && proposal && <div className="message error">Investigation failed. <button disabled={!enabled} onClick={() => void run({ type: 'retry_review', proposal_id: proposal.proposal_id })}>Retry investigation</button></div>}<h1>{selectedCase?.rule_name ?? actionName(proposal?.action ?? 'escalate')}</h1><dl><div><dt>Source IP</dt><dd><code>{selectedCase?.source_ip || proposal?.target || 'Unavailable'}</code></dd></div><div><dt>Host</dt><dd>{selectedCase?.host || 'Unavailable'}</dd></div><div><dt>Received</dt><dd>{time(selectedCase?.timestamp ?? proposal?.created_at ?? '')}</dd></div></dl>{selectedCase?.verdict && <section><h2>Agent assessment</h2><p><strong>{selectedCase.verdict.label.replace(/_/g, ' ')}</strong> · {Math.round(selectedCase.verdict.confidence * 100)}% confidence</p><p>{selectedCase.verdict.reasoning}</p></section>}<section><h2>Evidence</h2>{selectedCase?.findings.length ? selectedCase.findings.map((finding, index) => <div className="finding" key={`${finding.source}-${index}`}><h3>{finding.source}</h3><pre>{finding.detail.slice(0, 20000)}</pre></div>) : <p className="muted">No investigation findings were included in the backend events.</p>}{selectedCase?.log_text && <pre>{selectedCase.log_text.slice(0, 20000)}</pre>}</section>{proposal && <section className="proposal"><h2>Proposed response</h2><strong>{actionName(proposal.action)}</strong><p className="target"><code>{proposal.target}</code></p><p>{proposal.reason}</p>{proposal.explanation && <p className="muted">{proposal.explanation}</p>}<dl><div><dt>Rule duration</dt><dd>{Math.round(proposal.ttl_seconds / 60)} minutes</dd></div><div><dt>Approval deadline</dt><dd>{time(proposal.expires_at)}</dd></div><div><dt>Status</dt><dd>{proposal.status === 'pending' && Date.parse(proposal.expires_at) <= now ? 'expired' : proposal.status}</dd></div></dl>{proposal.status === 'approved' && <p className="message success">Approved for backend execution. The extension does not execute firewall rules.</p>}{proposal.status === 'pending' && Date.parse(proposal.expires_at) > now && <>{confirm?.proposal.proposal_id === proposal.proposal_id ? <div className="confirmation"><h3>Confirm {confirm.decision === 'approve' ? 'approval' : confirm.decision === 'reject' ? 'rejection' : 'review request'}</h3><p>{confirm.decision === 'approve' ? `Authorize ${actionName(proposal.action).toLowerCase()} for ${proposal.target}, with a ${Math.round(proposal.ttl_seconds / 60)} minute rule duration?` : confirm.decision === 'investigate_more' ? 'Queue a new investigation using the original alert and fresh read-only lookups? This proposal will be replaced and any new action requires a new decision.' : 'Reject this proposal? This action closes the current approval request.'}</p><div className="actions"><button className="primary" disabled={!enabled} onClick={() => void run({ type: 'decision', proposal_id: proposal.proposal_id, decision: confirm.decision })}>{busy ? 'Submitting…' : 'Confirm decision'}</button><button className="secondary" disabled={busy} onClick={() => setConfirm(null)}>Cancel</button></div></div> : <div className="actions"><button className="primary" disabled={!enabled} onClick={() => setConfirm({ proposal, decision: 'approve' })}>Approve</button><button className="secondary" disabled={!enabled} onClick={() => setConfirm({ proposal, decision: 'reject' })}>Reject</button><button className="text-button" disabled={!enabled} onClick={() => setConfirm({ proposal, decision: 'investigate_more' })}>Investigate more</button></div>}{!connected && <p className="hint">Reconnect before submitting a decision.</p>}</>}</section>}{selectedCase?.report_ready && <div className="actions"><button className="secondary" disabled={!enabled} onClick={() => void downloadReport(selectedCase.alert_id, 'pdf').catch(cause => setError(String(cause.message)))}>Download PDF report</button><button className="text-button" disabled={!enabled} onClick={() => void downloadReport(selectedCase.alert_id, 'text').catch(cause => setError(String(cause.message)))}>Download full text report</button></div>}<button className="secondary export" onClick={() => exportCase(selectedCase, proposal)}>Export case summary</button></article> : <section><div className="section-title"><h1>{tab === 'queue' ? 'Awaiting your decision' : 'Case history'}</h1><p>{tab === 'queue' ? 'Review the evidence before authorizing a response.' : 'Alerts and decisions recovered from the backend event ledger.'}</p></div>{!state.analyst && <div className="welcome"><h2>Connect your workspace</h2><p>Start a lab session to recover the queue and receive new alerts.</p><button className="primary" onClick={() => setTab('settings')}>Set up connection</button></div>}{tab === 'queue' ? pending.length ? <div className="queue">{pending.map(item => { const alert = state.cases[item.alert_id]; return <button className="queue-row" key={item.proposal_id} onClick={() => { setSelected(item.proposal_id); setConfirm(null); }}><div className="row-top"><span className={`severity ${alert?.severity ?? 'medium'}`}>{alert?.severity ?? 'Review'}</span><span className="deadline">{Math.max(1, Math.ceil((Date.parse(item.expires_at) - now) / 60000))} min left</span></div><h2>{alert?.rule_name ?? actionName(item.action)}</h2><p>{actionName(item.action)} · <code>{item.target}</code></p><div className="row-bottom"><code>{item.alert_id}</code><span>Review evidence →</span></div></button>; })}</div> : state.analyst && <div className="empty"><svg width="42" height="42" viewBox="0 0 42 42" fill="none" aria-hidden="true"><rect x="6" y="8" width="30" height="28" rx="3" stroke="currentColor" strokeWidth="1.5"/><path d="m13 22 5 5 11-12" stroke="currentColor" strokeWidth="2"/></svg><h2>{connected ? 'No pending approvals' : 'Waiting for the backend'}</h2><p>{connected ? 'New proposals will appear here. False positives are closed by the backend.' : 'Your cached cases remain available. Refresh when the backend is reachable.'}</p></div> : <div className="queue">{Object.values(state.cases).reverse().map(item => { const linked = Object.values(state.proposals).reverse().find(p => p.alert_id === item.alert_id); return <button className="queue-row" key={item.alert_id} onClick={() => { setSelected(linked?.proposal_id ?? item.alert_id); setConfirm(null); }}><div className="row-top"><span className={`severity ${item.severity}`}>{item.severity}</span><span className="deadline">{item.closed ? 'Auto-closed' : linked?.status ?? 'Analyzed'}</span></div><h2>{item.rule_name}</h2><p><code>{item.alert_id}</code> · {item.host || 'Host unavailable'}</p></button>; })}{!Object.keys(state.cases).length && <div className="empty"><h2>No cases yet</h2><p>Cases appear after the backend processes alerts.</p></div>}</div>}</section>}
    </main><footer><span>Human approval required</span><span>M3 · Lab console</span></footer>
  </>;
}

const root = document.getElementById('root');
if (root) createRoot(root).render(<React.StrictMode><App/></React.StrictMode>);
