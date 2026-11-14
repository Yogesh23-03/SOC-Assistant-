import { z } from 'zod';
import { ApiError, request } from './api';
import { commandSchema, emptyState, eventSchema, proposalSchema, sessionSchema, stateSchema, caseSchema, type Command, type Session } from './contracts';
import { applyEvent, pendingProposals, reconcilePending } from './state';

let state = emptyState();
let session: Session | null = null;
let socket: WebSocket | null = null;
let retry: ReturnType<typeof setTimeout> | undefined;
let heartbeat: ReturnType<typeof setInterval> | undefined;
let fallback: AbortController | null = null;
let failures = 0;
let work: Promise<unknown> = Promise.resolve();
const ready = (async () => {
  const [local, stored] = await Promise.all([chrome.storage.local.get('soc'), chrome.storage.session.get('session')]);
  const restored = stateSchema.safeParse(local.soc);
  if (restored.success) state = { ...restored.data, analyst: null, connection: 'signed_out', error: null };
  const auth = sessionSchema.safeParse(stored.session);
  if (auth.success && auth.data.expires_at > Date.now()) {
    session = auth.data;
    state.analyst = session.analyst_id;
    state.connection = 'connecting';
  }
})();

function serial<T>(fn: () => Promise<T>): Promise<T> {
  const result = work.then(async () => { await ready; return fn(); });
  work = result.catch(() => undefined);
  return result;
}

async function persist() {
  await chrome.storage.local.set({ soc: { ...state, analyst: null, connection: 'signed_out' } });
  await chrome.action.setBadgeText({ text: session && pendingProposals(state).length ? String(pendingProposals(state).length) : '' });
  await chrome.action.setBadgeBackgroundColor({ color: '#176b5b' });
  void chrome.runtime.sendMessage({ type: 'state.changed', state }).catch(() => undefined);
}

function stopConnection() {
  fallback?.abort(); fallback = null;
  clearTimeout(retry); clearInterval(heartbeat);
  retry = undefined; heartbeat = undefined;
  if (socket) { socket.onclose = null; socket.close(); socket = null; }
}

async function signOut() {
  stopConnection(); session = null;
  await chrome.storage.session.remove('session');
  state = { ...state, analyst: null, connection: 'signed_out' };
}

function requireSession(): Session {
  if (!session || session.expires_at <= Date.now()) throw new ApiError('Your session expired. Open Connection and start a new lab session.', 401);
  return session;
}

async function synchronize() {
  const auth = requireSession();
  const previousIds = new Set(Object.keys(state.proposals));
  // REST replay is paginated, unlike M2's 200-event WebSocket replay. A live
  // socket is only a wake-up signal, so out-of-order frames cannot skip events.
  for (;;) {
    const page = await request(state.settings.backend, `/api/events?last_seen_event_id=${state.cursor}&limit=500`, z.object({ events: z.array(eventSchema) }), auth.access_token);
    for (const event of page.events) state = applyEvent(state, event);
    if (page.events.length < 500) break;
  }
  for (let offset = 0; ; offset += 100) {
    const cases = await request(state.settings.backend, `/api/cases?limit=100&offset=${offset}`, z.array(z.object({
      alert_id: z.string(), alert: z.record(z.string(), z.unknown()), status: z.string(),
      verdict: caseSchema.shape.verdict.nullable(), findings: caseSchema.shape.findings,
      proposals: z.array(proposalSchema), review_status: z.string().nullable().optional(),
    })), auth.access_token);
    for (const item of cases) {
      const parsed = caseSchema.safeParse({ ...item.alert, alert_id: item.alert_id,
        verdict: item.verdict ?? undefined, findings: item.findings, closed: item.status === 'auto_closed',
        report_ready: true, investigating: item.proposals.some(p => p.status === 'investigating'),
      });
      if (parsed.success) state.cases[item.alert_id] = { ...parsed.data, review_failed: item.review_status === 'failed' };
      for (const proposal of item.proposals) state.proposals[proposal.proposal_id] = proposal;
    }
    if (cases.length < 100 || offset >= 400) break;
  }
  state.metrics = await request(state.settings.backend, '/api/metrics', z.object({ alerts_handled: z.number(), auto_closed_runs: z.number(), proposals: z.record(z.string(), z.number()) }), auth.access_token);
  const pending = await request(state.settings.backend, '/api/proposals/pending', z.array(z.unknown()), auth.access_token).then(rows => rows.flatMap(row => { const parsed = proposalSchema.safeParse(row); return parsed.success ? [parsed.data] : []; }));
  state = reconcilePending(state, pending);
  state.connection = socket?.readyState === WebSocket.OPEN ? 'live' : 'polling';
  state.last_sync = new Date().toISOString(); state.error = null;
  // Bound old case history, while retaining every case with a pending proposal.
  const retained = new Set(pending.map(p => p.alert_id));
  const cases = Object.values(state.cases);
  state.cases = Object.fromEntries(cases.filter((c, i) => i >= cases.length - 300 || retained.has(c.alert_id)).map(c => [c.alert_id, c]));
  const all = Object.values(state.proposals);
  state.proposals = Object.fromEntries(all.filter((p, i) => p.status === 'pending' || i >= all.length - 300).map(p => [p.proposal_id, p]));
  await persist();
  if (state.settings.notifications) {
    for (const proposal of pending.filter(p => !previousIds.has(p.proposal_id))) {
      await new Promise<void>(resolve => chrome.notifications.create(`proposal:${proposal.proposal_id}`, {
        type: 'basic', iconUrl: 'icon.png', title: 'SOC approval requested',
        message: `${proposal.action === 'block_ip' ? 'Block' : 'Review'} ${proposal.target}. Open SOC Assistant to review evidence.`,
      }, () => { void chrome.runtime.lastError; resolve(); }));
    }
  }
}

async function handleFailure(error: unknown) {
  state.error = error instanceof Error ? error.message : 'Connection failed. Check the backend and retry.';
  if (error instanceof ApiError && error.status === 401) await signOut();
  else if (!(error instanceof ApiError && error.status >= 400 && error.status < 500)) state.connection = 'offline';
  await persist();
}

async function refresh() {
  try { await synchronize(); } catch (error) { await handleFailure(error); }
}

// Authenticated fetch allows SSE without putting a session token in a URL.
function startFallback() {
  if (!session || fallback) return;
  const controller = new AbortController(); fallback = controller;
  const auth = session;
  void (async () => {
    try {
      const response = await fetch(`${state.settings.backend}/api/events/stream?last_seen_event_id=${state.cursor}`, {
        headers: { Authorization: `Bearer ${auth.access_token}` }, signal: controller.signal, redirect: 'error',
      });
      if (response.status === 401) { void serial(async () => handleFailure(new ApiError('Session expired', 401))); return; }
      if (!response.ok || !response.body) return;
      const reader = response.body.getReader();
      const decoder = new TextDecoder(); let buffer = '';
      while (!controller.signal.aborted) {
        const { done, value } = await reader.read(); if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let boundary: number;
        while ((boundary = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 2);
          if (frame.startsWith('id:')) void serial(refresh);
        }
        if (buffer.length > 1000000) throw new Error('Event stream frame too large');
      }
    } catch { /* Alarm polling remains available if both push transports fail. */ }
    finally { if (fallback === controller) fallback = null; }
  })();
}

function connect() {
  if (!session || socket || retry) return;
  const url = new URL('/ws/analyst', state.settings.backend);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(url, `soc.auth.${session.access_token}`);
  socket.onopen = () => {
    fallback?.abort(); fallback = null;
    failures = 0;
    heartbeat = setInterval(() => {
      if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'ping' }));
    }, 20000);
    void serial(async () => { state.connection = 'live'; await refresh(); });
  };
  socket.onmessage = message => {
    try {
      const frame = z.object({ event_id: z.number().optional(), type: z.string() }).parse(JSON.parse(String(message.data)));
      if (frame.event_id) void serial(refresh);
    } catch { /* Malformed frames cannot change state; REST remains authoritative. */ }
  };
  socket.onclose = () => {
    socket = null; clearInterval(heartbeat);
    startFallback();
    void serial(async () => { if (session) { state.connection = 'polling'; await refresh(); } });
    retry = setTimeout(() => { retry = undefined; connect(); }, Math.min(30000, 1000 * 2 ** failures++) + Math.random() * 500);
  };
  socket.onerror = () => socket?.close();
}

async function execute(command: Command) {
  switch (command.type) {
    case 'state': return;
    case 'sync': await synchronize(); connect(); return;
    case 'login': {
      stopConnection();
      const identity = await request(state.settings.backend, '/api/session', z.object({ analyst_id: z.string(), expires_at: z.number() }), command.access_token);
      if (identity.expires_at * 1000 <= Date.now()) throw new ApiError('Session token has expired.', 401);
      session = { access_token: command.access_token, analyst_id: identity.analyst_id, expires_at: identity.expires_at * 1000 };
      await chrome.storage.session.set({ session });
      state.analyst = session.analyst_id; state.connection = 'connecting';
      await synchronize(); connect(); return;
    }
    case 'report': return;
    case 'retry_review': {
      const auth = requireSession();
      await request(state.settings.backend, `/api/proposals/${encodeURIComponent(command.proposal_id)}/review/retry`, z.object({ status: z.string() }), auth.access_token, {});
      const proposal = state.proposals[command.proposal_id];
      if (proposal && state.cases[proposal.alert_id]) state.cases[proposal.alert_id].review_failed = false;
      await refresh(); return;
    }
    case 'logout': await signOut(); state.error = null; return;
    case 'settings': {
      const changed = command.settings.backend !== state.settings.backend;
      if (changed) { await signOut(); state = { ...emptyState(), settings: command.settings }; }
      else state.settings = command.settings;
      return;
    }
    case 'decision': {
      const auth = requireSession();
      const proposal = state.proposals[command.proposal_id];
      if (!proposal || proposal.status !== 'pending' || Date.parse(proposal.expires_at) <= Date.now()) throw new Error('This proposal is no longer pending. Refresh the queue.');
      // Never retry a decision automatically. A lost response needs a state refresh,
      // not a second authorization with a new nonce.
      try {
        const result = await request(state.settings.backend, '/api/decisions', z.object({ proposal: proposalSchema }), auth.access_token, {
          proposal_id: command.proposal_id, decision: command.decision, nonce: crypto.randomUUID(),
        });
        state.proposals[result.proposal.proposal_id] = result.proposal;
      } catch (error) { await refresh(); throw error; }
      // The decision already succeeded. A subsequent sync failure must not
      // tell the analyst that authorization failed or invite another decision.
      await refresh(); return;
    }
  }
}

chrome.runtime.onMessage.addListener((raw: unknown, sender, respond) => {
  if (sender.id !== chrome.runtime.id) return false;
  const command = commandSchema.safeParse(raw);
  if (!command.success) return false;
  void serial(async () => {
    try {
      if (command.data.type === 'report') {
        const auth = requireSession();
        const response = await fetch(`${state.settings.backend}/api/cases/${encodeURIComponent(command.data.alert_id)}/report?format=${command.data.format}`, {
          headers: { Authorization: `Bearer ${auth.access_token}` }, redirect: 'error', signal: AbortSignal.timeout(15000),
        });
        if (!response.ok) throw new ApiError('Report download failed.', response.status);
        const bytes = new Uint8Array(await response.arrayBuffer());
        let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
        respond({ ok: true, state, report: { content: btoa(binary), format: command.data.format } }); return;
      }
      await execute(command.data); await persist(); respond({ ok: true, state });
    }
    catch (error) { await handleFailure(error); respond({ ok: false, error: state.error }); }
  });
  return true;
});
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'soc.refresh') void serial(async () => { if (session) { await refresh(); connect(); } });
});
chrome.runtime.onInstalled.addListener(() => {
  void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
});
chrome.runtime.onStartup.addListener(() => { void serial(async () => { if (session) { await refresh(); connect(); } }); });
void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
void chrome.alarms.create('soc.refresh', { periodInMinutes: 0.5 });
void serial(async () => { if (session) { await refresh(); connect(); } else await persist(); });
