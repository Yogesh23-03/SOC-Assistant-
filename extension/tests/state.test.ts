import { describe, expect, it } from 'vitest';
import { emptyState, proposalSchema, settingsSchema } from '../src/contracts';
import { applyEvent, pendingProposals, reconcilePending } from '../src/state';

const proposal = proposalSchema.parse({ proposal_id: 'p1', alert_id: 'a1', action: 'block_ip', target: '203.0.113.5', reason: 'Repeated failed logins', status: 'pending', confidence: .9, ttl_seconds: 3600, created_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z' });
describe('case recovery', () => {
  it('replays hostile evidence as data and ignores duplicate events', () => {
    const event = { event_id: 1, event_type: 'alert.new', payload: { alert_id: 'a1', log_text: '<script>alert(1)</script>' }, created_at: '' };
    const state = applyEvent(emptyState(), event);
    expect(state.cases.a1.log_text).toBe('<script>alert(1)</script>');
    expect(applyEvent(state, event)).toBe(state);
  });
  it('coerces null optional fields to their defaults', () => {
    const state = applyEvent(emptyState(), { event_id: 7, event_type: 'alert.new', payload: { alert_id: 'a2', source_ip: null, host: null, severity: null }, created_at: '' });
    expect(state.cursor).toBe(7);
    expect(state.cases.a2).toMatchObject({ source_ip: '', host: '', severity: 'medium' });
  });
  it('skips unparseable events instead of stalling the cursor', () => {
    const state = applyEvent(emptyState(), { event_id: 9, event_type: 'alert.new', payload: { alert_id: 42 }, created_at: '' });
    expect(state.cursor).toBe(9);
    expect(Object.keys(state.cases)).toHaveLength(0);
  });
  it('skips an unparseable proposal event without stalling the cursor', () => {
    const state = applyEvent(emptyState(), { event_id: 4, event_type: 'proposal.updated', payload: { proposal_id: 'p1', expires_at: 'tomorrow' }, created_at: '' });
    expect(state.cursor).toBe(4);
    expect(Object.keys(state.proposals)).toHaveLength(0);
  });
  it('keeps a replay from resetting evidence already attached to the case', () => {
    const first = applyEvent(emptyState(), { event_id: 1, event_type: 'alert.new', payload: { alert_id: 'a1' }, created_at: '' });
    const second = applyEvent(first, { event_id: 2, event_type: 'alert.update', payload: { alert_id: 'a1', findings: [{ alert_id: 'a1', source: 'logs', detail: 'seen' }] }, created_at: '' });
    const replay = applyEvent(second, { event_id: 1, event_type: 'alert.new', payload: { alert_id: 'a1' }, created_at: '' });
    expect(replay).toBe(second);
  });
  it('recovers pending approvals and removes stale cached pending items', () => {
    const restored = reconcilePending(emptyState(), [proposal]);
    expect(pendingProposals(restored)).toHaveLength(1);
    expect(pendingProposals(restored, Date.parse('2100-01-01'))).toHaveLength(0);
    expect(pendingProposals(reconcilePending(restored, []))).toHaveLength(0);
  });
  it('keeps closed cases and investigation evidence after replay', () => {
    const first = applyEvent(emptyState(), { event_id: 1, event_type: 'alert.new', payload: { alert_id: 'a1' }, created_at: '' });
    const second = applyEvent(first, { event_id: 2, event_type: 'alert.update', payload: { alert_id: 'a1', findings: [{ alert_id: 'a1', source: 'logs', detail: '<img src=x onerror=alert(1)>' }] }, created_at: '' });
    const closed = applyEvent(second, { event_id: 3, event_type: 'case.closed', payload: { alert_id: 'a1' }, created_at: '' });
    expect(closed.cases.a1.closed).toBe(true);
    expect(closed.cases.a1.findings).toHaveLength(1);
  });
});
describe('backend restrictions', () => {
  it.each(['https://evil.test', 'http://localhost.evil.test:8000', 'http://user:pass@localhost:8000', 'http://localhost:8000/path'])('rejects %s', backend => {
    expect(settingsSchema.safeParse({ backend, notifications: true }).success).toBe(false);
  });
  it.each(['http://localhost:8000', 'http://127.0.0.1:8000', 'https://soc-backend.lab.local'])('accepts %s', backend => {
    expect(settingsSchema.safeParse({ backend, notifications: true }).success).toBe(true);
  });
});
