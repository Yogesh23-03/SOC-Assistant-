import { z } from 'zod';

export const findingSchema = z.object({ alert_id: z.string(), source: z.string(), detail: z.string() });
export const proposalSchema = z.object({
  proposal_id: z.string(), alert_id: z.string(), action: z.enum(['block_ip', 'escalate', 'none']),
  target: z.string(), reason: z.string(), explanation: z.string().nullable().optional(),
  status: z.enum(['pending', 'approved', 'rejected', 'expired', 'investigating']), confidence: z.number().min(0).max(1),
  ttl_seconds: z.number().int().positive(), created_at: z.string().datetime({ offset: true }),
  expires_at: z.string().datetime({ offset: true }), decision_by: z.string().nullable().optional(), decision_at: z.string().nullable().optional(),
});
export type Proposal = z.infer<typeof proposalSchema>;
export const eventSchema = z.object({
  event_id: z.number().int().positive(), event_type: z.string(), payload: z.unknown(), created_at: z.string(),
});
export type SocEvent = z.infer<typeof eventSchema>;
export const caseSchema = z.object({
  alert_id: z.string(), rule_name: z.string().nullish().transform(v => v ?? 'Security alert'), source_ip: z.string().nullish().transform(v => v ?? ''),
  host: z.string().nullish().transform(v => v ?? ''), severity: z.enum(['low', 'medium', 'high', 'critical']).nullish().transform(v => v ?? 'medium'),
  timestamp: z.string().nullish().transform(v => v ?? ''), log_text: z.string().nullish().transform(v => v ?? ''),
  verdict: z.object({ label: z.string(), confidence: z.number(), reasoning: z.string().default('') }).optional(),
  findings: z.array(findingSchema).default([]), closed: z.boolean().default(false),
  report_ready: z.boolean().default(false), investigating: z.boolean().default(false), review_failed: z.boolean().default(false),
});
export type Case = z.infer<typeof caseSchema>;
export const settingsSchema = z.object({
  backend: z.string().url().refine(value => {
    const url = new URL(value);
    return !url.username && !url.password && !url.search && !url.hash && url.pathname === '/' && (
      (url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)) ||
      (url.protocol === 'https:' && url.host === 'soc-backend.lab.local')
    );
  }, 'Use http://localhost:8000, http://127.0.0.1:8000 or https://soc-backend.lab.local.'),
  notifications: z.boolean(),
});
export const decisionSchema = z.enum(['approve', 'reject', 'investigate_more']);
export type Decision = z.infer<typeof decisionSchema>;
export const commandSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('state') }),
  z.object({ type: z.literal('sync') }),
  z.object({ type: z.literal('login'), access_token: z.string().trim().min(16) }),
  z.object({ type: z.literal('logout') }),
  z.object({ type: z.literal('report'), alert_id: z.string(), format: z.enum(['text', 'pdf']) }),
  z.object({ type: z.literal('retry_review'), proposal_id: z.string() }),
  z.object({ type: z.literal('settings'), settings: settingsSchema }),
  z.object({ type: z.literal('decision'), proposal_id: z.string(), decision: decisionSchema }),
]);
export type Command = z.infer<typeof commandSchema>;
export const sessionSchema = z.object({ access_token: z.string(), analyst_id: z.string(), expires_at: z.number() });
export type Session = z.infer<typeof sessionSchema>;
export const stateSchema = z.object({
  cases: z.record(z.string(), caseSchema), proposals: z.record(z.string(), proposalSchema), cursor: z.number().int().nonnegative(),
  connection: z.enum(['signed_out', 'connecting', 'live', 'polling', 'offline']),
  last_sync: z.string().nullable(), error: z.string().nullable(),
  settings: settingsSchema, analyst: z.string().nullable(),
  metrics: z.object({ alerts_handled: z.number(), auto_closed_runs: z.number(), proposals: z.record(z.string(), z.number()) }).optional(),
});
export type State = z.infer<typeof stateSchema>;
export const replySchema = z.discriminatedUnion('ok', [
  z.object({ ok: z.literal(true), state: stateSchema, report: z.object({ content: z.string(), format: z.enum(['text', 'pdf']) }).optional() }),
  z.object({ ok: z.literal(false), error: z.string() }),
]);
export const emptyState = (): State => ({
  cases: {}, proposals: {}, cursor: 0, connection: 'signed_out', last_sync: null, error: null,
  settings: { backend: 'http://localhost:8000', notifications: true }, analyst: null,
});
