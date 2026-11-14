import { z } from 'zod';
import { caseSchema, findingSchema, proposalSchema, type SocEvent, type State } from './contracts';

const idSchema = z.object({ alert_id: z.string() });

export function applyEvent(state: State, event: SocEvent): State {
  if (event.event_id <= state.cursor) return state;
  const next: State = { ...state, cases: { ...state.cases }, proposals: { ...state.proposals }, cursor: event.event_id };
  const id = idSchema.safeParse(event.payload);
  if (event.event_type === 'alert.new') {
    const parsed = caseSchema.safeParse(event.payload);
    if (!parsed.success) return next;
    next.cases[parsed.data.alert_id] = { ...next.cases[parsed.data.alert_id], ...parsed.data };
  } else if (id.success && ['alert.update', 'case.closed'].includes(event.event_type)) {
    const patch = z.object({ verdict: caseSchema.shape.verdict, findings: z.array(findingSchema).optional() }).parse(event.payload);
    const previous = next.cases[id.data.alert_id] ?? caseSchema.parse({ alert_id: id.data.alert_id });
    next.cases[id.data.alert_id] = {
      ...previous, ...patch, findings: patch.findings ?? previous.findings,
      closed: event.event_type === 'case.closed' || previous.closed,
    };
  } else if (id.success && ['report.ready', 'case.investigating', 'case.review_failed'].includes(event.event_type)) {
    const previous = next.cases[id.data.alert_id] ?? caseSchema.parse({ alert_id: id.data.alert_id });
    next.cases[id.data.alert_id] = { ...previous,
      report_ready: event.event_type === 'report.ready' || previous.report_ready,
      investigating: event.event_type === 'case.investigating',
      review_failed: event.event_type === 'case.review_failed',
    };
  } else if (event.event_type === 'proposal.updated') {
    const parsed = proposalSchema.safeParse(event.payload);
    if (!parsed.success) return next;
    next.proposals[parsed.data.proposal_id] = parsed.data;
  }
  // proposal.pending has a different M2 wire shape; the canonical REST snapshot
  // supplies status, TTL and timestamps before it becomes actionable.
  return next;
}

export function pendingProposals(state: State, now = Date.now()) {
  return Object.values(state.proposals).filter(p => p.status === 'pending' && Date.parse(p.expires_at) > now);
}

export function reconcilePending(state: State, proposals: z.infer<typeof proposalSchema>[]): State {
  const current = new Set(proposals.map(p => p.proposal_id));
  const next = { ...state, proposals: { ...state.proposals } };
  for (const proposal of Object.values(next.proposals)) {
    if (proposal.status === 'pending' && !current.has(proposal.proposal_id)) delete next.proposals[proposal.proposal_id];
  }
  for (const proposal of proposals) next.proposals[proposal.proposal_id] = proposal;
  return next;
}
