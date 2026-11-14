import { replySchema, type Command, type State } from './contracts';

export async function send(command: Command): Promise<State> {
  if (!globalThis.chrome?.runtime?.id) throw new Error('Load extension/dist as an unpacked extension to connect to the backend.');
  const reply = replySchema.parse(await chrome.runtime.sendMessage(command));
  if (!reply.ok) throw new Error(reply.error);
  return reply.state;
}

export async function downloadReport(alertId: string, format: 'text' | 'pdf') {
  const reply = replySchema.parse(await chrome.runtime.sendMessage({ type: 'report', alert_id: alertId, format }));
  if (!reply.ok) throw new Error(reply.error);
  if (!reply.report) throw new Error('No report returned.');
  const bytes = Uint8Array.from(atob(reply.report.content), c => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: format === 'pdf' ? 'application/pdf' : 'text/plain' }));
  const anchor = document.createElement('a'); anchor.href = url;
  anchor.download = `soc-case-${alertId.replace(/[^a-zA-Z0-9_-]/g, '_')}.${format === 'pdf' ? 'pdf' : 'txt'}`;
  anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
