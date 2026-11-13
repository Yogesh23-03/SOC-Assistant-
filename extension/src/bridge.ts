import { replySchema, type Command, type State } from './contracts';

export async function send(command: Command): Promise<State> {
  if (!globalThis.chrome?.runtime?.id) throw new Error('Load extension/dist as an unpacked extension to connect to the backend.');
  const reply = replySchema.parse(await chrome.runtime.sendMessage(command));
  if (!reply.ok) throw new Error(reply.error);
  return reply.state;
}
