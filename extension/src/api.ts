import { z } from 'zod';

export class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

export async function request<T>(backend: string, path: string, schema: z.ZodType<T>, token?: string, body?: unknown): Promise<T> {
  const response = await fetch(`${backend}${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(15000), redirect: 'error',
  });
  const text = await response.text();
  let data: unknown;
  try { data = JSON.parse(text); } catch { data = undefined; }
  if (!response.ok) {
    const detail = z.union([z.object({ detail: z.string() }), z.object({ detail: z.array(z.object({ msg: z.string() })) })]).safeParse(data);
    const message = detail.success ? (typeof detail.data.detail === 'string' ? detail.data.detail : detail.data.detail.map(item => item.msg).join('; ')) : '';
    throw new ApiError(message || `Backend returned HTTP ${response.status}.`, response.status);
  }
  return schema.parse(data);
}
