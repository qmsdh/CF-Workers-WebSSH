import type { Env } from './types';
import { SSHSessionDO } from './backend/durable-object';
import { corsPreflightResponse, corsResponse, httpsRedirect, isProductionHttp, jsonError, secureResponse } from './http-security';

export { SSHSessionDO };

function clientAddress(request: Request): string {
  const value = request.headers.get('CF-Connecting-IP') ?? 'local';
  return /^[0-9A-Fa-f:.]{2,64}$/.test(value) ? value.toLowerCase() : 'unknown';
}

function timingSafeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  if (bufA.length !== bufB.length) {
    crypto.getRandomValues(new Uint8Array(1));
    return false;
  }
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) diff |= bufA[i] ^ bufB[i];
  return diff === 0;
}

function hasValidWebSocketOrigin(request: Request): boolean {
  const origin = request.headers.get('Origin');
  return origin === null || origin === new URL(request.url).origin;
}

async function sessionTicket(request: Request, env: Env): Promise<Response> {
  if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) return jsonError('Expected application/json', 415);
  const contentLength = Number(request.headers.get('Content-Length') ?? 0);
  if (!Number.isFinite(contentLength) || contentLength < 0 || contentLength > 8192) return jsonError('Request body is too large', 413);
  let body: unknown;
  try {
    const text = await request.text();
    if (new TextEncoder().encode(text).length > 8192) return jsonError('Request body is too large', 413);
    body = JSON.parse(text);
  } catch { return jsonError('Invalid JSON body', 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return jsonError('Invalid JSON body', 400);
  const raw = body as Record<string, unknown>;
  if (env.ACCESS_PASSWORD) {
    const provided = typeof raw.password === 'string' ? raw.password : '';
    if (!timingSafeEqual(provided, env.ACCESS_PASSWORD)) return jsonError('Invalid access password', 401);
  }
  const fields = Object.keys(raw).filter((field) => field !== 'password');
  if (fields.length > 0) return jsonError('Unsupported request field', 400);
  const id = env.SSH_SESSIONS.newUniqueId();
  const stub = env.SSH_SESSIONS.get(id);
  const response = await stub.fetch(new Request('https://session.internal/ticket', {
    method: 'POST',
    headers: { 'x-client-ip': clientAddress(request) },
  }));
  if (!response.ok) return jsonError('Unable to create a session ticket', 503);
  const ticket = await response.json<{ ticket: string; expiresAt: number }>();
  return secureResponse(Response.json({ ...ticket, sessionId: id.toString() }, { headers: { 'Cache-Control': 'no-store' } }));
}

const MAX_CONNECTIONS_BLOB_BYTES = 600_000;
const CONNECTIONS_KV_KEY = 'connections:blob';

async function connectionsHandler(request: Request, env: Env): Promise<Response> {
  if (!env.CONNECTIONS_KV) return jsonError('Sync storage is not configured', 503);
  if (!env.ACCESS_PASSWORD) return jsonError('Access password is not configured', 403);
  const provided = request.headers.get('X-Access-Password') ?? '';
  if (!timingSafeEqual(provided, env.ACCESS_PASSWORD)) return jsonError('Invalid access password', 401);

  if (request.method === 'GET') {
    const stored = await env.CONNECTIONS_KV.get(CONNECTIONS_KV_KEY);
    return secureResponse(Response.json({ blob: stored ?? null }, { headers: { 'Cache-Control': 'no-store' } }));
  }

  const contentLength = Number(request.headers.get('Content-Length') ?? 0);
  if (!Number.isFinite(contentLength) || contentLength < 0 || contentLength > MAX_CONNECTIONS_BLOB_BYTES) return jsonError('Request body is too large', 413);
  let body: unknown;
  try {
    const text = await request.text();
    if (new TextEncoder().encode(text).length > MAX_CONNECTIONS_BLOB_BYTES) return jsonError('Request body is too large', 413);
    body = JSON.parse(text);
  } catch { return jsonError('Invalid JSON body', 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return jsonError('Invalid JSON body', 400);
  const blob = (body as Record<string, unknown>).blob;
  if (typeof blob !== 'string' || blob.length < 1 || blob.length > MAX_CONNECTIONS_BLOB_BYTES) return jsonError('Invalid sync payload', 400);
  await env.CONNECTIONS_KV.put(CONNECTIONS_KV_KEY, blob);
  return secureResponse(Response.json({ ok: true }, { headers: { 'Cache-Control': 'no-store' } }));
}

async function sshUpgrade(request: Request, env: Env): Promise<Response> {
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return jsonError('WebSocket upgrade required', 426);
  const url = new URL(request.url);
  if (!hasValidWebSocketOrigin(request)) return jsonError('WebSocket origin is not allowed', 403);
  const ticket = url.searchParams.get('ticket');
  const sessionId = url.searchParams.get('session');
  if (!ticket || !sessionId) return jsonError('Missing session ticket', 401);
  let id: DurableObjectId;
  try { id = env.SSH_SESSIONS.idFromString(sessionId); } catch { return jsonError('Invalid session identifier', 401); }
  const headers = new Headers(request.headers);
  headers.delete('Cookie');
  headers.delete('Authorization');
  const sftpAttachToken = crypto.randomUUID();
  const processAttachToken = crypto.randomUUID();
  const sftpAttachUrl = new URL('/api/sftp', 'https://session.invalid');
  sftpAttachUrl.searchParams.set('session', id.toString());
  sftpAttachUrl.searchParams.set('token', sftpAttachToken);
  const processAttachUrl = new URL('/api/processes', 'https://session.invalid');
  processAttachUrl.searchParams.set('session', id.toString());
  processAttachUrl.searchParams.set('token', processAttachToken);
  headers.set('x-session-ticket', ticket);
  headers.set('x-client-ip', clientAddress(request));
  headers.set('x-sftp-attach-token', sftpAttachToken);
  headers.set('x-sftp-attach-url', `${sftpAttachUrl.pathname}${sftpAttachUrl.search}`);
  headers.set('x-process-attach-token', processAttachToken);
  headers.set('x-process-attach-url', `${processAttachUrl.pathname}${processAttachUrl.search}`);
  const response = await env.SSH_SESSIONS.get(id).fetch(new Request('https://session.internal/connect', { headers }));
  if (response.status === 401) return jsonError('Invalid, expired, or already used session ticket', 401);
  return response;
}

async function sftpUpgrade(request: Request, env: Env): Promise<Response> {
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return jsonError('WebSocket upgrade required', 426);
  if (!hasValidWebSocketOrigin(request)) return jsonError('WebSocket origin is not allowed', 403);
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session');
  const token = url.searchParams.get('token');
  if (!sessionId || !token) return jsonError('Missing SFTP attachment authorization', 401);
  let id: DurableObjectId;
  try { id = env.SSH_SESSIONS.idFromString(sessionId); } catch { return jsonError('Invalid session identifier', 401); }
  const headers = new Headers(request.headers);
  headers.delete('Cookie');
  headers.delete('Authorization');
  headers.delete('x-session-ticket');
  headers.delete('x-client-ip');
  headers.delete('x-sftp-attach-url');
  headers.set('x-sftp-attach-token', token);
  const response = await env.SSH_SESSIONS.get(id).fetch(new Request('https://session.internal/sftp', {
    method: 'GET',
    headers,
  }));
  if (response.status === 401) return jsonError('Invalid, expired, or already used SFTP attachment token', 401);
  return response;
}

async function processUpgrade(request: Request, env: Env): Promise<Response> {
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return jsonError('WebSocket upgrade required', 426);
  if (!hasValidWebSocketOrigin(request)) return jsonError('WebSocket origin is not allowed', 403);
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session');
  const token = url.searchParams.get('token');
  if (!sessionId || !token) return jsonError('Missing process attachment authorization', 401);
  let id: DurableObjectId;
  try { id = env.SSH_SESSIONS.idFromString(sessionId); } catch { return jsonError('Invalid session identifier', 401); }
  const headers = new Headers(request.headers);
  headers.delete('Cookie');
  headers.delete('Authorization');
  headers.delete('x-session-ticket');
  headers.delete('x-client-ip');
  headers.delete('x-process-attach-url');
  headers.set('x-process-attach-token', token);
  const response = await env.SSH_SESSIONS.get(id).fetch(new Request('https://session.internal/processes', {
    method: 'GET',
    headers,
  }));
  if (response.status === 401) return jsonError('Invalid, expired, or already used process attachment token', 401);
  return response;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const isApiRequest = url.pathname.startsWith('/api/');
    try {
      if (isProductionHttp(request)) {
        if (isApiRequest) return corsResponse(jsonError('HTTPS is required', 403));
        if (request.method === 'GET' || request.method === 'HEAD') return httpsRedirect(request);
        return jsonError('HTTPS is required', 403);
      }
      if (isApiRequest && request.method === 'OPTIONS') {
        return corsResponse(corsPreflightResponse());
      }
      if (url.pathname === '/api/health' && request.method === 'GET') {
        return corsResponse(secureResponse(Response.json({ status: 'ok', runtime: 'cloudflare-workers', ssh: true }, { headers: { 'Cache-Control': 'no-store' } })));
      }
      if (url.pathname === '/api/session') {
        if (request.method !== 'POST') return corsResponse(jsonError('Method not allowed', 405));
        return corsResponse(await sessionTicket(request, env));
      }
      if (url.pathname === '/api/ssh') {
        if (request.method !== 'GET') return corsResponse(jsonError('Method not allowed', 405));
        // 成功时 sshUpgrade 返回 101 WebSocket 升级响应，corsResponse 内部会原样
        // 放行（不重新包装）；失败时返回 JSON 错误，正常附加 CORS 头。
        return corsResponse(await sshUpgrade(request, env));
      }
      if (url.pathname === '/api/sftp') {
        if (request.method !== 'GET') return corsResponse(jsonError('Method not allowed', 405));
        return corsResponse(await sftpUpgrade(request, env));
      }
      if (url.pathname === '/api/processes') {
        if (request.method !== 'GET') return corsResponse(jsonError('Method not allowed', 405));
        return corsResponse(await processUpgrade(request, env));
      }
      if (url.pathname === '/api/connections') {
        if (request.method !== 'GET' && request.method !== 'POST') return corsResponse(jsonError('Method not allowed', 405));
        return corsResponse(await connectionsHandler(request, env));
      }
      if (isApiRequest) return corsResponse(jsonError('Not found', 404));
      if (!env.ASSETS) return jsonError('Static assets binding is not configured', 503);
      return secureResponse(await env.ASSETS.fetch(request));
    } catch (error) {
      console.error('Worker request failed', error instanceof Error ? error.message : String(error));
      const response = jsonError('Internal server error', 500);
      return isApiRequest ? corsResponse(response) : response;
    }
  },
};
