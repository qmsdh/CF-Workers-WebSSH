// Cross-device connection-list sync backed by Cloudflare KV.
//
// The AES-GCM key is derived from the shared ACCESS_PASSWORD via PBKDF2, so
// every device that knows the access password derives the identical key —
// unlike the per-device, non-extractable key in history-key.ts. The entire
// serialized profile list is encrypted client-side before it ever reaches
// the Worker; the server only ever stores and returns opaque ciphertext.

const SALT_STRING = 'cf-workers-webssh/kv-sync/salt/v1';
const PBKDF2_ITERATIONS = 210_000;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_BLOB_BYTES = 512 * 1024;

let cachedKeyPassword: string | null = null;
let cachedKeyPromise: Promise<CryptoKey> | null = null;

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function deriveSyncKey(password: string): Promise<CryptoKey> {
  if (cachedKeyPassword === password && cachedKeyPromise) return cachedKeyPromise;
  cachedKeyPassword = password;
  cachedKeyPromise = (async () => {
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new TextEncoder().encode(SALT_STRING), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  })();
  return cachedKeyPromise;
}

async function encryptSyncBlob(plaintext: string, password: string): Promise<string> {
  const key = await deriveSyncKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
    key,
    new TextEncoder().encode(plaintext),
  ));
  return `v1.${encodeBase64Url(iv)}.${encodeBase64Url(ciphertext)}`;
}

async function decryptSyncBlob(blob: string, password: string): Promise<string | null> {
  const parts = blob.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;
  const iv = decodeBase64Url(parts[1]);
  const ciphertext = decodeBase64Url(parts[2]);
  if (!iv || iv.length !== IV_BYTES || !ciphertext) return null;
  try {
    const key = await deriveSyncKey(password);
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
      key,
      ciphertext,
    ));
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  } catch {
    return null;
  }
}

/** Fetches and decrypts the remote connection list. Returns null on any failure (offline, wrong password, no data yet) — callers fall back to local storage. */
export async function fetchRemoteProfiles(password: string): Promise<unknown[] | null> {
  try {
    const response = await fetch('/api/connections', {
      method: 'GET',
      headers: { 'X-Access-Password': password, Accept: 'application/json' },
    });
    if (!response.ok) return null;
    const payload = await response.json() as { blob?: string | null };
    if (!payload.blob) return null;
    const decrypted = await decryptSyncBlob(payload.blob, password);
    if (!decrypted) return null;
    const parsed: unknown = JSON.parse(decrypted);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** Best-effort push of the local connection list to KV. Never throws — local storage remains the source of truth if this fails. */
export async function pushRemoteProfiles(password: string, profiles: unknown): Promise<void> {
  try {
    const serialized = JSON.stringify(profiles);
    if (new TextEncoder().encode(serialized).length > MAX_BLOB_BYTES) return;
    const blob = await encryptSyncBlob(serialized, password);
    await fetch('/api/connections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Access-Password': password },
      body: JSON.stringify({ blob }),
    });
  } catch {
    // Best-effort sync; a failed push just means the next load retries.
  }
}
