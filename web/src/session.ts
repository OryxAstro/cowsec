// Client side of CowSec sign-in: every /api request carries the CSRF header the
// server requires, and a 401 from any non-auth endpoint signals an expired session.

export const UNAUTHORIZED_EVENT = 'cowsec:unauthorized';

export interface Identity {
  user: string;
  displayName: string;
  email: string;
  source: 'ldap' | 'local';
  method: 'totp' | 'duo';
  createdAt: string;
  expiresAt: string;
}

export interface MeResponse {
  identity: Identity;
  totpEnrolled: boolean;
  idleTimeoutSec: number;
}

export interface AuthConfig {
  service: string;
  ldap: boolean;
  duo: boolean;
  localAdmin: boolean;
  group: string;
}

function apiPath(input: RequestInfo | URL): string | null {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  try {
    const u = new URL(raw, window.location.href);
    return u.origin === window.location.origin && u.pathname.startsWith('/api/') ? u.pathname : null;
  } catch {
    return null;
  }
}

let installed = false;

export function installFetchInterceptor() {
  if (installed) return;
  installed = true;
  const original = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = apiPath(input);
    if (!path) return original(input, init);
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    headers.set('X-CowSec-Request', '1');
    const res = await original(input, { ...init, headers, credentials: 'same-origin' });
    if (res.status === 401 && !path.startsWith('/api/auth/')) {
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    }
    return res;
  };
}

export async function postJSON<T>(path: string, body: unknown): Promise<{ ok: boolean; status: number; data: T }> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let data = {} as T;
  try {
    data = await res.json();
  } catch {
    // empty body
  }
  return { ok: res.ok, status: res.status, data };
}
