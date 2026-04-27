// Token persistence in localStorage with a scope prefix so SOC and OSINT
// sessions stay independent (running both stacks on the same origin via
// reverse proxy would otherwise collide). The key name is intentionally
// opaque - don't parse it, use the helpers.

const KEY_PREFIX = "sec-toolkit.auth";

export type StoredUser = {
  id: string;
  username: string;
  role: string;
};

export type AuthState = {
  token: string;
  user: StoredUser;
};

function storageKey(scope: string): string {
  return `${KEY_PREFIX}.${scope}`;
}

export function readAuth(scope: string): AuthState | null {
  try {
    const raw = localStorage.getItem(storageKey(scope));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as AuthState;
    if (!parsed.token || !parsed.user?.username) return null;
    return parsed;
  } catch {
    // Corrupt entry - treat as signed-out so the login flow can recover.
    return null;
  }
}

export function writeAuth(scope: string, state: AuthState): void {
  localStorage.setItem(storageKey(scope), JSON.stringify(state));
}

export function clearAuth(scope: string): void {
  localStorage.removeItem(storageKey(scope));
}
