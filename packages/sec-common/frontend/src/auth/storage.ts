// Token persistence in localStorage with a scope prefix so SOC and OSINT
// sessions stay independent (running both stacks on the same origin via
// reverse proxy would otherwise collide). The key name is intentionally
// opaque - don't parse it, use the helpers.

const KEY_PREFIX = "sec-toolkit.auth";

export type StoredUser = {
  id: string;
  username: string;
  role: string;
  // SaaS subscription fields. Optional so single-tenant tokens (which
  // never carry them) and older persisted sessions stay valid.
  plan?: string;
  trial_ends_at?: string | null;
  // Public URL of the uploaded profile image, or null/undefined.
  avatar?: string | null;
  // Gamification fields (derived + returned by the backend).
  xp?: number;
  level?: number;
  xp_into_level?: number;
  xp_to_next?: number;
  email?: string;
  email_verified?: boolean;
  // Achievement badges earned at level milestones (derived by the backend).
  badges?: { id: string; label: string }[];
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
