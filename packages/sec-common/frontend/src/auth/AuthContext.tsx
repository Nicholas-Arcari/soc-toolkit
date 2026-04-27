import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { AxiosInstance } from "axios";

import { AuthState, StoredUser, clearAuth, readAuth, writeAuth } from "./storage";

// The axios interceptor attaches the bearer token on every request and
// clears local state on a 401 response. Scoped to the passed client so
// two apps sharing the same origin (reverse proxy) can run independently.

type AuthContextValue = {
  state: AuthState | null;
  // True when /api/auth/setup-required returned {setup_required: true}.
  // The login page uses this to switch to a "create first admin" form.
  setupRequired: boolean;
  // False when the backend has auth disabled (AUTH_SECRET unset - the
  // /auth/setup-required probe 404s). RequireAuth bypasses the login
  // page entirely in that case so a trusted-network install works with
  // zero config.
  authEnabled: boolean;
  // True until the provider has finished its boot-time probe of the
  // backend. Render a splash/spinner instead of the login page during
  // this window to avoid the signup form flashing for already-set-up
  // installs.
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  signup: (username: string, password: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export type AuthProviderProps = {
  client: AxiosInstance;
  scope: string; // e.g. "soc" or "osint"
  children: ReactNode;
};

export function AuthProvider({ client, scope, children }: AuthProviderProps) {
  const [state, setState] = useState<AuthState | null>(() => readAuth(scope));
  const [setupRequired, setSetupRequired] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(true);
  const [loading, setLoading] = useState(true);

  // Attach + clear interceptors once, keyed on the client instance.
  useEffect(() => {
    const reqId = client.interceptors.request.use((cfg) => {
      const current = readAuth(scope);
      if (current) {
        cfg.headers = cfg.headers ?? {};
        (cfg.headers as Record<string, string>)[
          "Authorization"
        ] = `Bearer ${current.token}`;
      }
      return cfg;
    });
    const resId = client.interceptors.response.use(
      (r) => r,
      (err) => {
        // A 401 on an authenticated request means the token is stale;
        // drop it so the RequireAuth guard redirects to /login.
        if (err?.response?.status === 401) {
          clearAuth(scope);
          setState(null);
        }
        return Promise.reject(err);
      },
    );
    return () => {
      client.interceptors.request.eject(reqId);
      client.interceptors.response.eject(resId);
    };
  }, [client, scope]);

  // Probe setup-required once on mount. A 404 here means auth is
  // disabled on the backend (AUTH_SECRET unset) - flip authEnabled off
  // so RequireAuth lets traffic through without a login page. A real
  // response (even if setup_required=false) means auth is live.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await client.get("/auth/setup-required");
        if (!cancelled) {
          setAuthEnabled(true);
          setSetupRequired(Boolean(res.data?.setup_required));
        }
      } catch (err: unknown) {
        if (cancelled) return;
        const status = (err as { response?: { status?: number } })?.response?.status;
        if (status === 404) {
          setAuthEnabled(false);
          setSetupRequired(false);
        } else {
          // Unreachable backend, 5xx, CORS - keep auth enabled so the
          // user lands on the login form and can retry once the backend
          // is back up. Safer than silently letting them in.
          setAuthEnabled(true);
          setSetupRequired(false);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client]);

  const login = useCallback(
    async (username: string, password: string) => {
      const res = await client.post("/auth/login", { username, password });
      const next: AuthState = {
        token: res.data.token,
        user: res.data.user as StoredUser,
      };
      writeAuth(scope, next);
      setState(next);
    },
    [client, scope],
  );

  const signup = useCallback(
    async (username: string, password: string) => {
      const res = await client.post("/auth/signup", { username, password });
      const next: AuthState = {
        token: res.data.token,
        user: res.data.user as StoredUser,
      };
      writeAuth(scope, next);
      setState(next);
      setSetupRequired(false);
    },
    [client, scope],
  );

  const logout = useCallback(() => {
    // Fire-and-forget - server is stateless so no need to await.
    client.post("/auth/logout").catch(() => {});
    clearAuth(scope);
    setState(null);
  }, [client, scope]);

  const value = useMemo<AuthContextValue>(
    () => ({ state, setupRequired, authEnabled, loading, login, signup, logout }),
    [state, setupRequired, authEnabled, loading, login, signup, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside <AuthProvider>");
  }
  return ctx;
}

// Non-throwing variant for components that are context-aware but also
// render in test harnesses or standalone demos without a provider
// (e.g. the Sidebar's sign-out widget - absent context just hides it).
export function useOptionalAuth(): AuthContextValue | null {
  return useContext(AuthContext);
}
