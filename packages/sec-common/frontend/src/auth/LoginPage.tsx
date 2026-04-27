import { FormEvent, useState } from "react";

import { useAuth } from "./AuthContext";

export type LoginPageProps = {
  // Display label for the toolkit - shown in the page heading so a
  // user running both stacks can tell which they're logging into.
  title?: string;
};

export function LoginPage({ title = "Sign in" }: LoginPageProps) {
  const { setupRequired, login, signup } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const isSignup = setupRequired;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (isSignup) {
        await signup(username, password);
      } else {
        await login(username, password);
      }
    } catch (err) {
      // Backend returns a consistent "invalid credentials" for auth
      // failures; surface anything else verbatim for operator debugging.
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? "authentication failed";
      setError(detail);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-bg px-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm bg-dark-card border border-slate-700 rounded-xl p-6 space-y-4 shadow-xl"
      >
        <div className="space-y-1">
          <h1 className="text-xl font-semibold text-slate-100">{title}</h1>
          <p className="text-sm text-slate-400">
            {isSignup
              ? "Create the first admin account for this instance."
              : "Sign in with your admin credentials."}
          </p>
        </div>

        <div className="space-y-2">
          <label
            htmlFor="auth-username"
            className="block text-xs font-medium text-slate-300"
          >
            Username
          </label>
          <input
            id="auth-username"
            type="text"
            autoComplete="username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-md bg-slate-900 border border-slate-700 px-3 py-2 text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
          />
        </div>

        <div className="space-y-2">
          <label
            htmlFor="auth-password"
            className="block text-xs font-medium text-slate-300"
          >
            Password
          </label>
          <input
            id="auth-password"
            type="password"
            autoComplete={isSignup ? "new-password" : "current-password"}
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-md bg-slate-900 border border-slate-700 px-3 py-2 text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
          />
          {isSignup && (
            <p className="text-xs text-slate-500">Minimum 8 characters.</p>
          )}
        </div>

        {error && (
          <div
            role="alert"
            className="rounded-md bg-red-950/70 border border-red-800 text-red-200 text-sm px-3 py-2"
          >
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium py-2"
        >
          {submitting ? "…" : isSignup ? "Create admin" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
