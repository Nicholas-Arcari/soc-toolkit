import { FormEvent, useState } from "react";
import { Shield } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useAuth } from "./AuthContext";

export type LoginPageProps = {
  // Display label for the toolkit - shown in the page heading so a
  // user running both stacks can tell which they're logging into.
  title?: string;
};

export function LoginPage({ title = "Sign in" }: LoginPageProps) {
  const { t } = useTranslation("seccommon");
  const { setupRequired, mode, login, signup, forgotPassword } = useAuth();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [wantRegister, setWantRegister] = useState(false);
  const [forgotMode, setForgotMode] = useState(false);
  const [forgotSent, setForgotSent] = useState(false);

  const isSignup = setupRequired || (mode === "saas" && wantRegister);
  const showRegisterToggle = mode === "saas" && !setupRequired && !forgotMode;
  const showForgotLink = mode === "saas" && !isSignup && !forgotMode;
  const showUsername = !forgotMode;
  const showEmail = forgotMode || (isSignup && !setupRequired);
  const showPassword = !forgotMode;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (forgotMode) {
        await forgotPassword(email);
        setForgotSent(true);
      } else if (isSignup) {
        await signup(username, password, email);
      } else {
        await login(username, password);
      }
    } catch (err) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? t("login.errorFailed");
      setError(detail);
    } finally {
      setSubmitting(false);
    }
  }

  function backToSignIn() {
    setForgotMode(false);
    setForgotSent(false);
    setError(null);
  }

  const heading = forgotMode
    ? t("login.heading.reset")
    : setupRequired
      ? t("login.heading.createAdmin")
      : isSignup
        ? t("login.heading.createAccount")
        : t("login.heading.signin");
  const subtitle = forgotMode
    ? t("login.subtitle.reset")
    : setupRequired
      ? t("login.subtitle.createAdmin")
      : isSignup
        ? t("login.subtitle.trial")
        : t("login.subtitle.signin");
  const submitLabel = forgotMode
    ? t("login.submit.reset")
    : setupRequired
      ? t("login.submit.createAdmin")
      : isSignup
        ? t("login.submit.trial")
        : t("login.submit.signin");

  const fieldClasses =
    "w-full rounded-lg bg-background border border-border px-3 py-2 text-foreground placeholder-muted focus:outline-none focus:ring-2 focus:ring-emerald-500/60 focus:border-emerald-500";

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm bg-card border border-border rounded-2xl p-7 space-y-5 shadow-xl"
      >
        <div className="space-y-3">
          <div className="flex items-center gap-2.5">
            <Shield className="w-7 h-7 text-emerald-400" />
            <span className="text-sm font-semibold text-muted">{title}</span>
          </div>
          <div className="space-y-1">
            <h1 className="text-xl font-semibold text-foreground">{heading}</h1>
            <p className="text-sm text-muted">{subtitle}</p>
          </div>
        </div>

        {forgotSent ? (
          <>
            <p className="text-sm text-muted">
              {t("login.forgotSentBefore")}
              <span className="text-foreground">
                {email || t("login.thatEmail")}
              </span>
              {t("login.forgotSentAfter")}
            </p>
            <button
              type="button"
              onClick={backToSignIn}
              className="w-full rounded-lg bg-foreground text-background hover:opacity-90 text-sm font-medium py-2.5 transition-opacity"
            >
              {t("login.backToSignIn")}
            </button>
          </>
        ) : (
          <>
            {showUsername && (
              <div className="space-y-2">
                <label
                  htmlFor="auth-username"
                  className="block text-xs font-medium text-muted"
                >
                  {t("login.username")}
                </label>
                <input
                  id="auth-username"
                  type="text"
                  autoComplete="username"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className={fieldClasses}
                />
              </div>
            )}

            {showEmail && (
              <div className="space-y-2">
                <label
                  htmlFor="auth-email"
                  className="block text-xs font-medium text-muted"
                >
                  {t("login.email")}
                </label>
                <input
                  id="auth-email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={fieldClasses}
                />
                {isSignup && (
                  <p className="text-xs text-muted">
                    {t("login.emailVerifyHint")}
                  </p>
                )}
              </div>
            )}

            {showPassword && (
              <div className="space-y-2">
                <label
                  htmlFor="auth-password"
                  className="block text-xs font-medium text-muted"
                >
                  {t("login.password")}
                </label>
                <input
                  id="auth-password"
                  type="password"
                  autoComplete={isSignup ? "new-password" : "current-password"}
                  required
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={fieldClasses}
                />
                {isSignup && (
                  <p className="text-xs text-muted">{t("login.minChars")}</p>
                )}
              </div>
            )}

            {error && (
              <div
                role="alert"
                className="rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm px-3 py-2"
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-lg bg-foreground text-background hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium py-2.5 transition-opacity"
            >
              {submitting ? "…" : submitLabel}
            </button>

            {showForgotLink && (
              <p className="text-center text-xs">
                <button
                  type="button"
                  onClick={() => {
                    setForgotMode(true);
                    setError(null);
                  }}
                  className="text-muted hover:text-foreground hover:underline"
                >
                  {t("login.forgotPassword")}
                </button>
              </p>
            )}

            {forgotMode && (
              <p className="text-center text-xs">
                <button
                  type="button"
                  onClick={backToSignIn}
                  className="text-muted hover:text-foreground hover:underline"
                >
                  {t("login.backToSignIn")}
                </button>
              </p>
            )}

            {showRegisterToggle && (
              <p className="text-center text-xs text-muted">
                {wantRegister ? t("login.haveAccount") : t("login.newHere")}
                <button
                  type="button"
                  onClick={() => {
                    setWantRegister((v) => !v);
                    setError(null);
                  }}
                  className="font-medium text-foreground hover:underline"
                >
                  {wantRegister ? t("login.signinShort") : t("login.createOne")}
                </button>
              </p>
            )}
          </>
        )}
      </form>
    </div>
  );
}
