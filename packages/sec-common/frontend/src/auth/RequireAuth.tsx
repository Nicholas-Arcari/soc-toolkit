import { ReactNode, useEffect, useState } from "react";
import { Clock, MailCheck } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useAuth } from "./AuthContext";
import { LoginPage, LoginPageProps } from "./LoginPage";
import { isTrialExpired } from "./trial";

export type RequireAuthProps = {
  children: ReactNode;
  loginProps?: LoginPageProps;
};

// Route guard: renders the login page instead of children when the
// user is unauthenticated. Shows a tiny splash during the setup-probe
// window to avoid flashing the signup form on already-configured apps.
// When the backend has auth disabled (probe 404), we render children
// directly - zero-config trusted-network installs don't get a login
// wall between them and the app.
export function RequireAuth({ children, loginProps }: RequireAuthProps) {
  const {
    state,
    loading,
    authEnabled,
    mode,
    logout,
    refreshUser,
    resendVerification,
    redeemLicense,
  } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background text-muted text-sm">
        …
      </div>
    );
  }

  if (!authEnabled) {
    return <>{children}</>;
  }

  if (!state) {
    return <LoginPage {...loginProps} />;
  }

  // SaaS accounts must confirm their email before using the app (anti-abuse).
  if (mode === "saas" && state.user.email_verified === false) {
    return (
      <VerifyEmailGate
        email={state.user.email ?? ""}
        onResend={resendVerification}
        onRefresh={refreshUser}
        onSignOut={logout}
      />
    );
  }

  // SaaS: a lapsed trial OR a paid plan whose license no longer validates
  // (downgraded to "expired" server-side at login) lands here. The user can
  // redeem a key inline to continue, or sign out.
  if (
    mode === "saas" &&
    (state.user.plan === "expired" || isTrialExpired(state.user))
  ) {
    return (
      <PlanEndedGate
        expiredPlan={state.user.plan === "expired"}
        username={state.user.username}
        onRedeem={redeemLicense}
        onSignOut={logout}
      />
    );
  }

  return <>{children}</>;
}

function VerifyEmailGate({
  email,
  onResend,
  onRefresh,
  onSignOut,
}: {
  email: string;
  onResend: () => Promise<void>;
  onRefresh: () => Promise<void>;
  onSignOut: () => void;
}) {
  const { t } = useTranslation("seccommon");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);

  // If the user just clicked the link (here or in another tab), re-checking
  // /me lifts the gate without forcing a re-login.
  useEffect(() => {
    void onRefresh();
  }, [onRefresh]);

  async function resend() {
    setBusy(true);
    try {
      await onResend();
      setSent(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <div className="w-full max-w-md bg-card border border-border rounded-2xl p-8 text-center space-y-4 shadow-xl">
        <div className="mx-auto w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center">
          <MailCheck className="w-6 h-6 text-emerald-400" />
        </div>
        <h1 className="text-xl font-semibold text-foreground">
          {t("gate.verifyTitle")}
        </h1>
        <p className="text-sm text-muted">
          {t("gate.verifyBodyBefore")}
          <span className="text-foreground">{email || t("gate.yourEmail")}</span>
          {t("gate.verifyBodyAfter")}
        </p>
        <div className="space-y-2">
          <button
            type="button"
            onClick={resend}
            disabled={busy || sent}
            className="w-full rounded-lg bg-foreground text-background hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium py-2.5 transition-opacity"
          >
            {sent
              ? t("gate.linkSent")
              : busy
                ? t("gate.sending")
                : t("gate.resendLink")}
          </button>
          <button
            type="button"
            onClick={onSignOut}
            className="w-full rounded-lg border border-border text-muted hover:text-foreground hover:bg-foreground/5 text-sm font-medium py-2.5 transition-colors"
          >
            {t("gate.signOut")}
          </button>
        </div>
      </div>
    </div>
  );
}

function PlanEndedGate({
  expiredPlan,
  username,
  onRedeem,
  onSignOut,
}: {
  expiredPlan: boolean;
  username: string;
  onRedeem: (key: string) => Promise<void>;
  onSignOut: () => void;
}) {
  const { t } = useTranslation("seccommon");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function redeem() {
    if (!key.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await onRedeem(key.trim());
    } catch (err) {
      setError(
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? t("gate.licenseError"),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <div className="w-full max-w-md bg-card border border-border rounded-2xl p-8 space-y-4 shadow-xl">
        <div className="mx-auto w-12 h-12 rounded-xl bg-amber-500/10 flex items-center justify-center">
          <Clock className="w-6 h-6 text-amber-400" />
        </div>
        <div className="text-center space-y-1">
          <h1 className="text-xl font-semibold text-foreground">
            {expiredPlan ? t("gate.planEnded") : t("gate.trialEnded")}
          </h1>
          <p className="text-sm text-muted">
            {expiredPlan
              ? t("gate.welcomeBack", { username })
              : t("gate.thanksTrying", { username })}
          </p>
        </div>
        <div className="space-y-2">
          <input
            type="text"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="SOCK-…"
            className="w-full rounded-lg bg-background border border-border px-3 py-2 text-sm text-foreground placeholder-muted font-mono focus:outline-none focus:ring-2 focus:ring-emerald-500/60 focus:border-emerald-500"
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            type="button"
            onClick={redeem}
            disabled={busy || !key.trim()}
            className="w-full rounded-lg bg-foreground text-background hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium py-2.5 transition-opacity"
          >
            {busy ? "…" : t("gate.activateLicense")}
          </button>
          <button
            type="button"
            onClick={onSignOut}
            className="w-full rounded-lg border border-border text-muted hover:text-foreground hover:bg-foreground/5 text-sm font-medium py-2.5 transition-colors"
          >
            {t("gate.signOut")}
          </button>
        </div>
      </div>
    </div>
  );
}
