import { FormEvent, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { CheckCircle } from "lucide-react";
import { useAuth } from "@sec-toolkit/common/auth";

// Public page (outside the auth gate) that the reset email links to.
export default function ResetPassword() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const { resetPassword } = useAuth();
  const [password, setPassword] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!token) {
      setError(t("auth.missingResetLink"));
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      await resetPassword(token, password);
      setDone(true);
    } catch (err) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? t("auth.resetFailed");
      setError(detail);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm bg-card border border-border rounded-2xl p-7 space-y-5 shadow-xl">
        {done ? (
          <div className="text-center space-y-4">
            <div className="mx-auto w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center">
              <CheckCircle className="w-6 h-6 text-emerald-400" />
            </div>
            <h1 className="text-xl font-semibold text-foreground">
              {t("auth.passwordUpdatedTitle")}
            </h1>
            <p className="text-sm text-muted">{t("auth.passwordUpdatedBody")}</p>
            <Link
              to="/"
              className="inline-block w-full rounded-lg bg-foreground text-background hover:opacity-90 text-sm font-medium py-2.5 transition-opacity"
            >
              {t("auth.goToSignIn")}
            </Link>
          </div>
        ) : (
          <form onSubmit={onSubmit} className="space-y-5">
            <div className="space-y-1">
              <h1 className="text-xl font-semibold text-foreground">
                {t("auth.setNewPasswordTitle")}
              </h1>
              <p className="text-sm text-muted">{t("auth.setNewPasswordBody")}</p>
            </div>
            <div className="space-y-2">
              <label
                htmlFor="new-password"
                className="block text-xs font-medium text-muted"
              >
                {t("auth.newPassword")}
              </label>
              <input
                id="new-password"
                type="password"
                autoComplete="new-password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-lg bg-background border border-border px-3 py-2 text-foreground placeholder-muted focus:outline-none focus:ring-2 focus:ring-emerald-500/60 focus:border-emerald-500"
              />
              <p className="text-xs text-muted">{t("auth.minChars")}</p>
            </div>
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
              {submitting ? "…" : t("auth.updatePassword")}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
