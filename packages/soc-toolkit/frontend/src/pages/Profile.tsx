import { useRef, useState, type ChangeEvent } from "react";
import { useTranslation } from "react-i18next";
import { Award, KeyRound, LogOut, Trash2, Upload } from "lucide-react";
import { trialDaysLeft, useOptionalAuth } from "@sec-toolkit/common/auth";
import { redeemLicense, removeAvatar, uploadAvatar } from "../api/client";
import Avatar from "../components/common/Avatar";
import XpBar from "../components/common/XpBar";

function errorDetail(err: unknown, fallback: string): string {
  return (
    (err as { response?: { data?: { detail?: string } } })?.response?.data
      ?.detail ?? fallback
  );
}

export default function Profile() {
  const { t } = useTranslation();
  const auth = useOptionalAuth();
  const state = auth?.state ?? null;
  const refreshUser = auth?.refreshUser;
  const logout = auth?.logout;
  const mode = auth?.mode;

  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [licenseKey, setLicenseKey] = useState("");
  const [licenseMsg, setLicenseMsg] = useState<string | null>(null);
  // Bumped after a change so the <img> re-fetches even when the avatar URL
  // (same user id + extension) is byte-different.
  const [bust, setBust] = useState(() => Date.now());

  if (!state) {
    return <p className="text-muted">{t("profile.notSignedIn")}</p>;
  }

  const user = state.user;
  const trialLeft = trialDaysLeft(user);
  const previewSrc = user.avatar ? `${user.avatar}?t=${bust}` : null;

  async function onPick(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    setBusy(true);
    try {
      await uploadAvatar(file);
      await refreshUser?.();
      setBust(Date.now());
    } catch (err) {
      setError(errorDetail(err, t("profile.uploadFailed")));
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  async function onRemove() {
    setError(null);
    setBusy(true);
    try {
      await removeAvatar();
      await refreshUser?.();
      setBust(Date.now());
    } catch (err) {
      setError(errorDetail(err, t("profile.removeFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function onRedeem() {
    if (!licenseKey.trim()) return;
    setError(null);
    setLicenseMsg(null);
    setBusy(true);
    try {
      await redeemLicense(licenseKey.trim());
      await refreshUser?.();
      setLicenseKey("");
      setLicenseMsg(t("profile.licenseActivated"));
    } catch (err) {
      setError(errorDetail(err, t("profile.licenseFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-2xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">{t("profile.title")}</h1>
        <p className="text-muted mt-2">{t("profile.subtitle")}</p>
      </div>

      <div className="bg-card border border-border rounded-xl p-6 space-y-6">
        <div className="flex items-center gap-5">
          <Avatar username={user.username} avatar={previewSrc} size={72} />
          <div className="space-y-1.5">
            <p className="text-lg font-semibold text-foreground">
              {user.username}
            </p>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="px-2 py-0.5 rounded-full bg-foreground/5 text-muted border border-border capitalize">
                {user.role}
              </span>
              {trialLeft !== null ? (
                <span className="px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30">
                  {t("profile.trial", { days: trialLeft })}
                </span>
              ) : user.plan && user.plan !== "unlimited" ? (
                <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 capitalize">
                  {user.plan}
                </span>
              ) : null}
            </div>
          </div>
        </div>

        <XpBar user={user} />

        {user.badges && user.badges.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {user.badges.map((b) => (
              <span
                key={b.id}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-foreground/5 border border-border text-xs text-muted"
              >
                <Award className="w-3.5 h-3.5 text-amber-400" />
                {b.label}
              </span>
            ))}
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

        <div className="space-y-2">
          <div className="flex flex-wrap gap-3">
            <input
              ref={fileRef}
              type="file"
              accept="image/png,image/jpeg,image/webp,image/gif"
              className="hidden"
              onChange={onPick}
            />
            <button
              type="button"
              disabled={busy}
              onClick={() => fileRef.current?.click()}
              className="inline-flex items-center gap-2 rounded-lg bg-foreground text-background hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium px-4 py-2 transition-opacity"
            >
              <Upload className="w-4 h-4" />
              {user.avatar ? t("profile.changeAvatar") : t("profile.uploadAvatar")}
            </button>
            {user.avatar && (
              <button
                type="button"
                disabled={busy}
                onClick={onRemove}
                className="inline-flex items-center gap-2 rounded-lg border border-border text-muted hover:text-foreground hover:bg-foreground/5 disabled:opacity-50 text-sm font-medium px-4 py-2 transition-colors"
              >
                <Trash2 className="w-4 h-4" />
                {t("profile.remove")}
              </button>
            )}
          </div>
          <p className="text-xs text-muted">{t("profile.avatarHint")}</p>
        </div>
      </div>

      {mode === "saas" && (
        <div className="bg-card border border-border rounded-xl p-6 mt-6 space-y-3">
          <h2 className="font-semibold text-foreground flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-emerald-400" />
            {t("profile.license")}
          </h2>
          <p className="text-sm text-muted">{t("profile.licensePrompt")}</p>
          <div className="flex flex-wrap gap-2">
            <input
              type="text"
              value={licenseKey}
              onChange={(e) => setLicenseKey(e.target.value)}
              placeholder="SOCK-…"
              className="flex-1 min-w-[12rem] rounded-lg bg-background border border-border px-3 py-2 text-sm text-foreground placeholder-muted font-mono focus:outline-none focus:ring-2 focus:ring-emerald-500/60 focus:border-emerald-500"
            />
            <button
              type="button"
              disabled={busy || !licenseKey.trim()}
              onClick={onRedeem}
              className="rounded-lg bg-foreground text-background hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium px-4 py-2 transition-opacity"
            >
              {t("profile.redeem")}
            </button>
          </div>
          {licenseMsg && <p className="text-xs text-emerald-400">{licenseMsg}</p>}
        </div>
      )}

      {logout && (
        <button
          type="button"
          onClick={logout}
          className="mt-6 inline-flex items-center gap-2 rounded-lg border border-border text-muted hover:text-foreground hover:bg-foreground/5 text-sm font-medium px-4 py-2 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          {t("profile.signOut")}
        </button>
      )}
    </div>
  );
}
