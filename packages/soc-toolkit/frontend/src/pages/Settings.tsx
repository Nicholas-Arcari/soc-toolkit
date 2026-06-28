import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, ExternalLink, Eye, EyeOff, KeyRound } from "lucide-react";
import {
  API_KEY_SERVICES,
  readApiKeys,
  writeApiKeys,
  type ApiKeyMap,
} from "../lib/apiKeys";
import { healthCheck } from "../api/client";

export default function Settings() {
  const { t } = useTranslation();
  const [keys, setKeys] = useState<ApiKeyMap>(() => readApiKeys());
  const [reveal, setReveal] = useState<Record<string, boolean>>({});
  const [configured, setConfigured] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);

  function refreshConfigured() {
    healthCheck()
      .then((h) => setConfigured(h.configured_apis ?? []))
      .catch(() => setConfigured([]));
  }

  useEffect(() => {
    refreshConfigured();
  }, []);

  function update(id: string, value: string) {
    setKeys((k) => ({ ...k, [id]: value }));
    setSaved(false);
  }

  function save() {
    writeApiKeys(keys);
    setKeys(readApiKeys());
    setSaved(true);
    // Keys are persisted now, so the next health probe carries them.
    window.setTimeout(refreshConfigured, 50);
  }

  function clearAll() {
    writeApiKeys({});
    setKeys({});
    setReveal({});
    setSaved(false);
    window.setTimeout(refreshConfigured, 50);
  }

  return (
    <div className="max-w-2xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">{t("settings.title")}</h1>
        <p className="text-muted mt-2">{t("settings.subtitle")}</p>
      </div>

      <div className="bg-card border border-border rounded-xl p-6 space-y-5">
        <div className="flex items-start gap-3 rounded-lg bg-foreground/5 border border-border p-3 text-sm text-muted">
          <KeyRound className="w-4 h-4 mt-0.5 text-emerald-400 shrink-0" />
          <p>{t("settings.info")}</p>
        </div>

        <div className="space-y-4">
          {API_KEY_SERVICES.map((svc) => {
            const isConfigured = configured.includes(svc.id);
            const shown = reveal[svc.id] ?? false;
            return (
              <div key={svc.id} className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor={`key-${svc.id}`}
                    className="text-sm font-medium text-foreground inline-flex items-center gap-2"
                  >
                    {svc.label}
                    {isConfigured && (
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                        <Check className="w-3 h-3" /> {t("settings.active")}
                      </span>
                    )}
                  </label>
                  <a
                    href={svc.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-muted hover:text-foreground inline-flex items-center gap-1"
                  >
                    {t("settings.getKey")} <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <div className="relative">
                  <input
                    id={`key-${svc.id}`}
                    type={shown ? "text" : "password"}
                    autoComplete="off"
                    spellCheck={false}
                    value={keys[svc.id] ?? ""}
                    onChange={(e) => update(svc.id, e.target.value)}
                    placeholder={t("settings.placeholder")}
                    className="w-full rounded-lg bg-background border border-border px-3 py-2 pr-10 text-foreground placeholder-muted focus:outline-none focus:ring-2 focus:ring-emerald-500/60 focus:border-emerald-500"
                  />
                  <button
                    type="button"
                    onClick={() => setReveal((r) => ({ ...r, [svc.id]: !shown }))}
                    aria-label={shown ? t("settings.hideKey") : t("settings.showKey")}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted hover:text-foreground"
                  >
                    {shown ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex items-center gap-3 pt-1">
          <button
            type="button"
            onClick={save}
            className="rounded-lg bg-foreground text-background hover:opacity-90 text-sm font-medium px-4 py-2 transition-opacity"
          >
            {t("settings.save")}
          </button>
          <button
            type="button"
            onClick={clearAll}
            className="rounded-lg border border-border text-muted hover:text-foreground hover:bg-foreground/5 text-sm font-medium px-4 py-2 transition-colors"
          >
            {t("settings.clearAll")}
          </button>
          {saved && (
            <span className="text-xs text-emerald-400 inline-flex items-center gap-1">
              <Check className="w-3.5 h-3.5" /> {t("settings.saved")}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
