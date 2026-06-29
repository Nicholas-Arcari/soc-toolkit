import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Plus, Target as TargetIcon, Trash2, CheckCircle2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import {
  createTarget,
  deleteTarget,
  listTargets,
  type Target,
} from "../api/client";

export default function Targets() {
  const { t } = useTranslation();
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  async function refresh() {
    try {
      setTargets(await listTargets());
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function handleDelete(id: number) {
    if (!confirm(t("targets.deleteConfirm"))) return;
    await deleteTarget(id);
    await refresh();
  }

  return (
    <div className="max-w-5xl space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <TargetIcon className="w-6 h-6 text-primary-500" />
            {t("targets.heading")}
          </h1>
          <p className="text-sm text-muted mt-1">{t("targets.subheading")}</p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 px-4 py-2 rounded-lg text-sm font-medium"
        >
          <Plus className="w-4 h-4" />
          {t("targets.newTarget")}
        </button>
      </header>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {showForm && (
        <NewTargetForm
          onCreated={async () => {
            setShowForm(false);
            await refresh();
          }}
          onCancel={() => setShowForm(false)}
        />
      )}

      <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
        {targets === null ? (
          <p className="p-6 text-sm text-muted">{t("targets.loading")}</p>
        ) : targets.length === 0 ? (
          <p className="p-6 text-sm text-muted">{t("targets.empty")}</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-dark-bg/50 text-xs text-muted uppercase">
              <tr>
                <th className="text-left px-4 py-3">{t("targets.columns.name")}</th>
                <th className="text-left px-4 py-3">{t("targets.columns.scope")}</th>
                <th className="text-left px-4 py-3">{t("targets.columns.owner")}</th>
                <th className="text-left px-4 py-3">{t("targets.columns.created")}</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-border">
              {targets.map((tr) => (
                <tr key={tr.id} className="hover:bg-dark-border/30">
                  <td className="px-4 py-3">
                    <Link
                      to={`/targets/${tr.id}`}
                      className="font-medium text-foreground hover:text-primary-300"
                    >
                      {tr.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-muted font-mono text-xs">
                    {tr.scope_domains.join(", ") || "-"}
                  </td>
                  <td className="px-4 py-3 text-muted">{tr.owner_email || "-"}</td>
                  <td className="px-4 py-3 text-muted text-xs">
                    {new Date(tr.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDelete(tr.id)}
                      className="text-muted hover:text-red-400"
                      aria-label={t("targets.deleteAria", { name: tr.name })}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function NewTargetForm({
  onCreated,
  onCancel,
}: {
  onCreated: () => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [ownerEmail, setOwnerEmail] = useState("");
  const [scopeDomainsRaw, setScopeDomainsRaw] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const scope_domains = scopeDomainsRaw
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      await createTarget({
        name,
        owner_email: ownerEmail || undefined,
        scope_domains,
        authorized_to_scan: authorized,
      });
      await onCreated();
    } catch (e: unknown) {
      const message =
        typeof e === "object" && e !== null && "response" in e
          ? ((e as { response?: { data?: { detail?: string } } }).response?.data
              ?.detail ?? String(e))
          : String(e);
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-dark-card border border-dark-border rounded-lg p-6 space-y-4"
    >
      <h2 className="text-lg font-semibold">{t("targets.form.heading")}</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Field label={t("targets.form.name")}>
          <input
            type="text"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full bg-dark-bg border border-dark-border rounded px-3 py-2 text-sm"
            placeholder={t("targets.form.namePlaceholder")}
          />
        </Field>
        <Field label={t("targets.form.ownerEmail")}>
          <input
            type="email"
            value={ownerEmail}
            onChange={(e) => setOwnerEmail(e.target.value)}
            className="w-full bg-dark-bg border border-dark-border rounded px-3 py-2 text-sm"
            placeholder={t("targets.form.ownerEmailPlaceholder")}
          />
        </Field>
      </div>
      <Field label={t("targets.form.scopeDomains")}>
        <textarea
          required
          value={scopeDomainsRaw}
          onChange={(e) => setScopeDomainsRaw(e.target.value)}
          className="w-full bg-dark-bg border border-dark-border rounded px-3 py-2 text-sm font-mono"
          rows={3}
          placeholder={t("targets.form.scopePlaceholder")}
        />
      </Field>

      <label className="flex items-start gap-3 p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 cursor-pointer">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
          className="mt-0.5 w-4 h-4 accent-amber-400"
        />
        <span className="text-xs text-amber-400 leading-relaxed">
          <strong className="block text-sm text-amber-100">
            {t("targets.form.authCheckbox.title")}
          </strong>
          {t("targets.form.authCheckbox.body")}
        </span>
      </label>

      {error && (
        <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded px-3 py-2">
          {error}
        </p>
      )}

      <div className="flex items-center justify-end gap-2 pt-2">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-sm text-muted hover:text-foreground"
        >
          {t("targets.form.cancel")}
        </button>
        <button
          type="submit"
          disabled={submitting || !authorized}
          className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 disabled:bg-dark-border disabled:text-muted px-4 py-2 rounded-lg text-sm font-medium"
        >
          <CheckCircle2 className="w-4 h-4" />
          {submitting ? t("targets.form.submitting") : t("targets.form.submit")}
        </button>
      </div>
    </form>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs uppercase tracking-wide text-muted">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}
