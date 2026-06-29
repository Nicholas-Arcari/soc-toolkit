import { useEffect, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Download,
  Globe,
  PlayCircle,
  RefreshCw,
  Server,
  Shield,
  AlertTriangle,
  Mail,
  Radar,
  Zap,
} from "lucide-react";
import {
  exportUrl,
  getTarget,
  listFindings,
  listServices,
  listSubdomains,
  runActiveScan,
  runDNSMapping,
  runServiceDiscovery,
  runSubdomainEnum,
  updateFinding,
  type ActiveScanResult,
  type DNSMappingResult,
  type ExportKind,
  type FindingRow,
  type FindingStatus,
  type ServiceDiscoveryResult,
  type ServiceRow,
  type SubdomainEnumResult,
  type SubdomainRow,
  type Target,
} from "../api/client";

type Tab = "assets" | "discovery" | "findings";

export default function TargetDetail() {
  const { id } = useParams<{ id: string }>();
  const targetId = Number(id);

  const [target, setTarget] = useState<Target | null>(null);
  const [subdomains, setSubdomains] = useState<SubdomainRow[]>([]);
  const [services, setServices] = useState<ServiceRow[]>([]);
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [tab, setTab] = useState<Tab>("assets");
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    const [t, subs, svcs, fnds] = await Promise.all([
      getTarget(targetId),
      listSubdomains(targetId),
      listServices(targetId),
      listFindings(targetId),
    ]);
    setTarget(t);
    setSubdomains(subs);
    setServices(svcs);
    setFindings(fnds);
  }

  useEffect(() => {
    let cancelled = false;
    reload().catch((e) => !cancelled && setError(String(e)));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId]);

  if (error) {
    return (
      <div className="max-w-3xl">
        <Link to="/targets" className="text-sm text-primary-400 flex items-center gap-1 mb-4">
          <ArrowLeft className="w-4 h-4" /> Back to targets
        </Link>
        <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded px-3 py-2">
          {error}
        </p>
      </div>
    );
  }
  if (!target) {
    return <p className="text-sm text-muted">Loading…</p>;
  }

  return (
    <div className="max-w-5xl space-y-6">
      <Link to="/targets" className="text-sm text-primary-400 flex items-center gap-1 w-fit">
        <ArrowLeft className="w-4 h-4" /> Back to targets
      </Link>

      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">{target.name}</h1>
          <p className="text-sm text-muted mt-1 font-mono">
            Scope: {target.scope_domains.join(", ") || "-"}
          </p>
        </div>
        <ExportMenu targetId={targetId} targetName={target.name} />
      </header>

      <div className="border-b border-dark-border flex gap-1">
        <TabButton active={tab === "assets"} onClick={() => setTab("assets")}>
          Assets ({subdomains.length + services.length})
        </TabButton>
        <TabButton active={tab === "discovery"} onClick={() => setTab("discovery")}>
          Discovery
        </TabButton>
        <TabButton active={tab === "findings"} onClick={() => setTab("findings")}>
          Findings ({findings.length})
        </TabButton>
      </div>

      {tab === "assets" && (
        <AssetsTab
          subdomains={subdomains}
          services={services}
          onRefresh={reload}
        />
      )}
      {tab === "discovery" && (
        <DiscoveryTab
          targetId={targetId}
          targetName={target.name}
          onComplete={reload}
        />
      )}
      {tab === "findings" && (
        <FindingsTab
          targetId={targetId}
          findings={findings}
          onChange={reload}
        />
      )}
    </div>
  );
}

function AssetsTab({
  subdomains,
  services,
  onRefresh,
}: {
  subdomains: SubdomainRow[];
  services: ServiceRow[];
  onRefresh: () => Promise<void>;
}) {
  return (
    <section className="space-y-6">
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm uppercase tracking-wide text-muted flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Subdomains ({subdomains.length})
          </h2>
          <button
            onClick={onRefresh}
            className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>

        <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
          {subdomains.length === 0 ? (
            <p className="p-6 text-sm text-muted">
              No subdomains yet. Run a passive discovery from the Discovery tab.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-dark-bg/50 text-xs text-muted uppercase">
                <tr>
                  <th className="text-left px-4 py-2">FQDN</th>
                  <th className="text-left px-4 py-2">Source</th>
                  <th className="text-left px-4 py-2">First seen</th>
                  <th className="text-left px-4 py-2">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-border">
                {subdomains.map((s) => (
                  <tr key={s.fqdn} className="hover:bg-dark-border/30">
                    <td className="px-4 py-2 font-mono text-xs">{s.fqdn}</td>
                    <td className="px-4 py-2 text-muted text-xs">{s.source}</td>
                    <td className="px-4 py-2 text-muted text-xs">
                      {new Date(s.first_seen).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-2 text-muted text-xs">
                      {new Date(s.last_seen).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="space-y-3">
        <h2 className="text-sm uppercase tracking-wide text-muted flex items-center gap-2">
          <Server className="w-4 h-4" />
          Services ({services.length})
        </h2>
        <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
          {services.length === 0 ? (
            <p className="p-6 text-sm text-muted">
              No services observed yet. Run service discovery after a subdomain
              enum - it enriches resolved IPs with Shodan banner data.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-dark-bg/50 text-xs text-muted uppercase">
                <tr>
                  <th className="text-left px-4 py-2">IP</th>
                  <th className="text-left px-4 py-2">Port</th>
                  <th className="text-left px-4 py-2">Banner</th>
                  <th className="text-left px-4 py-2">CVEs</th>
                  <th className="text-left px-4 py-2">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-border">
                {services.map((s, i) => (
                  <tr
                    key={`${s.subdomain_id}-${s.ip}-${s.port}-${i}`}
                    className="hover:bg-dark-border/30"
                  >
                    <td className="px-4 py-2 font-mono text-xs">{s.ip}</td>
                    <td className="px-4 py-2 font-mono text-xs">{s.port}</td>
                    <td className="px-4 py-2 text-muted text-xs">{s.banner || "-"}</td>
                    <td className="px-4 py-2 text-xs">
                      {s.cves.length > 0 ? (
                        <span className="text-red-400">{s.cves.length}</span>
                      ) : (
                        <span className="text-muted">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-muted text-xs">
                      {new Date(s.last_seen).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </section>
  );
}

function DiscoveryTab({
  targetId,
  targetName,
  onComplete,
}: {
  targetId: number;
  targetName: string;
  onComplete: () => Promise<void>;
}) {
  return (
    <section className="space-y-4">
      <ScanCard
        title="Passive subdomain enumeration"
        icon={Globe}
        description="Reads Certificate Transparency logs (crt.sh) and SecurityTrails if a key is configured. Scope-filtered server-side."
        run={() => runSubdomainEnum(targetId)}
        onComplete={onComplete}
        renderResult={(r) => {
          const data = r as SubdomainEnumResult;
          return (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <MetricCard label="Total" value={String(data.summary.discovered_total)} />
              <MetricCard label="New" value={String(data.summary.new)} />
              <MetricCard label="Updated" value={String(data.summary.updated)} />
              <MetricCard
                label="Sources"
                value={Object.entries(data.summary.sources)
                  .filter(([, c]) => c > 0)
                  .map(([n, c]) => `${n}:${c}`)
                  .join(" · ") || "-"}
              />
            </div>
          );
        }}
      />

      <ScanCard
        title="DNS mapping + email auth"
        icon={Mail}
        description="Resolves A / AAAA / MX / NS / TXT for every scope root and flags SPF/DMARC gaps as findings."
        run={() => runDNSMapping(targetId)}
        onComplete={onComplete}
        renderResult={(r) => {
          const data = r as DNSMappingResult;
          return (
            <>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <MetricCard label="Domains" value={String(data.summary.domains_checked)} />
                <MetricCard label="Findings" value={String(data.summary.findings_created)} />
                <MetricCard
                  label="SPF present"
                  value={String(
                    data.summary.domains.filter((d) => d.spf).length,
                  )}
                />
              </div>
              <div className="mt-3 space-y-2">
                {data.summary.domains.map((d) => (
                  <div
                    key={d.domain}
                    className="bg-dark-bg border border-dark-border rounded p-3 text-xs space-y-1"
                  >
                    <div className="font-mono text-muted">{d.domain}</div>
                    <div className="text-muted">
                      A: {d.a.length} · MX: {d.mx.length} · NS: {d.ns.length}
                    </div>
                    <div className={d.spf ? "text-green-400" : "text-amber-400"}>
                      SPF: {d.spf ? "present" : "missing"}
                    </div>
                    <div className={d.dmarc ? "text-green-400" : "text-amber-400"}>
                      DMARC: {d.dmarc ? "present" : "missing"}
                    </div>
                  </div>
                ))}
              </div>
            </>
          );
        }}
      />

      <ScanCard
        title="Service discovery (Shodan)"
        icon={Radar}
        description="Queries Shodan for open ports / banners / CVEs on every resolved IP. Degrades cleanly without a key."
        run={() => runServiceDiscovery(targetId)}
        onComplete={onComplete}
        renderResult={(r) => {
          const data = r as ServiceDiscoveryResult;
          if (data.summary.skipped) {
            return (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded p-3 text-sm text-amber-400/80">
                Skipped: {data.summary.note}
              </div>
            );
          }
          return (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <MetricCard
                label="Hosts checked"
                value={String(data.summary.hosts_checked ?? 0)}
              />
              <MetricCard
                label="Services new"
                value={String(data.summary.services_new ?? 0)}
              />
              <MetricCard
                label="Services updated"
                value={String(data.summary.services_updated ?? 0)}
              />
              <MetricCard
                label="CVEs"
                value={String((data.summary.cves_seen ?? []).length)}
              />
            </div>
          );
        }}
      />

      <ActiveScanCard
        targetId={targetId}
        targetName={targetName}
        onComplete={onComplete}
      />
    </section>
  );
}

export function ActiveScanCard({
  targetId,
  targetName,
  onComplete,
}: {
  targetId: number;
  targetName: string;
  onComplete: () => Promise<void>;
}) {
  const [modalOpen, setModalOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ActiveScanResult | null>(null);

  function reset() {
    setTyped("");
    setError(null);
    setRunning(false);
  }

  async function submit() {
    setError(null);
    setRunning(true);
    try {
      const data = await runActiveScan(targetId, typed);
      setResult(data);
      setModalOpen(false);
      reset();
      await onComplete();
    } catch (e) {
      const msg = (e as { response?: { data?: { detail?: string } } }).response?.data?.detail
        ?? "Active scan failed.";
      setError(msg);
    } finally {
      setRunning(false);
    }
  }

  const canSubmit = typed.trim().toLowerCase() === targetName.trim().toLowerCase() && !running;

  return (
    <div className="bg-dark-card border border-amber-500/30 rounded-xl p-5 space-y-3">
      <div className="flex items-start gap-3">
        <Zap className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" />
        <div className="flex-1">
          <h3 className="font-semibold text-amber-100">Active subdomain scan</h3>
          <p className="text-xs text-amber-400/80 mt-1">
            Runs Subfinder/Amass as a subprocess - issues DNS probes that the
            target can observe. Requires{" "}
            <span className="font-mono">OSINT_ENABLE_ACTIVE_SCANNING=true</span>{" "}
            on the backend and explicit per-scan confirmation. Only use against
            perimeters you are authorized to probe.
          </p>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => setModalOpen(true)}
          className="text-xs px-3 py-1.5 bg-amber-600/30 hover:bg-amber-600/50 text-amber-50 rounded-lg font-medium flex items-center gap-1.5"
        >
          <PlayCircle className="w-3.5 h-3.5" />
          Start active scan…
        </button>
        {result && (
          <span className="text-xs text-muted">
            Last run: {result.summary.tool} · {result.summary.discovered_total} found ·{" "}
            {result.summary.new} new
          </span>
        )}
      </div>

      {modalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="active-scan-confirm-heading"
          className="fixed inset-0 flex items-center justify-center z-50 p-4"
        >
          <button
            type="button"
            aria-label="Cancel and close dialog"
            className="absolute inset-0 bg-black/70"
            onClick={() => {
              setModalOpen(false);
              reset();
            }}
          />
          <div className="relative bg-dark-card border border-dark-border rounded-xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" />
              <div>
                <h2 id="active-scan-confirm-heading" className="text-lg font-semibold">Confirm active scan</h2>
                <p className="text-sm text-muted mt-1">
                  Active scans issue DNS probes that the target can observe. To
                  confirm, type the target name verbatim:{" "}
                  <span className="font-mono text-foreground">{targetName}</span>
                </p>
              </div>
            </div>
            <input
              // eslint-disable-next-line jsx-a11y/no-autofocus -- focus-on-open is expected for a modal dialog
              autoFocus
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder="Type the target name to confirm"
              aria-label="Target name confirmation"
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-amber-500"
            />
            {error && (
              <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded px-2 py-1">
                {error}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setModalOpen(false);
                  reset();
                }}
                className="text-xs px-3 py-1.5 bg-dark-bg border border-dark-border rounded-lg text-muted hover:text-foreground"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!canSubmit}
                onClick={submit}
                className="text-xs px-3 py-1.5 bg-amber-600/50 hover:bg-amber-600/70 disabled:bg-dark-bg disabled:text-muted text-amber-50 rounded-lg font-medium"
              >
                {running ? "Running…" : "Run active scan"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ExportMenu({
  targetId,
  targetName,
}: {
  targetId: number;
  targetName: string;
}) {
  const [open, setOpen] = useState(false);
  const items: { kind: ExportKind; label: string }[] = [
    { kind: "subdomains.csv", label: "Subdomains (CSV)" },
    { kind: "services.csv", label: "Services (CSV)" },
    { kind: "findings.csv", label: "Findings (CSV)" },
    { kind: "report.json", label: "Full engagement (JSON)" },
  ];
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="text-xs px-3 py-1.5 bg-dark-card border border-dark-border rounded-lg text-foreground hover:bg-dark-border flex items-center gap-1.5"
      >
        <Download className="w-3.5 h-3.5" /> Export
      </button>
      {open && (
        <div className="absolute right-0 mt-1 w-56 bg-dark-card border border-dark-border rounded-lg shadow-lg z-10">
          {items.map((it) => (
            <a
              key={it.kind}
              href={exportUrl(targetId, it.kind)}
              download={`${targetName}-${it.kind}`}
              onClick={() => setOpen(false)}
              className="block px-3 py-2 text-xs text-foreground hover:bg-dark-border/50 first:rounded-t-lg last:rounded-b-lg"
            >
              {it.label}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

const STATUS_OPTIONS: { value: FindingStatus; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
];

const STATUS_CLASS: Record<FindingStatus, string> = {
  open: "bg-red-500/10 text-red-400 border-red-500/30",
  acknowledged: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  resolved: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  false_positive: "bg-muted/15 text-muted border-border",
};

function FindingsTab({
  targetId,
  findings,
  onChange,
}: {
  targetId: number;
  findings: FindingRow[];
  onChange: () => Promise<void>;
}) {
  if (findings.length === 0) {
    return (
      <p className="text-sm text-muted bg-dark-card border border-dark-border rounded-lg p-6">
        No findings yet. DNS mapping and service discovery surface SPF/DMARC
        gaps and CVE exposures here.
      </p>
    );
  }
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  // Active findings first (open/acknowledged), then by severity; resolved
  // items sink to the bottom so an analyst's eye lands on the live work.
  const activeWeight = (s: FindingStatus) =>
    s === "open" || s === "acknowledged" ? 0 : 1;
  const sorted = [...findings].sort((a, b) => {
    const byActive = activeWeight(a.status) - activeWeight(b.status);
    if (byActive !== 0) return byActive;
    return (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5);
  });
  return (
    <div className="space-y-2">
      {sorted.map((f) => (
        <FindingRowCard
          key={f.id}
          targetId={targetId}
          finding={f}
          onChange={onChange}
        />
      ))}
    </div>
  );
}

function FindingRowCard({
  targetId,
  finding,
  onChange,
}: {
  targetId: number;
  finding: FindingRow;
  onChange: () => Promise<void>;
}) {
  const [note, setNote] = useState(finding.note);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // If the reload brings in a newer note from the server, reflect it in
  // the local buffer - but don't clobber unsaved edits.
  useEffect(() => {
    setNote(finding.note);
  }, [finding.note]);

  async function save(patch: { status?: FindingStatus; note?: string }) {
    setSaving(true);
    setErr(null);
    try {
      await updateFinding(targetId, finding.id, patch);
      await onChange();
    } catch (e) {
      setErr(String(e));
    } finally {
      setSaving(false);
    }
  }

  const dirty = note !== finding.note;
  return (
    <div className="flex items-start gap-3 p-3 bg-dark-card border border-dark-border rounded-lg">
      <SeverityDot severity={finding.severity} />
      <div className="flex-1 min-w-0 space-y-2">
        <div className="flex items-start justify-between gap-3">
          <p className="text-sm text-foreground flex-1">{finding.description}</p>
          <span
            className={`text-[10px] uppercase tracking-wide px-2 py-0.5 rounded border ${STATUS_CLASS[finding.status]}`}
          >
            {finding.status.replace("_", " ")}
          </span>
        </div>
        <p className="text-xs text-muted">
          {finding.category} · {new Date(finding.created_at).toLocaleString()}
          {finding.resolved_at && (
            <>
              {" · resolved "}
              {new Date(finding.resolved_at).toLocaleString()}
            </>
          )}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor={`finding-${finding.id}-status`} className="text-xs text-muted">Status</label>
          <select
            id={`finding-${finding.id}-status`}
            value={finding.status}
            disabled={saving}
            onChange={(e) => save({ status: e.target.value as FindingStatus })}
            className="text-xs bg-dark-bg border border-dark-border rounded px-2 py-1 text-foreground"
          >
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
        <div>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Triage note…"
            rows={2}
            className="w-full text-xs bg-dark-bg border border-dark-border rounded px-2 py-1 text-foreground placeholder-gray-600"
          />
          <div className="flex items-center gap-2 mt-1">
            <button
              type="button"
              disabled={!dirty || saving}
              onClick={() => save({ note })}
              className="text-xs px-2 py-1 rounded bg-primary-600 text-white disabled:opacity-50 disabled:text-muted"
            >
              {saving ? "Saving…" : "Save note"}
            </button>
            {dirty && (
              <button
                type="button"
                onClick={() => setNote(finding.note)}
                className="text-xs text-muted hover:text-foreground"
              >
                Discard
              </button>
            )}
            {err && <span className="text-xs text-red-400">{err}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

function ScanCard<T>({
  title,
  icon: Icon,
  description,
  run,
  onComplete,
  renderResult,
}: {
  title: string;
  icon: typeof Shield;
  description: string;
  run: () => Promise<T>;
  onComplete: () => Promise<void>;
  renderResult: (result: T) => ReactNode;
}) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    setError(null);
    setRunning(true);
    try {
      const r = await run();
      setResult(r);
      await onComplete();
    } catch (e: unknown) {
      const detail =
        typeof e === "object" && e !== null && "response" in e
          ? ((e as { response?: { data?: { detail?: string } } }).response?.data?.detail ?? String(e))
          : String(e);
      setError(detail);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="bg-dark-card border border-dark-border rounded-lg p-6 space-y-4">
      <div className="flex items-start gap-3">
        <Icon className="w-5 h-5 text-primary-400 mt-0.5 shrink-0" />
        <div>
          <h2 className="text-lg font-semibold">{title}</h2>
          <p className="text-sm text-muted mt-1">{description}</p>
        </div>
      </div>

      <button
        onClick={handleRun}
        disabled={running}
        className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 disabled:bg-dark-border disabled:text-muted px-4 py-2 rounded-lg text-sm font-medium"
      >
        <PlayCircle className="w-4 h-4" />
        {running ? "Running…" : "Run"}
      </button>

      {error && (
        <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded px-3 py-2 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
        </p>
      )}

      {result && <div className="space-y-3">{renderResult(result)}</div>}
    </div>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-red-400",
    medium: "bg-amber-400",
    low: "bg-blue-400",
    info: "bg-muted",
  };
  return (
    <span
      className={`w-2 h-2 rounded-full mt-2 shrink-0 ${map[severity] ?? "bg-muted"}`}
      title={severity}
    />
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
        active
          ? "border-primary-500 text-primary-300"
          : "border-transparent text-muted hover:text-foreground"
      }`}
    >
      {children}
    </button>
  );
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-dark-bg border border-dark-border rounded p-3">
      <div className="text-xs text-muted uppercase tracking-wide">{label}</div>
      <div className="text-lg font-bold mt-1 break-all">{value}</div>
    </div>
  );
}
