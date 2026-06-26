import type { PivotResult } from "../../api/client";

export type DomainTab = "certificates" | "passive_dns" | "whois" | "subdomains";
export type IPTab = "asn" | "reverse_dns" | "passive_dns" | "shodan";
export type TabName = DomainTab | IPTab;

export function tabsFor(targetType: string, pivot: PivotResult["pivot"]) {
  if (targetType === "ip") {
    return [
      { key: "asn" as const, label: "ASN" },
      { key: "reverse_dns" as const, label: "Reverse DNS", count: pivot.reverse_dns?.length },
      { key: "passive_dns" as const, label: "Passive DNS", count: pivot.passive_dns?.length },
      { key: "shodan" as const, label: "Shodan" },
    ];
  }
  return [
    { key: "certificates" as const, label: "Certificates", count: pivot.certificates?.length },
    { key: "passive_dns" as const, label: "Passive DNS", count: pivot.passive_dns?.length },
    { key: "whois" as const, label: "WHOIS" },
    { key: "subdomains" as const, label: "Subdomains", count: pivot.subdomains?.length },
  ];
}

export function defaultTab(targetType: string): TabName {
  return targetType === "ip" ? "asn" : "certificates";
}

export function TabContent({ tab, pivot }: { tab: TabName; pivot: PivotResult["pivot"] }) {
  if (tab === "certificates") return <CertificatesView rows={pivot.certificates ?? []} />;
  if (tab === "passive_dns") return <PassiveDNSView rows={pivot.passive_dns ?? []} />;
  if (tab === "whois") return <WhoisView whois={pivot.whois} history={pivot.whois_history} />;
  if (tab === "subdomains") return <SubdomainsView subs={pivot.subdomains ?? []} />;
  if (tab === "asn") return <ASNView asn={pivot.asn} />;
  if (tab === "reverse_dns") return <ReverseDNSView ptrs={pivot.reverse_dns ?? []} />;
  if (tab === "shodan") return <ShodanView shodan={pivot.shodan} />;
  return null;
}

function EmptyState({ message }: { message: string }) {
  return <p className="text-sm text-muted italic">{message}</p>;
}

function CertificatesView({ rows }: { rows: NonNullable<PivotResult["pivot"]["certificates"]> }) {
  if (rows.length === 0)
    return <EmptyState message="No certificates found in Certificate Transparency logs." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-muted border-b border-dark-border">
            <th className="pb-3 pr-4">Subdomain</th>
            <th className="pb-3 pr-4">Issuer</th>
            <th className="pb-3 pr-4">Not Before</th>
            <th className="pb-3 pr-4">Not After</th>
            <th className="pb-3">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-border">
          {rows.map((r, i) => (
            <tr key={`${r.cert_id}-${i}`}>
              <td className="py-2 pr-4 font-mono text-foreground">{r.subdomain}</td>
              <td className="py-2 pr-4 text-muted text-xs">{r.issuer}</td>
              <td className="py-2 pr-4 text-muted text-xs">{r.not_before.slice(0, 10)}</td>
              <td className="py-2 pr-4 text-muted text-xs">{r.not_after.slice(0, 10)}</td>
              <td className="py-2">
                {r.active ? (
                  <span className="text-green-400 text-xs">active</span>
                ) : (
                  <span className="text-muted text-xs">expired</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PassiveDNSView({ rows }: { rows: NonNullable<PivotResult["pivot"]["passive_dns"]> }) {
  if (rows.length === 0)
    return (
      <EmptyState message="No passive DNS records - SecurityTrails requires an API key; Mnemonic is anonymous but rate-limited." />
    );
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-muted border-b border-dark-border">
            <th className="pb-3 pr-4">Value</th>
            <th className="pb-3 pr-4">Type</th>
            <th className="pb-3 pr-4">First Seen</th>
            <th className="pb-3 pr-4">Last Seen</th>
            <th className="pb-3">Source</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-border">
          {rows.map((r, i) => (
            <tr key={i}>
              <td className="py-2 pr-4 font-mono text-foreground">{r.value}</td>
              <td className="py-2 pr-4">
                <span className="px-2 py-0.5 bg-dark-border rounded text-xs">{r.record_type}</span>
              </td>
              <td className="py-2 pr-4 text-muted text-xs">{String(r.first_seen).slice(0, 10)}</td>
              <td className="py-2 pr-4 text-muted text-xs">{String(r.last_seen).slice(0, 10)}</td>
              <td className="py-2 text-muted text-xs">{r.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function WhoisView({
  whois,
  history,
}: {
  whois?: PivotResult["pivot"]["whois"];
  history?: PivotResult["pivot"]["whois_history"];
}) {
  const hasCurrent = whois && Object.values(whois).some(Boolean);
  const hasHistory = (history?.length ?? 0) > 0;
  if (!hasCurrent && !hasHistory)
    return <EmptyState message="No WHOIS data - registrar rate-limits may apply; retry in a moment." />;

  return (
    <div className="space-y-6">
      {hasCurrent && whois && (
        <div>
          <h3 className="text-sm font-semibold text-foreground mb-3">Current WHOIS</h3>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
            {Object.entries(whois).map(([k, v]) => {
              if (!v || (Array.isArray(v) && v.length === 0)) return null;
              return (
                <div key={k}>
                  <dt className="text-muted text-xs uppercase tracking-wide">
                    {k.replace(/_/g, " ")}
                  </dt>
                  <dd className="text-foreground font-mono text-xs break-all">
                    {Array.isArray(v) ? v.join(", ") : String(v)}
                  </dd>
                </div>
              );
            })}
          </dl>
        </div>
      )}
      {hasHistory && history && (
        <div>
          <h3 className="text-sm font-semibold text-foreground mb-3">History ({history.length})</h3>
          <div className="space-y-2">
            {history.map((h, i) => (
              <div key={i} className="bg-dark-bg rounded-lg p-3 text-xs text-foreground">
                <div className="flex justify-between">
                  <span className="font-mono">{h.registrar || "unknown registrar"}</span>
                  <span className="text-muted">{h.updated_date}</span>
                </div>
                {h.contact_email && <div className="mt-1 text-muted">{h.contact_email}</div>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SubdomainsView({ subs }: { subs: string[] }) {
  if (subs.length === 0)
    return <EmptyState message="No subdomains - SecurityTrails API key required for this source." />;
  return (
    <div className="flex flex-wrap gap-2">
      {subs.map((s) => (
        <span key={s} className="px-3 py-1 bg-dark-bg rounded text-xs font-mono text-foreground">
          {s}
        </span>
      ))}
    </div>
  );
}

function ASNView({ asn }: { asn?: PivotResult["pivot"]["asn"] }) {
  if (!asn || !asn.asn) return <EmptyState message="No ASN data." />;
  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
      <div>
        <dt className="text-muted text-xs uppercase">ASN</dt>
        <dd className="text-foreground font-mono">{asn.asn}</dd>
      </div>
      <div>
        <dt className="text-muted text-xs uppercase">Description</dt>
        <dd className="text-foreground">{asn.asn_description || "-"}</dd>
      </div>
      <div>
        <dt className="text-muted text-xs uppercase">CIDR</dt>
        <dd className="text-foreground font-mono">{asn.cidr || "-"}</dd>
      </div>
      <div>
        <dt className="text-muted text-xs uppercase">Country</dt>
        <dd className="text-foreground">{asn.country || "-"}</dd>
      </div>
      <div>
        <dt className="text-muted text-xs uppercase">Registry</dt>
        <dd className="text-foreground uppercase">{asn.registry || "-"}</dd>
      </div>
    </dl>
  );
}

function ReverseDNSView({ ptrs }: { ptrs: string[] }) {
  if (ptrs.length === 0) return <EmptyState message="No PTR records for this IP." />;
  return (
    <div className="space-y-2">
      {ptrs.map((p) => (
        <div key={p} className="px-3 py-2 bg-dark-bg rounded font-mono text-sm text-foreground">
          {p}
        </div>
      ))}
    </div>
  );
}

function ShodanView({ shodan }: { shodan?: PivotResult["pivot"]["shodan"] }) {
  if (!shodan || shodan.error || !shodan.ip)
    return (
      <EmptyState
        message={shodan?.error ?? "No Shodan data - API key required for host lookups."}
      />
    );
  return (
    <div className="space-y-4">
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
        <div>
          <dt className="text-muted text-xs uppercase">Organization</dt>
          <dd className="text-foreground">{shodan.organization || "-"}</dd>
        </div>
        <div>
          <dt className="text-muted text-xs uppercase">ISP</dt>
          <dd className="text-foreground">{shodan.isp || "-"}</dd>
        </div>
        <div>
          <dt className="text-muted text-xs uppercase">Location</dt>
          <dd className="text-foreground">
            {[shodan.city, shodan.country].filter(Boolean).join(", ") || "-"}
          </dd>
        </div>
        <div>
          <dt className="text-muted text-xs uppercase">OS</dt>
          <dd className="text-foreground">{shodan.os || "-"}</dd>
        </div>
      </dl>
      {(shodan.open_ports?.length ?? 0) > 0 && (
        <div>
          <h4 className="text-xs text-muted uppercase mb-2">Open Ports</h4>
          <div className="flex flex-wrap gap-2">
            {shodan.open_ports?.map((p) => (
              <span key={p} className="px-2 py-1 bg-dark-bg rounded font-mono text-xs text-foreground">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}
      {(shodan.vulns?.length ?? 0) > 0 && (
        <div>
          <h4 className="text-xs text-red-400 uppercase mb-2">Vulnerabilities</h4>
          <div className="flex flex-wrap gap-2">
            {shodan.vulns?.map((v) => (
              <span key={v} className="px-2 py-1 bg-red-900/30 text-red-300 rounded font-mono text-xs">
                {v}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
