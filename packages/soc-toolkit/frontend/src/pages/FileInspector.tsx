import { useState } from "react";
import { useTranslation } from "react-i18next";
import ExportButtons from "../components/common/ExportButtons";
import CopyButton from "../components/common/CopyButton";
import { FileUpload } from "@sec-toolkit/common/components";
import {
  AlertTriangle,
  CheckCircle,
  FileWarning,
  Hash,
  Link2,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";
import { awardXp, inspectFile, type FileInspectionReport } from "../api/client";

const VERDICTS: Record<string, { label: string; cls: string; Icon: LucideIcon }> =
  {
    malicious: {
      label: "Malicious",
      cls: "text-red-400 bg-red-500/10 border-red-500/30",
      Icon: ShieldAlert,
    },
    suspicious: {
      label: "Suspicious",
      cls: "text-amber-400 bg-amber-500/10 border-amber-500/30",
      Icon: AlertTriangle,
    },
    clean: {
      label: "Clean",
      cls: "text-green-400 bg-green-500/10 border-green-500/30",
      Icon: CheckCircle,
    },
  };

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function FileInspector() {
  const { t } = useTranslation();
  const [report, setReport] = useState<FileInspectionReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleFileSelect(file: File) {
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const report = await inspectFile(file);
      setReport(report);
      awardXp("file", report.reasons.length);
    } catch {
      setError(t("file.error"));
    } finally {
      setLoading(false);
    }
  }

  const verdict = report ? (VERDICTS[report.verdict] ?? VERDICTS.clean) : null;
  const embedded = report?.embedded;
  const hasEmbedded =
    !!embedded &&
    (embedded.urls.length > 0 ||
      embedded.ips.length > 0 ||
      embedded.script_markers.length > 0);
  const yesNo = (v: boolean) => (v ? t("common.yes") : t("common.no"));

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">{t("file.title")}</h1>
        <p className="text-muted mt-2">{t("file.subtitle")}</p>
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        label={t("file.uploadLabel")}
        description={t("file.uploadDescription")}
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-muted mt-4">{t("file.inspecting")}</p>
        </div>
      )}

      {error && (
        <div className="mt-8 bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-red-400">
          {error}
        </div>
      )}

      {report && verdict && !loading && (
        <div className="mt-8 space-y-6">
          <div className="flex justify-end">
            <ExportButtons data={report} reportType="fileinspect" />
          </div>
          <div className="bg-card border border-border rounded-xl p-6">
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-3 min-w-0">
                <span
                  className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-semibold ${verdict.cls}`}
                >
                  <verdict.Icon className="w-4 h-4" />
                  {t(`file.verdict.${report.verdict}`, verdict.label)}
                </span>
                <span
                  className="text-muted text-sm truncate"
                  title={report.filename}
                >
                  {report.filename}
                </span>
              </div>
              <div className="text-right">
                <p className="text-2xl font-bold text-foreground">
                  {report.risk_score}
                  <span className="text-sm text-muted">/100</span>
                </p>
                <p className="text-xs text-muted">{t("file.riskScore")}</p>
              </div>
            </div>
            {report.reasons.length > 0 && (
              <ul className="mt-4 space-y-1.5">
                {report.reasons.map((reason) => (
                  <li
                    key={reason}
                    className="flex items-start gap-2 text-sm text-foreground"
                  >
                    <FileWarning className="w-4 h-4 mt-0.5 shrink-0 text-amber-400" />
                    {reason}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-card border border-border rounded-xl p-5 space-y-2 text-sm">
              <h3 className="font-semibold text-foreground mb-2">
                {t("file.fileSection")}
              </h3>
              <Row label={t("file.detectedType")} value={report.detected_type} />
              <Row
                label={t("file.extension")}
                value={report.extension ? `.${report.extension}` : "-"}
              />
              <Row label={t("file.size")} value={formatBytes(report.size)} />
              <Row
                label={t("file.typeMismatch")}
                value={yesNo(report.type_mismatch)}
                warn={report.type_mismatch}
              />
              <Row
                label={t("file.officeMacros")}
                value={yesNo(report.macros)}
                warn={report.macros}
              />
              <Row
                label={t("file.appendedData")}
                value={
                  report.trailing_bytes > 0
                    ? `${report.trailing_bytes} B`
                    : t("common.no")
                }
                warn={report.trailing_bytes > 0}
              />
            </div>

            <div className="bg-card border border-border rounded-xl p-5 space-y-2 text-sm">
              <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                <Hash className="w-4 h-4 text-muted" />
                {t("file.hashes")}
              </h3>
              <HashRow label="MD5" value={report.hashes.md5} />
              <HashRow label="SHA1" value={report.hashes.sha1} />
              <HashRow label="SHA256" value={report.hashes.sha256} />
            </div>
          </div>

          {report.yara_matches.length > 0 && (
            <div className="bg-card border border-border rounded-xl p-5">
              <h3 className="font-semibold text-foreground mb-3">
                {t("file.yaraMatches")}
              </h3>
              <div className="flex flex-wrap gap-2">
                {report.yara_matches.map((match) => (
                  <span
                    key={match.rule}
                    className="px-2.5 py-1 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30 text-xs font-medium"
                  >
                    {match.rule}
                  </span>
                ))}
              </div>
            </div>
          )}

          {hasEmbedded && embedded && (
            <div className="bg-card border border-border rounded-xl p-5 space-y-3">
              <h3 className="font-semibold text-foreground flex items-center gap-2">
                <Link2 className="w-4 h-4 text-muted" />
                {t("file.embeddedIndicators")}
              </h3>
              {embedded.script_markers.length > 0 && (
                <Indicators
                  title={t("file.scriptMarkers")}
                  items={embedded.script_markers}
                  tone="amber"
                />
              )}
              {embedded.urls.length > 0 && (
                <Indicators
                  title={t("file.urls")}
                  items={embedded.urls}
                  tone="muted"
                />
              )}
              {embedded.ips.length > 0 && (
                <Indicators
                  title={t("file.ips")}
                  items={embedded.ips}
                  tone="muted"
                />
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({
  label,
  value,
  warn,
}: {
  label: string;
  value: string;
  warn?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted">{label}</span>
      <span className={warn ? "text-amber-400 font-medium" : "text-foreground"}>
        {value}
      </span>
    </div>
  );
}

function HashRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-muted text-xs">{label}</span>
      <div className="flex items-start gap-1.5">
        <p className="font-mono text-xs text-foreground break-all">{value}</p>
        <CopyButton
          value={value}
          label={`Copy ${label}`}
          className="shrink-0 mt-0.5"
        />
      </div>
    </div>
  );
}

function Indicators({
  title,
  items,
  tone,
}: {
  title: string;
  items: string[];
  tone: "amber" | "muted";
}) {
  const cls =
    tone === "amber"
      ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
      : "bg-foreground/5 text-muted border-border";
  return (
    <div>
      <p className="text-xs text-muted mb-1.5">{title}</p>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item) => (
          <span
            key={item}
            className={`px-2 py-0.5 rounded-md border text-xs font-mono break-all ${cls}`}
          >
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}
