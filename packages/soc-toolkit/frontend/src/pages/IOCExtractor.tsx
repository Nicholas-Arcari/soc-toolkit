import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Download, X, GitBranch } from "lucide-react";
import { FileUpload } from "@sec-toolkit/common/components";
import CopyButton from "../components/common/CopyButton";
import {
  awardXp,
  extractIOCs,
  exportReport,
  pivotOSINT,
  type IOC,
  type IOCExtractionResult,
  type PivotResult,
} from "../api/client";
import { TabContent, defaultTab, tabsFor, type TabName } from "../components/pivot/PivotViews";

const PIVOTABLE_TYPES = new Set(["domain", "ipv4", "ipv6"]);

export default function IOCExtractor() {
  const { t } = useTranslation();
  const [result, setResult] = useState<IOCExtractionResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("all");
  const [pivotIOC, setPivotIOC] = useState<IOC | null>(null);

  const handleFileSelect = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await extractIOCs(file);
      setResult(data);
      awardXp("ioc", data.iocs.length);
    } catch {
      setError(t("ioc.error"));
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format: string) => {
    if (!result) return;
    try {
      const blob = await exportReport(result as unknown as Record<string, unknown>, "ioc", format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ioc_report.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError(t("ioc.exportError"));
    }
  };

  const filteredIOCs = result?.iocs.filter(
    (ioc) => filter === "all" || ioc.type === filter
  ) ?? [];

  const iocTypes = result ? Object.keys(result.stats) : [];

  const typeColors: Record<string, string> = {
    ipv4: "text-red-400 bg-red-900/30",
    domain: "text-blue-400 bg-blue-900/30",
    url: "text-purple-400 bg-purple-900/30",
    email: "text-yellow-400 bg-yellow-900/30",
    sha256: "text-green-400 bg-green-900/30",
    sha1: "text-green-400 bg-green-900/30",
    md5: "text-green-400 bg-green-900/30",
    cve: "text-orange-400 bg-orange-900/30",
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">{t("ioc.title")}</h1>
        <p className="text-muted mt-2">{t("ioc.subtitle")}</p>
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        accept=".pdf,.eml,.txt,.html,.csv"
        label={t("ioc.uploadLabel")}
        description={t("ioc.uploadDescription")}
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-muted mt-4">{t("ioc.extracting")}</p>
        </div>
      )}

      {error && (
        <div className="mt-8 bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-400">
          {error}
        </div>
      )}

      {result && !loading && (
        <div className="mt-8 space-y-6">
          <div className="bg-dark-card rounded-xl border border-dark-border p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold">
                  {t("ioc.extracted", {
                    n: result.total_iocs,
                    source: result.source,
                  })}
                </h3>
              </div>
              <div className="flex gap-2">
                {["json", "csv", "pdf"].map((format) => (
                  <button
                    key={format}
                    onClick={() => handleExport(format)}
                    className="flex items-center gap-1 px-3 py-1.5 bg-dark-bg border border-dark-border rounded-lg text-xs font-medium text-foreground hover:text-foreground hover:border-primary-500 transition-colors"
                  >
                    <Download className="w-3 h-3" />
                    {format.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              {Object.entries(result.stats).map(([type, count]) => (
                <span
                  key={type}
                  className={`px-3 py-1 rounded-full text-xs font-medium ${typeColors[type] ?? "text-muted bg-card"}`}
                >
                  {type.toUpperCase()}: {count}
                </span>
              ))}
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => setFilter("all")}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                filter === "all"
                  ? "bg-primary-600 text-white"
                  : "bg-dark-card text-muted border border-dark-border hover:text-foreground"
              }`}
            >
              {t("ioc.all")}
            </button>
            {iocTypes.map((type) => (
              <button
                key={type}
                onClick={() => setFilter(type)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  filter === type
                    ? "bg-primary-600 text-white"
                    : "bg-dark-card text-muted border border-dark-border hover:text-foreground"
                }`}
              >
                {type.toUpperCase()}
              </button>
            ))}
          </div>

          <div className="bg-dark-card rounded-xl border border-dark-border p-6">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-muted border-b border-dark-border">
                    <th className="pb-3 pr-4">{t("ioc.colType")}</th>
                    <th className="pb-3 pr-4">{t("ioc.colValue")}</th>
                    <th className="pb-3 pr-4">{t("ioc.colMalicious")}</th>
                    <th className="pb-3 pr-4">{t("ioc.colContext")}</th>
                    <th className="pb-3 w-12"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-border">
                  {filteredIOCs.map((ioc, i) => {
                    const pivotable = PIVOTABLE_TYPES.has(ioc.type);
                    return (
                      <tr
                        key={i}
                        className={pivotable ? "hover:bg-dark-bg/40 cursor-pointer" : ""}
                        onClick={() => pivotable && setPivotIOC(ioc)}
                      >
                        <td className="py-3 pr-4">
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-mono ${typeColors[ioc.type] ?? "text-muted"}`}
                          >
                            {ioc.type.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-3 pr-4 font-mono text-foreground">
                          <div className="flex items-center gap-1.5 max-w-md">
                            <span className="truncate">{ioc.value}</span>
                            <CopyButton value={ioc.value} className="shrink-0" />
                          </div>
                        </td>
                        <td className="py-3 pr-4">
                          {ioc.malicious === true && <span className="text-red-400">{t("ioc.yes")}</span>}
                          {ioc.malicious === false && <span className="text-green-400">{t("ioc.no")}</span>}
                          {ioc.malicious === null && <span className="text-muted">-</span>}
                        </td>
                        <td className="py-3 pr-4 text-xs text-muted max-w-xs truncate">
                          {ioc.context ?? ""}
                        </td>
                        <td className="py-3">
                          {pivotable && (
                            <GitBranch className="w-4 h-4 text-muted hover:text-foreground" />
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {pivotIOC && <PivotDrawer ioc={pivotIOC} onClose={() => setPivotIOC(null)} />}
    </div>
  );
}

function PivotDrawer({ ioc, onClose }: { ioc: IOC; onClose: () => void }) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [result, setResult] = useState<PivotResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabName>("certificates");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await pivotOSINT(ioc.type, ioc.value);
        if (!cancelled) {
          setResult(data);
          setActiveTab(defaultTab(data.target_type));
        }
      } catch {
        if (!cancelled) setError(t("ioc.pivotFailed"));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [ioc.type, ioc.value, t]);

  const tabs = result ? tabsFor(result.target_type, result.pivot) : [];

  return (
    <div className="fixed inset-0 z-50 flex">
      <button
        type="button"
        aria-label={t("ioc.closePanel")}
        className="flex-1 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="w-[40rem] max-w-full bg-dark-bg border-l border-dark-border overflow-y-auto">
        <div className="sticky top-0 bg-dark-bg border-b border-dark-border p-4 flex items-center justify-between z-10">
          <div>
            <div className="text-xs text-muted uppercase">{ioc.type}</div>
            <div className="text-lg font-mono text-foreground break-all">{ioc.value}</div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-dark-card rounded-lg text-muted hover:text-foreground"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6">
          {loading && (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500 mx-auto" />
              <p className="text-muted mt-3 text-sm">{t("ioc.pivoting")}</p>
            </div>
          )}

          {error && (
            <div className="bg-red-900/20 border border-red-700 rounded-lg p-3 text-sm text-red-400">
              {error}
            </div>
          )}

          {result?.error && (
            <div className="bg-yellow-900/20 border border-yellow-700 rounded-lg p-3 text-sm text-yellow-400">
              {result.error}
            </div>
          )}

          {result && !result.error && !loading && (
            <>
              <div className="flex flex-wrap gap-3 text-xs text-muted mb-4 pb-4 border-b border-dark-border">
                {Object.entries(result.summary).map(([k, v]) => (
                  <div key={k}>
                    <span className="text-muted">{k.replace(/_/g, " ")}:</span>{" "}
                    <span className="text-foreground font-mono">{String(v || "-")}</span>
                  </div>
                ))}
              </div>

              <div className="flex gap-1 border-b border-dark-border mb-4 overflow-x-auto">
                {tabs.map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => setActiveTab(tab.key)}
                    className={`px-3 py-2 text-xs font-medium border-b-2 -mb-px transition-colors whitespace-nowrap ${
                      activeTab === tab.key
                        ? "border-primary-500 text-foreground"
                        : "border-transparent text-muted hover:text-foreground"
                    }`}
                  >
                    {tab.label}
                    {tab.count !== undefined && tab.count > 0 && (
                      <span className="ml-1.5 px-1.5 py-0.5 bg-dark-border rounded text-[10px]">
                        {tab.count}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              <TabContent tab={activeTab} pivot={result.pivot} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
