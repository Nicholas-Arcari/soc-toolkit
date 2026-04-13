import { useState } from "react";
import { Download } from "lucide-react";
import FileUpload from "../components/common/FileUpload";
import { extractIOCs, exportReport, type IOCExtractionResult } from "../api/client";

export default function IOCExtractor() {
  const [result, setResult] = useState<IOCExtractionResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("all");

  const handleFileSelect = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await extractIOCs(file);
      setResult(data);
    } catch {
      setError("Extraction failed. Make sure the backend is running.");
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
      setError("Export failed.");
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
        <h1 className="text-3xl font-bold">IOC Extractor</h1>
        <p className="text-gray-400 mt-2">Extract indicators of compromise from files and text</p>
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        accept=".pdf,.eml,.txt,.html,.csv"
        label="Upload File"
        description="Supports PDF threat reports, .eml emails, plain text, HTML, CSV"
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-gray-400 mt-4">Extracting IOCs...</p>
        </div>
      )}

      {error && (
        <div className="mt-8 bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-400">
          {error}
        </div>
      )}

      {result && !loading && (
        <div className="mt-8 space-y-6">
          {/* Stats */}
          <div className="bg-dark-card rounded-xl border border-dark-border p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold">
                  {result.total_iocs} IOCs extracted from {result.source}
                </h3>
              </div>
              <div className="flex gap-2">
                {["json", "csv", "pdf"].map((format) => (
                  <button
                    key={format}
                    onClick={() => handleExport(format)}
                    className="flex items-center gap-1 px-3 py-1.5 bg-dark-bg border border-dark-border rounded-lg text-xs font-medium text-gray-300 hover:text-white hover:border-primary-500 transition-colors"
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
                  className={`px-3 py-1 rounded-full text-xs font-medium ${typeColors[type] ?? "text-gray-400 bg-gray-800"}`}
                >
                  {type.toUpperCase()}: {count}
                </span>
              ))}
            </div>
          </div>

          {/* Filter */}
          <div className="flex gap-2">
            <button
              onClick={() => setFilter("all")}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                filter === "all"
                  ? "bg-primary-600 text-white"
                  : "bg-dark-card text-gray-400 border border-dark-border hover:text-white"
              }`}
            >
              All
            </button>
            {iocTypes.map((type) => (
              <button
                key={type}
                onClick={() => setFilter(type)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  filter === type
                    ? "bg-primary-600 text-white"
                    : "bg-dark-card text-gray-400 border border-dark-border hover:text-white"
                }`}
              >
                {type.toUpperCase()}
              </button>
            ))}
          </div>

          {/* IOC Table */}
          <div className="bg-dark-card rounded-xl border border-dark-border p-6">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-400 border-b border-dark-border">
                    <th className="pb-3 pr-4">Type</th>
                    <th className="pb-3 pr-4">Value</th>
                    <th className="pb-3 pr-4">Malicious</th>
                    <th className="pb-3">Context</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-border">
                  {filteredIOCs.map((ioc, i) => (
                    <tr key={i}>
                      <td className="py-3 pr-4">
                        <span className={`px-2 py-0.5 rounded text-xs font-mono ${typeColors[ioc.type] ?? "text-gray-400"}`}>
                          {ioc.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 pr-4 font-mono text-gray-300 max-w-md truncate">
                        {ioc.value}
                      </td>
                      <td className="py-3 pr-4">
                        {ioc.malicious === true && <span className="text-red-400">Yes</span>}
                        {ioc.malicious === false && <span className="text-green-400">No</span>}
                        {ioc.malicious === null && <span className="text-gray-500">-</span>}
                      </td>
                      <td className="py-3 text-xs text-gray-500 max-w-xs truncate">
                        {ioc.context ?? ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
