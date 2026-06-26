import { useState } from "react";
import { Download } from "lucide-react";
import { exportReport } from "../../api/client";
import { downloadBlob } from "../../lib/download";

// Export a tool's result via the generic /reports/export endpoint (JSON + PDF).
export default function ExportButtons({
  data,
  reportType,
}: {
  data: unknown;
  reportType: string;
}) {
  const [busy, setBusy] = useState<string | null>(null);

  async function run(format: "json" | "pdf") {
    setBusy(format);
    try {
      const blob = await exportReport(
        data as Record<string, unknown>,
        reportType,
        format,
      );
      downloadBlob(blob, `soc_${reportType}.${format}`);
    } catch {
      // best-effort export; a failed download shouldn't break the page
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="flex gap-2">
      {(["json", "pdf"] as const).map((f) => (
        <button
          key={f}
          type="button"
          onClick={() => run(f)}
          disabled={busy !== null}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border text-muted hover:text-foreground hover:bg-foreground/5 disabled:opacity-50 disabled:cursor-not-allowed text-xs font-medium px-3 py-1.5 transition-colors"
        >
          <Download className="w-3.5 h-3.5" />
          {busy === f ? "…" : f.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
