import { AlertTriangle } from "lucide-react";

/**
 * Sticky banner making it hard to forget that this is authorization-gated
 * software. Paired with the server-side gate in the targets route so even
 * someone bypassing the UI still hits the rule.
 */
export default function EthicsBanner() {
  return (
    <div className="bg-amber-950/40 border-b border-amber-900/50 px-6 py-2 text-xs text-amber-200 flex items-center gap-2">
      <AlertTriangle className="w-4 h-4 shrink-0" />
      <span>
        For authorized security testing and research only. See{" "}
        <a
          href="https://github.com/Nicholas-Arcari/soc-toolkit/blob/main/packages/osint-toolkit/ETHICS.md"
          target="_blank"
          rel="noreferrer"
          className="underline hover:text-amber-100"
        >
          ETHICS.md
        </a>{" "}
        before creating a target.
      </span>
    </div>
  );
}
