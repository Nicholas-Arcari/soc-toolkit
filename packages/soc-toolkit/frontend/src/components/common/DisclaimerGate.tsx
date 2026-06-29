import { useState } from "react";
import { ShieldAlert } from "lucide-react";

// Versioned so a material wording change can re-prompt everyone by bumping
// the suffix. Stored once accepted; the gate then never shows again.
const STORAGE_KEY = "soc-toolkit.disclaimer.v1";

// Cookie-style responsibility gate: blocks the app until the user accepts
// that lawful/ethical use is on them, not the developer. Mounted in the
// app shell (post-login) so it covers every page.
export default function DisclaimerGate() {
  const [accepted, setAccepted] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });

  if (accepted) return null;

  function accept() {
    try {
      localStorage.setItem(STORAGE_KEY, "1");
    } catch {
      // Storage blocked (private mode): let them through this session anyway.
    }
    setAccepted(true);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
      <div className="w-full max-w-lg bg-card border border-border rounded-2xl p-7 space-y-4 shadow-2xl">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-amber-500/10 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-6 h-6 text-amber-400" />
          </div>
          <h2 className="text-lg font-semibold text-foreground">
            Authorized &amp; responsible use only
          </h2>
        </div>

        <div className="space-y-3 text-sm text-muted">
          <p>
            SOC Toolkit is provided for authorized security operations,
            research and education. Analyze only systems, files and data you
            own or have explicit written permission to assess.
          </p>
          <p>
            <span className="text-foreground font-medium">
              You are solely responsible for how you use this software.
            </span>{" "}
            Any unlawful or unethical use is your responsibility alone - not
            the developer. The software is provided as-is, without warranty of
            any kind.
          </p>
        </div>

        <div className="flex justify-end pt-1">
          <button
            type="button"
            onClick={accept}
            className="rounded-lg bg-foreground text-background hover:opacity-90 text-sm font-medium px-5 py-2.5 transition-opacity"
          >
            I understand and accept
          </button>
        </div>
      </div>
    </div>
  );
}
