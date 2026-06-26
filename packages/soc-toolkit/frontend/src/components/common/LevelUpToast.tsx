import { useEffect, useRef, useState } from "react";
import { Sparkles } from "lucide-react";
import { useOptionalAuth } from "@sec-toolkit/common/auth";

// Watches the signed-in user's level and shows a transient toast whenever it
// increases (XP is awarded after analyses via the auth context refresh).
export default function LevelUpToast() {
  const auth = useOptionalAuth();
  const level = auth?.state?.user.level ?? null;
  const previous = useRef<number | null>(null);
  const [shown, setShown] = useState<number | null>(null);

  useEffect(() => {
    if (level == null) {
      previous.current = null;
      return;
    }
    if (previous.current != null && level > previous.current) {
      setShown(level);
      const timer = setTimeout(() => setShown(null), 4000);
      previous.current = level;
      return () => clearTimeout(timer);
    }
    previous.current = level;
  }, [level]);

  if (shown == null) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 rounded-xl bg-card border border-emerald-500/40 shadow-2xl px-4 py-3">
      <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center">
        <Sparkles className="w-5 h-5 text-emerald-400" />
      </div>
      <div>
        <p className="text-sm font-semibold text-foreground">Level up!</p>
        <p className="text-xs text-muted">You reached level {shown}.</p>
      </div>
    </div>
  );
}
