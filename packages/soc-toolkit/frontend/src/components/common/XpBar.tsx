import { Sparkles } from "lucide-react";
import type { StoredUser } from "@sec-toolkit/common/auth";

type XpBarProps = {
  user: Pick<StoredUser, "level" | "xp_into_level" | "xp_to_next">;
  className?: string;
};

// Compact level + progress bar fed entirely by the backend-computed fields
// (level, xp_into_level, xp_to_next), so the curve lives in one place.
export default function XpBar({ user, className = "" }: XpBarProps) {
  const level = user.level ?? 1;
  const into = user.xp_into_level ?? 0;
  const toNext = user.xp_to_next ?? 0;
  const span = into + toNext;
  const pct = span > 0 ? Math.min(100, Math.round((into / span) * 100)) : 0;

  return (
    <div className={className}>
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="inline-flex items-center gap-1 font-medium text-foreground">
          <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
          Level {level}
        </span>
        <span className="text-muted">
          {into}/{span} XP
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-foreground/10 overflow-hidden">
        <div
          className="h-full rounded-full bg-emerald-500 transition-[width] duration-500 ease-out"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
