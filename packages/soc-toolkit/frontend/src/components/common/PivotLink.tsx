import { Link } from "react-router-dom";
import { GitBranch } from "lucide-react";

// Deep-link an indicator (domain/IP/host) into the IOC Pivot page, pre-filled.
export default function PivotLink({
  value,
  className = "",
}: {
  value: string;
  className?: string;
}) {
  return (
    <Link
      to={`/ioc-pivot?q=${encodeURIComponent(value)}`}
      title="Pivot in IOC Pivot"
      aria-label="Pivot in IOC Pivot"
      className={`inline-flex items-center justify-center rounded text-muted hover:text-cyan-400 transition-colors ${className}`}
    >
      <GitBranch className="w-3.5 h-3.5" />
    </Link>
  );
}
