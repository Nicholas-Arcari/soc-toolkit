interface SeverityBadgeProps {
  severity: string;
}

const severityStyles: Record<string, string> = {
  critical: "bg-red-900/50 text-red-300 border-red-700",
  high: "bg-orange-900/50 text-orange-300 border-orange-700",
  medium: "bg-yellow-900/50 text-yellow-300 border-yellow-700",
  low: "bg-green-900/50 text-green-300 border-green-700",
  info: "bg-blue-900/50 text-blue-300 border-blue-700",
};

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const style = severityStyles[severity.toLowerCase()] ?? severityStyles.info;

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold border ${style}`}
    >
      {severity.toUpperCase()}
    </span>
  );
}
