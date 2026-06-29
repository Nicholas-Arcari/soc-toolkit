import {
  LayoutDashboard,
  Mail,
  FileText,
  Search,
  GitBranch,
  FileSearch,
  Radar,
  Share2,
  Newspaper,
  ScanSearch,
  QrCode,
  Link2,
  type LucideIcon,
} from "lucide-react";

/**
 * Single source of truth for the toolkit's modules: their route, label,
 * description and per-category colour. Consumed by both the Sidebar (nav) and
 * the Dashboard (cards) so the colour assigned to each module stays
 * consistent across the app.
 *
 * `color` is the icon text colour; `tint` is the matching translucent
 * background used for icon chips and the active nav row.
 */
export interface ModuleMeta {
  path: string;
  label: string;
  description: string;
  icon: LucideIcon;
  color: string;
  tint: string;
}

export const dashboardItem: ModuleMeta = {
  path: "/",
  label: "Dashboard",
  description: "Overview and backend/system status",
  icon: LayoutDashboard,
  color: "text-zinc-400",
  tint: "bg-zinc-500/10",
};

export const modules: ModuleMeta[] = [
  {
    path: "/phishing",
    label: "Phishing Analyzer",
    description:
      "Analyze .eml files for phishing indicators, URL threats and malicious attachments",
    icon: Mail,
    color: "text-amber-400",
    tint: "bg-amber-500/10",
  },
  {
    path: "/logs",
    label: "Log Analyzer",
    description:
      "Detect brute force attacks, web exploits and suspicious Windows events",
    icon: FileText,
    color: "text-blue-400",
    tint: "bg-blue-500/10",
  },
  {
    path: "/ioc",
    label: "IOC Extractor",
    description:
      "Extract and enrich indicators of compromise from PDFs, emails and text",
    icon: Search,
    color: "text-violet-400",
    tint: "bg-violet-500/10",
  },
  {
    path: "/ioc-pivot",
    label: "IOC Pivot",
    description:
      "Drill a single indicator across CT logs, passive DNS, WHOIS, ASN and Shodan",
    icon: GitBranch,
    color: "text-cyan-400",
    tint: "bg-cyan-500/10",
  },
  {
    path: "/yara",
    label: "YARA Scanner",
    description:
      "Match uploaded files against a curated YARA rule set with MITRE mapping",
    icon: FileSearch,
    color: "text-red-400",
    tint: "bg-red-500/10",
  },
  {
    path: "/sigma",
    label: "Sigma Detection",
    description: "Evaluate JSON events against the bundled Sigma rule library",
    icon: Radar,
    color: "text-green-400",
    tint: "bg-green-500/10",
  },
  {
    path: "/misp",
    label: "MISP Enrichment",
    description:
      "Extract IOCs from text and flag which ones your MISP instance already knows",
    icon: Share2,
    color: "text-orange-400",
    tint: "bg-orange-500/10",
  },
  {
    path: "/file",
    label: "File Inspector",
    description:
      "Static check of a download or setup for trojans, polyglots and embedded payloads",
    icon: ScanSearch,
    color: "text-rose-400",
    tint: "bg-rose-500/10",
  },
  {
    path: "/qr",
    label: "QR Analyzer",
    description:
      "Decode a QR image and check the embedded link for quishing tricks",
    icon: QrCode,
    color: "text-indigo-400",
    tint: "bg-indigo-500/10",
  },
  {
    path: "/link",
    label: "Link Analyzer",
    description:
      "Unshorten a link, trace its redirects and check where it really lands",
    icon: Link2,
    color: "text-teal-400",
    tint: "bg-teal-500/10",
  },
];

export const newsItem: ModuleMeta = {
  path: "/news",
  label: "News",
  description: "Latest security news",
  icon: Newspaper,
  color: "text-sky-400",
  tint: "bg-sky-500/10",
};

/** Dashboard first, the tool modules, then News - the sidebar order. */
export const navItems: ModuleMeta[] = [dashboardItem, ...modules, newsItem];
