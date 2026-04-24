import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Mail, FileText, Search, CheckCircle, XCircle } from "lucide-react";
import { healthCheck, type HealthCheck } from "../api/client";

export default function Dashboard() {
  const [health, setHealth] = useState<HealthCheck | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    healthCheck()
      .then(setHealth)
      .catch(() => setError(true));
  }, []);

  const modules = [
    {
      title: "Phishing Analyzer",
      description: "Analyze email files for phishing indicators, URL threats, and malicious attachments",
      icon: Mail,
      path: "/phishing",
      color: "text-red-400",
      bg: "bg-red-500/10",
    },
    {
      title: "Log Analyzer",
      description: "Detect brute force attacks, web exploits, and suspicious Windows events",
      icon: FileText,
      path: "/logs",
      color: "text-yellow-400",
      bg: "bg-yellow-500/10",
    },
    {
      title: "IOC Extractor",
      description: "Extract and enrich indicators of compromise from PDFs, emails, and text",
      icon: Search,
      path: "/ioc",
      color: "text-blue-400",
      bg: "bg-blue-500/10",
    },
  ];

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-gray-400 mt-2">SOC Toolkit - Security Operations Center</p>
      </div>

      {/* Health Status */}
      <div className="bg-dark-card rounded-xl border border-dark-border p-6 mb-8">
        <h2 className="text-lg font-semibold mb-4">System Status</h2>
        {error ? (
          <div className="flex items-center gap-2 text-red-400">
            <XCircle className="w-5 h-5" />
            <span>Backend unreachable - start the server with `uvicorn api.app:app`</span>
          </div>
        ) : health ? (
          <div>
            <div className="flex items-center gap-2 text-green-400 mb-4">
              <CheckCircle className="w-5 h-5" />
              <span>Backend online (v{health.version})</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {["virustotal", "abuseipdb", "shodan", "urlscan", "otx"].map((api) => (
                <span
                  key={api}
                  className={`px-3 py-1 rounded-full text-xs font-medium ${
                    health.configured_apis.includes(api)
                      ? "bg-green-900/30 text-green-400 border border-green-700"
                      : "bg-gray-800 text-gray-500 border border-gray-700"
                  }`}
                >
                  {api}
                </span>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-gray-500">Checking...</p>
        )}
      </div>

      {/* Module Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {modules.map(({ title, description, icon: Icon, path, color, bg }) => (
          <Link
            key={path}
            to={path}
            className="bg-dark-card rounded-xl border border-dark-border p-6 hover:border-primary-500/50 transition-colors group"
          >
            <div className={`w-12 h-12 rounded-lg ${bg} flex items-center justify-center mb-4`}>
              <Icon className={`w-6 h-6 ${color}`} />
            </div>
            <h3 className="text-lg font-semibold group-hover:text-primary-400 transition-colors">
              {title}
            </h3>
            <p className="text-sm text-gray-400 mt-2">{description}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
