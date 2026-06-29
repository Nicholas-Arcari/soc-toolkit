import {
  lazy,
  Suspense,
  useEffect,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";
import {
  Search,
  AlertTriangle,
  Image as ImageIcon,
  Loader2,
  User,
  ExternalLink,
  Globe,
  Download,
} from "lucide-react";
import {
  exportReport,
  getInvestigationHistory,
  investigateBreaches,
  investigateFingerprint,
  investigateImage,
  investigatePerson,
  investigateUsername,
  type BreachSearchResponse,
  type EntityGraph,
  type FingerprintResponse,
  type InvestigationEntry,
  type ImageMetadataResponse,
  type PersonResponse,
  type UsernameSearchResponse,
} from "../api/client";
import { downloadBlob } from "../lib/download";
import CopyButton from "../components/common/CopyButton";

const personField =
  "bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500";

/**
 * Cytoscape ships ~600 KB minified; lazy-loading keeps the Investigate
 * page snappy on first paint and excludes the cost from Targets/Dashboard.
 */
const GraphView = lazy(() => import("../components/investigate/GraphView"));

type Mode = "username" | "email" | "image";

interface Results {
  username?: UsernameSearchResponse;
  breach?: BreachSearchResponse;
  image?: ImageMetadataResponse;
  person?: PersonResponse;
}

const PREFIX_RE = /^(username|email|image):\s*(.*)$/i;

/**
 * Parse the search-bar input. Defaulting to ``username:`` when no prefix
 * is typed keeps the common case fast - most searches will be
 * usernames. Email and image require explicit prefixes so a raw
 * email address isn't accidentally submitted to the username probe.
 */
function parseQuery(raw: string): { mode: Mode; value: string } | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const match = PREFIX_RE.exec(trimmed);
  if (match) {
    const mode = match[1].toLowerCase() as Mode;
    return { mode, value: match[2].trim() };
  }

  if (trimmed.includes("@")) return { mode: "email", value: trimmed };
  return { mode: "username", value: trimmed };
}

export default function Investigate() {
  const [query, setQuery] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [results, setResults] = useState<Results>({});
  const [activeGraph, setActiveGraph] = useState<EntityGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [person, setPerson] = useState({
    email: "",
    name: "",
    org: "",
    location: "",
    handle: "",
  });
  const [ack, setAck] = useState(false);
  const [personLoading, setPersonLoading] = useState(false);
  const [fp, setFp] = useState({ url: "", authorized: false });
  const [fpResult, setFpResult] = useState<FingerprintResponse | null>(null);
  const [fpLoading, setFpLoading] = useState(false);
  const [history, setHistory] = useState<InvestigationEntry[]>([]);

  async function loadHistory() {
    try {
      setHistory(await getInvestigationHistory());
    } catch {
      // history is best-effort
    }
  }

  useEffect(() => {
    void loadHistory();
  }, []);

  async function handlePersonSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!person.email.trim() && !person.name.trim()) {
      setError("Person search needs at least an email or a name.");
      return;
    }
    setError(null);
    setPersonLoading(true);
    try {
      const r = await investigatePerson(person);
      setResults((prev) => ({ ...prev, person: r }));
      setActiveGraph(r.graph);
      void loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPersonLoading(false);
    }
  }

  async function handleFingerprintSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!fp.url.trim()) return;
    setError(null);
    setFpLoading(true);
    try {
      setFpResult(await investigateFingerprint(fp.url.trim(), fp.authorized));
      void loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setFpLoading(false);
    }
  }

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);

    const parsed = parseQuery(query);
    if (!parsed && !file) {
      setError("Enter a username, email, or upload an image.");
      return;
    }

    setLoading(true);
    try {
      if (parsed?.mode === "username") {
        const r = await investigateUsername(parsed.value);
        setResults((prev) => ({ ...prev, username: r }));
        setActiveGraph(r.graph);
      } else if (parsed?.mode === "email") {
        const r = await investigateBreaches(parsed.value);
        setResults((prev) => ({ ...prev, breach: r }));
        setActiveGraph(r.graph);
      } else if (parsed?.mode === "image" || (file && !parsed)) {
        if (!file) {
          setError("image: prefix requires uploading a file too.");
          return;
        }
        const r = await investigateImage(file);
        setResults((prev) => ({ ...prev, image: r }));
        setActiveGraph(r.graph);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0] ?? null;
    setFile(selected);
    if (selected && !query.toLowerCase().startsWith("image:")) {
      setQuery(`image: ${selected.name}`);
    }
  }

  return (
    <div className="max-w-6xl space-y-6">
      <header>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Search className="w-8 h-8 text-primary-500" />
          Investigate
        </h1>
        <p className="text-muted mt-2">
          Pivot from a username, email, or image to a graph of connected entities.
          All sources are passive; platform hits indicate a URL collision, not
          confirmed identity.
        </p>
      </header>

      {history.length > 0 && (
        <section className="bg-dark-card border border-dark-border rounded-lg p-4">
          <h2 className="text-sm font-semibold mb-2">Recent investigations</h2>
          <ul className="divide-y divide-dark-border">
            {history.slice(0, 8).map((h) => (
              <li key={h.id} className="py-2 flex items-center gap-3 text-sm">
                <span className="text-xs px-2 py-0.5 rounded-full bg-primary-600/20 text-primary-400 capitalize shrink-0">
                  {h.kind}
                </span>
                <span className="font-mono text-foreground truncate flex-1">
                  {h.query}
                </span>
                <span className="text-xs text-muted shrink-0">{h.summary}</span>
                <span className="text-xs text-muted shrink-0">
                  {new Date(h.created_at).toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="username:alice · email:user@example.com · image: uploaded.jpg"
            className="flex-1 bg-dark-card border border-dark-border rounded-lg px-4 py-3 text-sm font-mono placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white rounded-lg font-medium flex items-center gap-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Search
          </button>
        </div>

        <div className="flex items-center gap-3 text-sm text-muted">
          <label className="flex items-center gap-2 cursor-pointer hover:text-muted">
            <ImageIcon className="w-4 h-4" />
            <span>{file ? file.name : "Upload image for EXIF/GPS"}</span>
            <input
              type="file"
              accept="image/*"
              onChange={handleFileChange}
              className="hidden"
            />
          </label>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-2">
            <AlertTriangle className="w-4 h-4" />
            {error}
          </div>
        )}
      </form>

      <form
        onSubmit={handlePersonSubmit}
        className="bg-dark-card border border-dark-border rounded-lg p-4 space-y-3"
      >
        <h2 className="font-semibold flex items-center gap-2">
          <User className="w-5 h-5 text-primary-500" />
          Person investigation
        </h2>
        <p className="text-xs text-muted">
          Combine an email and/or name with filters to narrow in on the right
          person. Public, free sources only.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <input
            className={personField}
            placeholder="Email"
            value={person.email}
            onChange={(e) => setPerson({ ...person, email: e.target.value })}
          />
          <input
            className={personField}
            placeholder="Name (first last)"
            value={person.name}
            onChange={(e) => setPerson({ ...person, name: e.target.value })}
          />
          <input
            className={personField}
            placeholder="Org / company (optional)"
            value={person.org}
            onChange={(e) => setPerson({ ...person, org: e.target.value })}
          />
          <input
            className={personField}
            placeholder="Location (optional)"
            value={person.location}
            onChange={(e) => setPerson({ ...person, location: e.target.value })}
          />
          <input
            className={personField}
            placeholder="Known handle (optional)"
            value={person.handle}
            onChange={(e) => setPerson({ ...person, handle: e.target.value })}
          />
        </div>
        <label className="flex items-start gap-2 text-xs text-muted">
          <input
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            I will use this lawfully - public information only, with a valid
            basis (GDPR Art. 6). Not for harassment or stalking.
          </span>
        </label>
        <button
          type="submit"
          disabled={personLoading || !ack}
          className="px-5 py-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium flex items-center gap-2"
        >
          {personLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Search className="w-4 h-4" />
          )}
          Investigate person
        </button>
      </form>

      <form
        onSubmit={handleFingerprintSubmit}
        className="bg-dark-card border border-dark-border rounded-lg p-4 space-y-3"
      >
        <h2 className="font-semibold flex items-center gap-2">
          <Globe className="w-5 h-5 text-primary-500" />
          Website fingerprint
        </h2>
        <p className="text-xs text-muted">
          Detect the software and versions a site runs (CMS, framework, server,
          JS). This is active recon - only with authorization.
        </p>
        <input
          className={personField}
          placeholder="https://example.com"
          value={fp.url}
          onChange={(e) => setFp({ ...fp, url: e.target.value })}
        />
        <label className="flex items-start gap-2 text-xs text-muted">
          <input
            type="checkbox"
            checked={fp.authorized}
            onChange={(e) => setFp({ ...fp, authorized: e.target.checked })}
            className="mt-0.5"
          />
          <span>
            I am authorized to assess this site. Unauthorized scanning may be
            unlawful (CFAA; Italy art. 615-ter c.p.).
          </span>
        </label>
        <button
          type="submit"
          disabled={fpLoading || !fp.authorized || !fp.url.trim()}
          className="px-5 py-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium flex items-center gap-2"
        >
          {fpLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Search className="w-4 h-4" />
          )}
          Fingerprint
        </button>
      </form>

      {activeGraph && (
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Entity graph</h2>
          <Suspense
            fallback={
              <div
                className="flex items-center justify-center text-sm text-muted bg-dark-card border border-dark-border rounded-lg"
                style={{ height: 480 }}
              >
                <Loader2 className="w-4 h-4 animate-spin mr-2" />
                Loading graph…
              </div>
            }
          >
            <GraphView graph={activeGraph} />
          </Suspense>
        </section>
      )}

      {fpResult && <FingerprintResults data={fpResult} />}
      {results.person && <PersonResults data={results.person} />}
      {results.username && <UsernameResults data={results.username} />}
      {results.breach && <BreachResults data={results.breach} />}
      {results.image && <ImageResults data={results.image} />}
    </div>
  );
}

function UsernameResults({ data }: { data: UsernameSearchResponse }) {
  const present = data.hits.filter((h) => h.status === "present");
  const inconclusive = data.hits.filter((h) => h.status === "inconclusive");

  return (
    <section className="bg-dark-card border border-dark-border rounded-lg p-4 space-y-4">
      <h3 className="font-semibold">
        {data.username} - {data.present_count}/{data.checked} platforms with a hit
      </h3>

      {present.length > 0 && (
        <div>
          <h4 className="text-sm text-muted mb-2">Present</h4>
          <ul className="space-y-1 text-sm">
            {present.map((h) => (
              <li key={h.platform} className="flex justify-between">
                <a href={h.url} target="_blank" rel="noreferrer" className="text-primary-400 hover:underline">
                  {h.platform}
                </a>
                <span className="text-muted">{h.category}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {inconclusive.length > 0 && (
        <div>
          <h4 className="text-sm text-muted mb-2">Inconclusive</h4>
          <ul className="space-y-1 text-sm text-muted">
            {inconclusive.map((h) => (
              <li key={h.platform}>
                {h.platform} - {h.note || `HTTP ${h.http_status}`}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function BreachResults({ data }: { data: BreachSearchResponse }) {
  if (!data.available) {
    return (
      <section className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 text-sm">
        <strong className="text-amber-400">HIBP unavailable.</strong>{" "}
        <span className="text-amber-400/80">{data.note}</span>
      </section>
    );
  }

  if (data.breaches.length === 0) {
    return (
      <section className="bg-dark-card border border-dark-border rounded-lg p-4 text-sm text-muted">
        No known breaches for <span className="text-foreground">{data.query}</span>.
      </section>
    );
  }

  return (
    <section className="bg-dark-card border border-dark-border rounded-lg p-4 space-y-3">
      <h3 className="font-semibold">Breaches for {data.query}</h3>
      <ul className="space-y-2">
        {data.breaches.map((b) => (
          <li key={b.name} className="border-t border-dark-border pt-2 first:border-t-0 first:pt-0">
            <div className="flex justify-between">
              <span className="font-medium">{b.title || b.name}</span>
              <span className="text-xs text-muted">{b.breach_date}</span>
            </div>
            <div className="text-xs text-muted mt-1">
              {b.pwn_count.toLocaleString()} affected · {b.data_classes.join(", ")}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}

function ExportButtons({
  data,
  reportType,
}: {
  data: unknown;
  reportType: string;
}) {
  const [exporting, setExporting] = useState<string | null>(null);

  async function run(format: "json" | "pdf") {
    setExporting(format);
    try {
      const blob = await exportReport(
        data as Record<string, unknown>,
        reportType,
        format,
      );
      downloadBlob(blob, `osint_${reportType}.${format}`);
    } catch {
      // best-effort export; a failed download shouldn't break the page
    } finally {
      setExporting(null);
    }
  }

  return (
    <div className="flex gap-2 shrink-0">
      {(["json", "pdf"] as const).map((f) => (
        <button
          key={f}
          type="button"
          onClick={() => run(f)}
          disabled={exporting !== null}
          className="inline-flex items-center gap-1.5 rounded-lg border border-dark-border text-muted hover:text-foreground disabled:opacity-50 disabled:cursor-not-allowed text-xs font-medium px-3 py-1.5"
        >
          <Download className="w-3.5 h-3.5" />
          {exporting === f ? "…" : f.toUpperCase()}
        </button>
      ))}
    </div>
  );
}


function FingerprintResults({ data }: { data: FingerprintResponse }) {
  if (data.error) {
    return (
      <section className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 text-sm text-amber-400/90">
        {data.error}
      </section>
    );
  }
  return (
    <section className="bg-dark-card border border-dark-border rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <h3 className="font-semibold flex items-center gap-2">
          <Globe className="w-4 h-4 text-primary-500" />
          {data.final_url} · HTTP {data.status}
        </h3>
        <ExportButtons data={data} reportType="fingerprint" />
      </div>
      {data.technologies.length === 0 ? (
        <p className="text-sm text-muted">No technologies fingerprinted.</p>
      ) : (
        <ul className="space-y-1.5 text-sm">
          {data.technologies.map((t) => (
            <li
              key={`${t.name}-${t.evidence}`}
              className="flex items-center justify-between gap-3"
            >
              <span>
                <span className="text-foreground font-medium">{t.name}</span>
                {t.version && (
                  <span className="text-primary-400"> {t.version}</span>
                )}
                <span className="text-muted text-xs"> · {t.category}</span>
              </span>
              <span className="text-xs text-muted">{t.evidence}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function PersonResults({ data }: { data: PersonResponse }) {
  const accounts =
    data.username_result?.hits.filter((h) => h.status === "present") ?? [];
  return (
    <section className="bg-dark-card border border-dark-border rounded-lg p-4 space-y-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="font-semibold flex items-center gap-2">
            <User className="w-4 h-4 text-primary-500" />
            {data.email || data.name}
          </h3>
          <p className="text-xs text-muted mt-1">{data.note}</p>
        </div>
        <ExportButtons data={data} reportType="person" />
      </div>

      {data.gravatar?.found && (
        <div className="flex items-center gap-3">
          <img
            src={`${data.gravatar.avatar_url}?s=64&d=mp`}
            alt=""
            className="w-12 h-12 rounded-full bg-dark-bg"
          />
          <div className="text-sm">
            <p className="text-foreground">
              {data.gravatar.display_name || "Gravatar profile"}
            </p>
            <a
              href={data.gravatar.profile_url}
              target="_blank"
              rel="noreferrer"
              className="text-primary-400 hover:underline text-xs inline-flex items-center gap-1"
            >
              View profile <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      )}

      {data.email_hygiene && (
        <div className="text-sm text-muted">
          <span className="text-muted">Email:</span>{" "}
          {data.email_hygiene.domain} · MX{" "}
          {data.email_hygiene.has_mx ? "yes" : "no"}
          {data.email_hygiene.disposable && (
            <span className="text-amber-400"> · disposable</span>
          )}
          {data.email_hygiene.role_account && (
            <span className="text-amber-400"> · role account</span>
          )}
        </div>
      )}

      {accounts.length > 0 && (
        <div>
          <h4 className="text-sm text-muted mb-2">
            Accounts found ({data.username_result?.username})
          </h4>
          <ul className="space-y-1 text-sm">
            {accounts.map((h) => (
              <li key={h.platform} className="flex justify-between">
                <a
                  href={h.url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-primary-400 hover:underline"
                >
                  {h.platform}
                </a>
                <span className="text-muted">{h.category}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {data.breaches?.available && data.breaches.breaches.length > 0 && (
        <div>
          <h4 className="text-sm text-muted mb-2">Breaches</h4>
          <ul className="space-y-1 text-sm">
            {data.breaches.breaches.map((b) => (
              <li key={b.name} className="flex justify-between">
                <span>{b.title || b.name}</span>
                <span className="text-xs text-muted">{b.breach_date}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {data.username_candidates.length > 0 && (
        <div>
          <h4 className="text-sm text-muted mb-2">Handle candidates</h4>
          <div className="flex flex-wrap gap-1.5">
            {data.username_candidates.map((c) => (
              <span
                key={c}
                className="px-2 py-0.5 rounded bg-dark-bg border border-dark-border text-xs font-mono text-muted"
              >
                {c}
              </span>
            ))}
          </div>
        </div>
      )}

      {data.dorks.length > 0 && (
        <div>
          <h4 className="text-sm text-muted mb-2">
            Search links (you click these)
          </h4>
          <div className="flex flex-wrap gap-2">
            {data.dorks.map((d) => (
              <span
                key={d.label}
                className="inline-flex items-center gap-1 rounded-lg bg-dark-bg border border-dark-border pr-1.5"
              >
                <a
                  href={d.url}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1 text-xs text-primary-400 hover:underline inline-flex items-center gap-1"
                >
                  {d.label} <ExternalLink className="w-3 h-3" />
                </a>
                <CopyButton value={d.url} label="Copy search link" />
              </span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function ImageResults({ data }: { data: ImageMetadataResponse }) {
  const exifEntries = Object.entries(data.exif);

  return (
    <section className="bg-dark-card border border-dark-border rounded-lg p-4 space-y-3">
      <h3 className="font-semibold">
        {data.filename} · {data.format} · {data.size_px[0]}×{data.size_px[1]}
      </h3>

      {data.gps && (
        <div className="text-sm">
          <span className="text-muted">GPS:</span>{" "}
          <a
            href={`https://www.openstreetmap.org/?mlat=${data.gps.latitude}&mlon=${data.gps.longitude}#map=14/${data.gps.latitude}/${data.gps.longitude}`}
            target="_blank"
            rel="noreferrer"
            className="text-primary-400 hover:underline font-mono"
          >
            {data.gps.latitude.toFixed(5)}, {data.gps.longitude.toFixed(5)}
          </a>
          {data.gps.altitude !== null && data.gps.altitude !== undefined && (
            <span className="text-muted"> @ {data.gps.altitude.toFixed(0)} m</span>
          )}
        </div>
      )}

      {exifEntries.length > 0 ? (
        <dl className="text-sm grid grid-cols-2 gap-x-4 gap-y-1">
          {exifEntries.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted font-mono">{k}</dt>
              <dd className="text-foreground">{v}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-sm text-muted">{data.note || "No EXIF metadata present."}</p>
      )}
    </section>
  );
}
