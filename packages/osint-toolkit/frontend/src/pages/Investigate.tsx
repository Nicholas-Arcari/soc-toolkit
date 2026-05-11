import { lazy, Suspense, useState, type ChangeEvent, type FormEvent } from "react";
import { Search, AlertTriangle, Image as ImageIcon, Loader2 } from "lucide-react";
import {
  investigateBreaches,
  investigateImage,
  investigateUsername,
  type BreachSearchResponse,
  type EntityGraph,
  type ImageMetadataResponse,
  type UsernameSearchResponse,
} from "../api/client";

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
        <p className="text-gray-400 mt-2">
          Pivot from a username, email, or image to a graph of connected entities.
          All sources are passive; platform hits indicate a URL collision, not
          confirmed identity.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="username:alice · email:user@example.com · image: uploaded.jpg"
            className="flex-1 bg-dark-card border border-dark-border rounded-lg px-4 py-3 text-sm font-mono placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 bg-primary-600 hover:bg-primary-500 disabled:bg-gray-700 text-white rounded-lg font-medium flex items-center gap-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Search
          </button>
        </div>

        <div className="flex items-center gap-3 text-sm text-gray-500">
          <label className="flex items-center gap-2 cursor-pointer hover:text-gray-300">
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
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-950/40 border border-red-900/40 rounded-lg px-4 py-2">
            <AlertTriangle className="w-4 h-4" />
            {error}
          </div>
        )}
      </form>

      {activeGraph && (
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Entity graph</h2>
          <Suspense
            fallback={
              <div
                className="flex items-center justify-center text-sm text-gray-500 bg-dark-card border border-dark-border rounded-lg"
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
          <h4 className="text-sm text-gray-400 mb-2">Present</h4>
          <ul className="space-y-1 text-sm">
            {present.map((h) => (
              <li key={h.platform} className="flex justify-between">
                <a href={h.url} target="_blank" rel="noreferrer" className="text-primary-400 hover:underline">
                  {h.platform}
                </a>
                <span className="text-gray-500">{h.category}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {inconclusive.length > 0 && (
        <div>
          <h4 className="text-sm text-gray-400 mb-2">Inconclusive</h4>
          <ul className="space-y-1 text-sm text-gray-500">
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
      <section className="bg-amber-950/40 border border-amber-900/40 rounded-lg p-4 text-sm">
        <strong className="text-amber-300">HIBP unavailable.</strong>{" "}
        <span className="text-amber-200/80">{data.note}</span>
      </section>
    );
  }

  if (data.breaches.length === 0) {
    return (
      <section className="bg-dark-card border border-dark-border rounded-lg p-4 text-sm text-gray-400">
        No known breaches for <span className="text-white">{data.query}</span>.
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
              <span className="text-xs text-gray-500">{b.breach_date}</span>
            </div>
            <div className="text-xs text-gray-400 mt-1">
              {b.pwn_count.toLocaleString()} affected · {b.data_classes.join(", ")}
            </div>
          </li>
        ))}
      </ul>
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
          <span className="text-gray-400">GPS:</span>{" "}
          <a
            href={`https://www.openstreetmap.org/?mlat=${data.gps.latitude}&mlon=${data.gps.longitude}#map=14/${data.gps.latitude}/${data.gps.longitude}`}
            target="_blank"
            rel="noreferrer"
            className="text-primary-400 hover:underline font-mono"
          >
            {data.gps.latitude.toFixed(5)}, {data.gps.longitude.toFixed(5)}
          </a>
          {data.gps.altitude !== null && data.gps.altitude !== undefined && (
            <span className="text-gray-500"> @ {data.gps.altitude.toFixed(0)} m</span>
          )}
        </div>
      )}

      {exifEntries.length > 0 ? (
        <dl className="text-sm grid grid-cols-2 gap-x-4 gap-y-1">
          {exifEntries.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-gray-500 font-mono">{k}</dt>
              <dd className="text-gray-200">{v}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-sm text-gray-500">{data.note || "No EXIF metadata present."}</p>
      )}
    </section>
  );
}
