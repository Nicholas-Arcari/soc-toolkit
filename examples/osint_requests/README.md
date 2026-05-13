# OSINT toolkit: curl cheat-sheet

Every request assumes the API is reachable at `http://localhost:8001`.
Spin it up with:

```bash
docker compose --profile osint up --build
```

---

## 1. Register an authorized target

`authorized_to_scan` MUST be `true` - the backend rejects the creation
otherwise. Set your own scope domains; never scan something you don't own
or don't have written authorization for.

```bash
curl -s -X POST http://localhost:8001/api/targets \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Example Corp",
    "owner_email": "you@example.com",
    "scope_domains": ["example.com"],
    "authorized_to_scan": true
  }' | jq
```

Save the returned `id` - every scan is scoped to it.

## 2. Run passive subdomain enumeration

```bash
TARGET_ID=1
curl -s -X POST "http://localhost:8001/api/scans/targets/${TARGET_ID}/subdomain-enum" | jq
```

Sources: crt.sh (always on) + SecurityTrails (if key present).
Scope-filtered - neighbor domains are dropped before persist.

## 3. Map DNS + email-auth posture

```bash
curl -s -X POST "http://localhost:8001/api/scans/targets/${TARGET_ID}/dns-mapping" | jq
```

Checks A / AAAA / MX / NS / TXT on every scope root, parses SPF and
DMARC. Missing / permissive policies surface in `/findings`.

## 4. Service discovery (Shodan per resolved IP)

```bash
curl -s -X POST "http://localhost:8001/api/scans/targets/${TARGET_ID}/service-discovery" | jq
```

Degrades cleanly without `SHODAN_API_KEY`. CVEs on each host become
high-severity findings.

## 5. List everything the target has accumulated

```bash
curl -s "http://localhost:8001/api/scans/targets/${TARGET_ID}/subdomains" | jq
curl -s "http://localhost:8001/api/scans/targets/${TARGET_ID}/services" | jq
curl -s "http://localhost:8001/api/scans/targets/${TARGET_ID}/findings" | jq
```

## 6. Investigate workflows (no target needed)

Username across 12 platforms:

```bash
curl -s -X POST http://localhost:8001/api/investigate/username \
  -H 'Content-Type: application/json' \
  -d '{"username": "johndoe"}' | jq
```

Breach lookup (requires `HIBP_API_KEY` - degrades to empty list otherwise):

```bash
curl -s -X POST http://localhost:8001/api/investigate/breaches \
  -H 'Content-Type: application/json' \
  -d '{"account": "test@example.com"}' | jq
```

EXIF extraction (multipart):

```bash
curl -s -X POST http://localhost:8001/api/investigate/image \
  -F "image=@/path/to/photo.jpg" | jq
```

## Cleanup

```bash
curl -s -X DELETE "http://localhost:8001/api/targets/${TARGET_ID}"
```

Cascades into scans / subdomains / services / findings.
