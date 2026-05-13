# Regenerating README screenshots

The README screenshots under `docs/screenshots/` drive a contributor's
first impression of the project. They must be reproducible - if a UI
refactor lands that changes a verdict card or a sidebar icon, the
screenshots should be re-shot from a known demo state rather than from
whatever ad-hoc data the contributor happens to have locally.

## Workflow

1. **Boot the full stack.**
   ```bash
   cp .env.example .env
   docker compose --profile all up -d --build
   ```

2. **Seed demo data.** The seed script analyses the bundled SOC samples
   and registers an authorized `demo-example-com` target in OSINT, then
   runs a passive subdomain enumeration against it.
   ```bash
   ./scripts/seed-demo.sh
   ```
   Re-running is safe - the OSINT target is only created on first run.

3. **Capture.** Follow the naming convention already in the tree:
   - `docs/screenshots/01-dashboard.png` - SOC dashboard with module cards
   - `docs/screenshots/02-phishing-result.png` - verdict panel after seed
   - `docs/screenshots/03-logs-result.png` - alert table after seed
   - `docs/screenshots/04-ioc-result.png` - extracted IOC table
   - `docs/screenshots/05-swagger.png` - `/api/docs` root
   - `docs/screenshots/osint-01-dashboard.png` - OSINT landing page
   - `docs/screenshots/osint-02-target-detail.png` - demo target's
     Discovery tab post-seed
   - `docs/screenshots/osint-03-investigate.png` - Investigate view with
     a username probe result + entity graph

   The three OSINT shots are scripted - after the seed is staged, run:
   ```bash
   node e2e/scripts/capture-osint-screenshots.mjs
   ```
   The SOC shots are still captured by hand (verdict panels depend on
   scroll position and which tab the analyst opened).

   Window size: **1440x900** with the browser's devtools closed. Dark
   mode is the design default - stay in it unless capturing a
   light-mode screenshot deliberately. Crop the captured PNG to the
   browser viewport only; no OS chrome.

4. **Optimize.** Run through `pngquant --quality 80 --ext .png --force`
   (or your preferred lossless/near-lossless optimizer) before
   committing - the existing screenshots are ~150-260 kB and new ones
   should stay in that range.

5. **Commit under `docs:`.**
   ```
   docs: refresh SOC phishing screenshot after verdict UI redesign
   ```

## Don't

- **Don't include real telemetry.** The seed uses `example.com` for
  OSINT and the bundled `samples/` fixtures for SOC - nothing else
  should appear in screenshots. Redact anything that slips through.
- **Don't screenshot behind login.** Auth is opt-in (set `AUTH_SECRET`
  in `.env`). Keep it unset for the canonical screenshots so the
  README-to-running-app mapping stays one hop.
- **Don't resize in the browser.** Use a clean 1440x900 viewport; a
  zoomed-in screenshot degrades on high-DPI displays.
