# End-to-end browser smoke tests

Playwright-driven smoke tests that hit the **running compose stack** on
`http://localhost:3000` (SOC) and `http://localhost:3001` (OSINT). The
tests stay minimal on purpose - one or two golden-path flows per
toolkit. They catch regressions the Python / Vitest suites miss:
nginx upstream wiring, frontend-backend contract drift, SPA routing,
and the form-submission paths that only exist in the browser.

## Run locally

```bash
# one-time browser install
cd e2e && npm install && npm run install-browsers

# start the stack in another terminal
docker compose -f docker-compose.yml --profile all up -d --build

# run the tests
cd e2e && npm test
```

Use `npm run test:ui` for the Playwright UI runner - handy for
iterating on a failing test without a full re-run.

## CI

The `e2e-smoke` job in `.github/workflows/ci.yml` runs on every PR that
touches either frontend, either backend, or `sec-common`. It boots the
`--profile all` stack, waits for both `/api/health` probes, and then
runs the two projects in parallel.

If a run fails, the job uploads the HTML report as a workflow artifact
(`playwright-report`) - download it from the run page for a
time-traveling trace of what the browser saw.
