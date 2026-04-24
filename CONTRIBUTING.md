# Contributing

Thanks for considering a contribution. This repository is a Poetry + npm
monorepo with three workspaces:

| Workspace | Purpose | Python entry |
|-----------|---------|--------------|
| `packages/sec-common` | Shared library (HTTP clients, cache, IOC parsing) | library - no app |
| `packages/soc-toolkit` | Blue-team SOC analyst app | `backend/api/app.py` |
| `packages/osint-toolkit` | ASM + investigative OSINT app | `backend/api/app.py` |

## Before you start

- Read [ETHICS.md](ETHICS.md) before contributing. Active-scanning features,
  new integrations that send traffic to targets, or anything that broadens
  the attack surface must respect the passive-by-default posture. Changes
  that make it easier to operate outside a defined scope will be rejected.
- This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
  participating you agree to uphold it.
- For behavior changes, open an issue first. This avoids wasted work on
  PRs that conflict with roadmap direction.

## Getting set up

```bash
git clone https://github.com/YOUR_USERNAME/soc-toolkit.git
cd soc-toolkit
cp .env.example .env   # fill in only the keys you need; all are optional
```

Per-workspace setup (pick the ones you'll touch):

```bash
# sec-common
cd packages/sec-common/python && poetry install
cd ../..

# soc-toolkit
cd packages/soc-toolkit/backend && poetry install
cd ../frontend && npm install
cd ../../..

# osint-toolkit
cd packages/osint-toolkit/backend && poetry install && poetry run alembic upgrade head
cd ../frontend && npm install
cd ../../..
```

## Development loop

Each workspace has identical quality gates. From inside the relevant
`backend/` directory:

```bash
poetry run ruff check .
poetry run mypy .
poetry run pytest -q
```

Frontend (from `frontend/`):

```bash
npx tsc --noEmit
npm run build
```

Run all three workspaces' backend suites before opening a PR. The CI
matrix runs the same gates - if one fails locally, it'll fail there too.

## Code standards

- **Python**: Ruff rules `E, F, I, N, W, UP`. Line length 100. Strict
  mypy on everything under `packages/`. Type-annotate new public
  functions; `-> None` is not optional.
- **TypeScript**: strict mode. No `any`. Prefer `type` imports where the
  symbol is type-only.
- **Commits**: conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, `chore:`). One logical change per commit; rebase before PR if
  commits get messy.
- **Comments**: explain *why* (non-obvious invariants, workarounds for
  specific upstream bugs, intent that isn't in the code). Do not
  describe *what* - the code already does that.

## Writing tests

- `sec-common`: mock HTTP with `respx`. Target ≥70% coverage.
- `soc-toolkit`: pytest + `pytest-asyncio`. Gate: 30% (rising over time).
- `osint-toolkit`: pytest + `pytest-asyncio`. Gate: 50%. The
  `conftest.py` autouse fixture resets the sec-common cache between
  tests, so cache-dependent tests don't bleed into each other.

Integration-style tests that depend on external services (crt.sh,
Shodan, HIBP) must mock the network - CI runs without keys and these
tests must stay green.

## Adding a new integration

Integrations live in `packages/sec-common/python/sec_common/integrations/`
(unless they are tenant-specific, like MISP, which stays inside
`soc-toolkit/backend/integrations/`).

1. Create `<service>_client.py` extending `BaseAPIClient`.
2. Set `RATE_LIMIT` to the documented free-tier ceiling (when in doubt,
   start low - upstream rate-limit pages are often stale).
3. Handle the no-API-key path: return a degraded response (empty list,
   `{"error": "...not configured"}`, etc.), never raise. A toolkit
   install without keys must stay functional.
4. Register in `sec_common/integrations/__init__.py`.
5. Add the key to `config/base.py` and to `.env.example` with a link to
   the provider's key page and a one-line note on free-tier limits.
6. Write tests with `respx` - mock every endpoint you call.

## Adding a new OSINT scan kind

Follow the pattern in `packages/osint-toolkit/backend/core/asm/`:

1. Build a module with an async orchestrator that takes a `Target` and
   returns a dataclass result. Core must stay framework-free (no
   FastAPI imports).
2. Add `summarize(result)` that returns a JSON-safe dict - the API layer
   writes it into `Scan.summary` unchanged.
3. Register a POST endpoint in `api/routes/scans.py` using the
   `_run_scan` helper so status bookkeeping stays consistent.
4. Surface a `ScanCard` in `frontend/src/pages/TargetDetail.tsx`'s
   Discovery tab with a `renderResult` tailored to the summary shape.
5. Write tests under `tests/test_<kind>.py` - mock external clients at
   their boundaries, not inside the orchestrator.

## Regenerating README screenshots

UI changes that alter a verdict card, a sidebar icon, the dashboard
layout, or anything else visible in `docs/screenshots/*.png` must ship
refreshed screenshots in the same PR - reviewers shouldn't have to
imagine what the new UI looks like.

The workflow is scripted: a seed script populates both toolkits with
a known demo state, and
[`docs/regenerating-screenshots.md`](docs/regenerating-screenshots.md)
documents the naming and capture conventions.

```bash
docker compose --profile all up -d --build
./scripts/seed-demo.sh
# capture per docs/regenerating-screenshots.md, commit under `docs:`
```

## Pull request checklist

- [ ] Lint + type-check + tests pass in every workspace you touched
- [ ] New behavior has test coverage
- [ ] `.env.example` updated if you added a config key
- [ ] Workspace README updated if you changed observable behavior
- [ ] Screenshots regenerated if the PR changes UI that's shown in
      `docs/screenshots/`
- [ ] For `osint-toolkit`: passive-by-default preserved; any new active
      path is gated behind `OSINT_ENABLE_ACTIVE_SCANNING` or equivalent

## License

By contributing, you agree that your contributions are licensed under
the MIT License (see [LICENSE](LICENSE)).
