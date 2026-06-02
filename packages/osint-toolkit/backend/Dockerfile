FROM python:3.14-slim

# Mirror the host layout inside the container so the `../../sec-common/python`
# path dependency in pyproject.toml resolves without patching the manifest.
# Build context must be the monorepo root (see docker-compose.yml).

RUN pip install --no-cache-dir poetry==2.3.4

# Copy sec-common first - infrequent changes, better layer cache.
COPY packages/sec-common/python/ /app/packages/sec-common/python/
COPY packages/osint-toolkit/backend/ /app/packages/osint-toolkit/backend/

WORKDIR /app/packages/osint-toolkit/backend

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main

# Drop privileges: alembic + uvicorn run as an unprivileged user, the
# data dir (where the SQLite state DB lives) is pre-owned so the volume
# mount inherits correct perms on first create.
RUN groupadd --system --gid 1000 app \
    && useradd --system --uid 1000 --gid app --create-home app \
    && mkdir -p /app/packages/osint-toolkit/backend/data \
    && chown -R app:app /app
USER app

EXPOSE 8001

# Run migrations before uvicorn binds - idempotent `upgrade head`. `exec`
# makes uvicorn PID 1 so SIGTERM from `docker compose stop` reaches it.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn api.app:app --host 0.0.0.0 --port 8001"]
