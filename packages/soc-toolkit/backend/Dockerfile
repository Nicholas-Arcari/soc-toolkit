FROM python:3.12-slim

# Mirror the host layout inside the container so the `../../sec-common/python`
# path dependency in pyproject.toml resolves without patching the manifest.
# Build context must be the monorepo root (see docker-compose.yml).

# Install system dependencies for WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.8.4

# Copy sec-common first - infrequent changes, better layer cache.
COPY packages/sec-common/python/ /app/packages/sec-common/python/
COPY packages/soc-toolkit/backend/ /app/packages/soc-toolkit/backend/

WORKDIR /app/packages/soc-toolkit/backend

# Install dependencies (no dev deps in production)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main

# Drop privileges: create an unprivileged user, pre-create the data
# directory where SQLite caches land and hand ownership of /app to it
# before switching USER. Existing named volumes created under the old
# root-owned layout need `docker compose down -v` to inherit this.
RUN groupadd --system --gid 1000 app \
    && useradd --system --uid 1000 --gid app --create-home app \
    && mkdir -p /app/packages/soc-toolkit/backend/data \
    && chown -R app:app /app
USER app

EXPOSE 8000

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
