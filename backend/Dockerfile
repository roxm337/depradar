# Same uv release as CI, so images install exactly what uv.lock records.
FROM ghcr.io/astral-sh/uv:0.13.1 AS uv

FROM python:3.12-slim AS app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv sync --locked --no-dev --no-install-project --no-cache
COPY src ./src
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv sync --locked --no-dev --no-editable --no-cache \
    && useradd --uid 10001 --create-home depradar \
    && mkdir -p /data/inventories /data/backups && chown -R depradar:depradar /data
COPY alembic.ini ./
COPY migrations ./migrations
USER 10001:10001
CMD ["uvicorn", "depradar.interfaces.http.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]

FROM python:3.12-slim AS scanner-download
ARG TARGETARCH
RUN python - "$TARGETARCH" <<'PY'
import hashlib
import pathlib
import sys
import urllib.request
checksums = {
    'amd64': '160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b',
    'arm64': '4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7',
}
arch = sys.argv[1]
if arch not in checksums:
    raise SystemExit('Unsupported scanner architecture')
url = f'https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_{arch}'
data = urllib.request.urlopen(url, timeout=120).read()
if hashlib.sha256(data).hexdigest() != checksums[arch]:
    raise SystemExit('Scanner checksum mismatch')
pathlib.Path('/osv-scanner').write_bytes(data)
PY

FROM app AS scanner
COPY --from=scanner-download --chmod=0555 /osv-scanner /usr/local/bin/osv-scanner
CMD ["uvicorn", "depradar.interfaces.scanner_service:app", "--host", "0.0.0.0", "--port", "8001", "--no-proxy-headers"]

FROM app AS tests
USER root
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv sync --locked --no-editable --no-cache
COPY tests ./tests
COPY examples ./examples
USER 10001:10001
CMD ["pytest", "-q", "-o", "cache_dir=/tmp/pytest-cache"]
