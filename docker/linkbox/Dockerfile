# Link sandbox image: headless Chromium with an empty profile, driven by pg_link_worker.
# The app runs it with a read-only root, all capabilities dropped, no-new-privileges, memory/PID/CPU limits,
# an unprivileged user and tmpfs scratch space. Inside, Chromium is forced through a filtering proxy that
# refuses loopback/LAN/metadata addresses (see src/pg_link_worker/proxy.py).
#
# Build (from the repository root):  docker build -f docker/linkbox/Dockerfile -t phishguard-linkbox:latest .
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers \
    HOME=/tmp

# Playwright installs Chromium plus the system libraries it needs (this step needs root, at build time only).
RUN pip install playwright==1.64.1 \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX /opt/pw-browsers

WORKDIR /app
COPY src/pg_link_worker /app/pg_link_worker
RUN chmod -R a+rX,a-w /app && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin worker
USER 65532:65532

# Modes: `expand` (redirect headers only) and `browse` (full headless visit). JSON in on stdin, JSON out on stdout.
ENTRYPOINT ["python", "-m", "pg_link_worker"]
