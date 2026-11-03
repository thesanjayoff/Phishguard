# Attachment analysis image: static analysis only. It is never given network access (the app runs it with
# --network none, a read-only root, all capabilities dropped, no-new-privileges, memory/PID/CPU limits,
# an unprivileged user, and tmpfs scratch space). The sample arrives on stdin and is never written to disk.
#
# Build (from the repository root):  docker build -f docker/rebox/Dockerfile -t phishguard-rebox:latest .
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

# Pinned analysis libraries (versions the unit tests were run against).
RUN pip install \
      oletools==0.60.2 \
      pefile==2024.8.26 \
      capstone==5.0.9 \
      olefile==0.47 \
      msoffcrypto-tool==6.0.0 \
    && pip uninstall -y pip setuptools wheel 2>/dev/null || true

WORKDIR /app
COPY src/pg_re_worker /app/pg_re_worker

# Nothing in the image is writable by the runtime user.
RUN chmod -R a-w /app && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin worker
USER 65532:65532

# The host adapter runs:  docker run ... phishguard-rebox:latest python -m pg_re_worker
# A custom tool (attachments.adapter = "command") is run the same way: build your own image FROM this one,
# add the tool, and point sandbox.re_image at it.
CMD ["python", "-m", "pg_re_worker"]
