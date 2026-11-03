"""Container entry point: `python -m pg_re_worker`.

stdin  : one JSON line {"filename": ..., "passwords": [...]} followed by the raw file bytes
stdout : one JSON report
The container runs with no network, a read-only root filesystem, no capabilities, and as an unprivileged user.
Nothing from the sample is ever executed or written to disk."""
from __future__ import annotations

import json
import sys

from . import __version__
from .analyze import analyze_bytes
from .core import Budget

MAX_INPUT = 64 << 20


def _limit_resources() -> None:
    try:
        import resource  # POSIX only (the container is Linux)

        resource.setrlimit(resource.RLIMIT_CPU, (75, 80))
        resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))  # cannot write files at all
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    except Exception:
        pass


def main() -> int:
    _limit_resources()
    raw = sys.stdin.buffer.read(MAX_INPUT + 4096)
    head, _, body = raw.partition(b"\n")
    try:
        meta = json.loads(head.decode("utf-8"))
        filename = str(meta.get("filename") or "sample")
        passwords = [str(p)[:64] for p in (meta.get("passwords") or [])][:8]
    except Exception:
        sys.stdout.write(json.dumps({"errors": ["bad request header"], "behaviors": []}))
        return 2
    rep = analyze_bytes(filename, body[:MAX_INPUT], passwords, 0, Budget())
    rep["engine"] = f"pg_re_worker/{__version__} (static)"
    sys.stdout.write(json.dumps(rep, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
