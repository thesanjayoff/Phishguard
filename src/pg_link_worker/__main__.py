"""Container entry point: `python -m pg_link_worker expand|browse`.

stdin : one JSON object  (expand: {"urls": [...], "max_hops": 8}   browse: {"url": ..., "timeout_s": 45, "screenshot": true})
stdout: one JSON object. Nothing else is ever printed there."""
from __future__ import annotations

import json
import os
import signal
import sys

MAX_INPUT = 64 * 1024


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=True))
    sys.stdout.flush()


def _deadline(seconds: int, mode: str) -> None:
    """Last line of defence: if the browser hangs, report that and exit instead of living forever."""
    if not hasattr(signal, "SIGALRM"):
        return

    def fire(_sig, _frm):
        _emit({"error": "worker deadline reached", "forms": [], "redirects": [], "results": {}} if mode else {})
        os._exit(0)

    signal.signal(signal.SIGALRM, fire)
    signal.alarm(max(10, seconds))


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else ""
    if mode not in ("expand", "browse"):
        sys.stderr.write("usage: python -m pg_link_worker expand|browse  (JSON on stdin)\n")
        return 2
    try:
        req = json.loads(sys.stdin.buffer.read(MAX_INPUT).decode("utf-8"))
        if not isinstance(req, dict):
            raise ValueError("request must be an object")
    except Exception:
        _emit({"error": "bad request"})
        return 2
    if mode == "expand":
        from .expand import expand_many

        urls = [u for u in (req.get("urls") or []) if isinstance(u, str)][:20]
        _deadline(55, mode)
        _emit(expand_many(urls, max_hops=int(req.get("max_hops") or 8)))
        return 0
    url = req.get("url")
    if not isinstance(url, str):
        _emit({"error": "missing url"})
        return 2
    timeout_s = min(max(int(req.get("timeout_s") or 40), 10), 90)
    _deadline(timeout_s + 12, mode)
    from .browse import browse

    _emit(browse(url, timeout_s=timeout_s, screenshot=bool(req.get("screenshot", True))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
