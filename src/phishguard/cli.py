"""Command line: `phishguard check <file.eml | url | text>` and friends."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from .config import Config, load_config
from .models import Verdict
from .parsing.email_parser import from_text, parse_email
from .redact import setup_logging
from .urlutil import defang

COLORS = {"safe": "32", "suspicious": "33", "phishing": "31"}


def _c(text: str, code: str, on: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if on else text


def load_target(target: str, source: str = "cli"):
    """A path to .eml/.txt, '-' for stdin, a URL, or literal text."""
    if target == "-":
        data = sys.stdin.buffer.read()
        return parse_email(data, source=source) if re.search(rb"(?im)^(from|subject|received):", data[:4000]) else from_text(data.decode("utf-8", "replace"), source=source)
    p = Path(target)
    try:
        is_file = p.is_file()
    except OSError:
        is_file = False
    if is_file:
        data = p.read_bytes()
        if p.suffix.lower() in (".eml", ".msg", ".mbox") or re.search(rb"(?im)^(received|return-path|mime-version|subject):", data[:4000]):
            return parse_email(data, source=source)
        return from_text(data.decode("utf-8", "replace"), source=source)
    return from_text(target, source=source)


def render(v: Verdict, color: bool, verbose: bool) -> str:
    out: list[str] = []
    col = COLORS[v.label]
    out.append(_c(f"{v.label.upper()}  risk {v.score}/100", "1;" + col, color))
    out.append(v.summary)
    out.append("")
    shown = [s for s in v.signals if abs(s.points) >= (1 if verbose else 8)]
    if shown:
        out.append("Reasons:")
        for s in shown[: (40 if verbose else 12)]:
            sign = "+" if s.points > 0 else ""
            ev = f"  [{defang(s.evidence) if s.layer in ('urls', 'behavior') and s.evidence.startswith(('http', 'hxxp')) else s.evidence}]" if verbose and s.evidence else ""
            out.append(f"  {sign}{s.points:>5.0f}  {s.layer:<10} {s.reason}{ev}")
    if v.layer_scores:
        out.append("")
        out.append("Layers: " + "  ".join(f"{k}={int(x)}" for k, x in v.layer_scores.items()))
    if v.urls:
        out.append("")
        out.append("Links (defanged):")
        for u in v.urls[:10]:
            fin = f"  ->  {u['defanged_final']}" if u.get("defanged_final") else ""
            out.append(f"  - {u['defanged']}{fin}")
    for rep in v.link_reports:
        out.append(f"  sandbox: {rep.get('defanged_final')} status={rep.get('status')} login_form={rep.get('has_login_form')} title={rep.get('title')!r}")
    for ar in v.attachment_reports:
        out.append("")
        out.append(f"Attachment report: {ar.get('filename')}  ({ar.get('file_type') or '?'}, {ar.get('size')} bytes)")
        out.append(f"  sha256 {ar.get('sha256')}")
        for b in ar.get("behaviors", []):
            out.append(f"  [{b['severity']}] {b.get('title') or b['id']}  {b.get('location', '')}")
            if b.get("snippet"):
                out.append("      " + b["snippet"].replace("\n", "\n      ")[:400])
        iocs = ar.get("iocs", {})
        for k, vals in iocs.items():
            if vals:
                out.append(f"  IOC {k}: " + ", ".join(defang(x) if k == "urls" else x for x in vals[:6]))
    for n in v.notes:
        out.append(_c("note: " + n, "2", color))
    return "\n".join(out)


def cmd_check(args, cfg: Config) -> int:
    from .pipeline import Analyzer
    from .service import Scanner

    containers = not args.no_sandbox
    analyzer = Analyzer.from_config(cfg, online=not args.offline, containers=containers)
    msg = load_target(args.target)
    scanner = Scanner(analyzer)
    res = scanner.scan(msg, persist=args.save, deep=containers)
    if args.json:
        from .present import public_verdict

        print(json.dumps(public_verdict(res.verdict.to_dict()), indent=2, default=str))   # links are defanged here too
    else:
        print(render(res.verdict, color=sys.stdout.isatty() and not os.environ.get("NO_COLOR"), verbose=args.verbose))
    return {"safe": 0, "suspicious": 1, "phishing": 2}[res.verdict.label]


def cmd_serve(args, cfg: Config) -> int:
    import uvicorn

    from .web.app import create_app

    if args.host:
        cfg.server.host = args.host
    if args.port:
        cfg.server.port = args.port
    app = create_app(cfg)
    if cfg.server.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: listening on {cfg.server.host}. Anyone on your network can reach the API; "
              f"all requests need the token in {cfg.path('token')}.")
    print(f"PhishGuard on http://{cfg.server.host}:{cfg.server.port}   (API token: {cfg.path('token')})")
    uvicorn.run(app, host=cfg.server.host, port=cfg.server.port, log_level="warning")
    return 0


def cmd_scan(args, cfg: Config) -> int:
    from .pipeline import Analyzer
    from .service import Scanner
    from .sources import poll_sources

    analyzer = Analyzer.from_config(cfg)
    scanner = Scanner(analyzer)
    names = None if args.source == "all" else [args.source]
    for line in poll_sources(cfg, scanner, names):
        print(line)
    return 0


def cmd_auth(args, cfg: Config) -> int:
    from .sources import authenticate

    print(authenticate(cfg, args.provider))
    return 0


def cmd_feeds(args, cfg: Config) -> int:
    from .intel import Intel
    from .store import Store

    store = Store(cfg.path("phishguard.db"))
    intel = Intel.from_config(cfg, store, online=True)
    if args.action == "update":
        for k, v in intel.feeds.update_all().items():
            print(f"{k}: {v}")
    for row in intel.feeds.stats():
        print(f"{row['source']}: {row['count']} urls (fetched {row['fetched_at']:.0f})")
    return 0


def cmd_train(args, cfg: Config) -> int:
    from .training import train_and_save

    print(train_and_save(cfg, Path(args.corpora)))
    return 0


def cmd_eval(args, cfg: Config) -> int:
    from .evaluation import run_eval

    print(run_eval(cfg, Path(args.corpora), out=Path(args.out) if args.out else None, limit=args.limit))
    return 0


def cmd_rescore(args, cfg: Config) -> int:
    from .feedback import rescore_all
    from .pipeline import Analyzer

    a = Analyzer.from_config(cfg, online=False, containers=False)
    print(f"{rescore_all(a)} message(s) re-scored with your feedback")
    return 0


def cmd_init(args, cfg: Config) -> int:
    dst = Path("config.toml")
    src = Path(__file__).resolve().parents[2] / "config.example.toml"
    if dst.exists():
        print("config.toml already exists")
        return 1
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    print("wrote config.toml")
    return 0


def cmd_doctor(args, cfg: Config) -> int:
    from .sandbox import make_re_adapter, make_sandbox

    print(f"data dir: {cfg.data_dir}")
    ls = make_sandbox(cfg)
    ok, why = ls.available()
    print(f"link sandbox  : {'OK' if ok else 'UNAVAILABLE'} - {why}")
    ra = make_re_adapter(cfg)
    ok2, why2 = ra.available()
    print(f"attachment RE : {'OK' if ok2 else 'UNAVAILABLE'} ({ra.name}) - {why2}")
    print(f"classifier    : {'trained' if cfg.path('classifier.joblib').exists() else 'not trained (run: phishguard train)'}")
    from .intel.feeds import FeedDB
    from .store import Store

    stats = FeedDB(Store(cfg.path('phishguard.db')), cfg.intel).stats()
    print("feeds         : " + (", ".join(f"{r['source']}={r['count']}" for r in stats) if stats else "empty (run: phishguard feeds update)"))
    print(f"gmail/imap/outlook enabled: {cfg.gmail.enabled}/{cfg.imap.enabled}/{cfg.outlook.enabled}")
    return 0


def cmd_build_images(args, cfg: Config) -> int:
    import shutil
    import subprocess

    if shutil.which(cfg.sandbox.docker_bin) is None:
        print(f"'{cfg.sandbox.docker_bin}' was not found on PATH. Install Docker (Docker Desktop on Windows/macOS, Docker Engine on Linux) "
              "or Podman (set sandbox.docker_bin = \"podman\"; see the README), then run this again. Until then links and attachments are not opened or analysed at all (there is no host fallback).")
        return 1
    root = Path(__file__).resolve().parents[2]
    rc = 0
    for name, ctx, tag in (("link", "docker/linkbox", cfg.sandbox.link_image), ("attachment", "docker/rebox", cfg.sandbox.re_image)):
        print(f"building {name} image {tag} ...")
        rc |= subprocess.call([cfg.sandbox.docker_bin, "build", "-f", str(root / ctx / "Dockerfile"), "-t", tag, str(root)])
    return rc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishguard", description="Personal phishing detector (local-first)")
    p.add_argument("--config", help="path to config.toml")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="check a .eml file, URL or text ('-' reads stdin)")
    c.add_argument("target")
    c.add_argument("--json", action="store_true")
    c.add_argument("-v", "--verbose", action="store_true")
    c.add_argument("--save", action="store_true", help="store the result in the local inbox")
    c.add_argument("--offline", action="store_true", help="no network lookups at all (feeds already downloaded are still used)")
    c.add_argument("--no-sandbox", action="store_true", help="skip Docker link/attachment analysis")
    c.set_defaults(fn=cmd_check)

    s = sub.add_parser("serve", help="run the local web app / API")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.set_defaults(fn=cmd_serve)

    sc = sub.add_parser("scan", help="poll a mailbox once")
    sc.add_argument("source", choices=["gmail", "imap", "outlook", "all"])
    sc.set_defaults(fn=cmd_scan)

    a = sub.add_parser("auth", help="one-time OAuth sign-in")
    a.add_argument("provider", choices=["gmail", "outlook"])
    a.set_defaults(fn=cmd_auth)

    f = sub.add_parser("feeds", help="phishing feed database")
    f.add_argument("action", choices=["update", "status"])
    f.set_defaults(fn=cmd_feeds)

    t = sub.add_parser("train", help="train the text classifier from corpora")
    t.add_argument("--corpora", default="data/corpora")
    t.set_defaults(fn=cmd_train)

    e = sub.add_parser("eval", help="precision/recall on held-out corpora")
    e.add_argument("--corpora", default="data/corpora")
    e.add_argument("--out")
    e.add_argument("--limit", type=int, default=0)
    e.set_defaults(fn=cmd_eval)

    r = sub.add_parser("rescore", help="re-combine stored signals with learned feedback weights")
    r.set_defaults(fn=cmd_rescore)
    i = sub.add_parser("init", help="write a starter config.toml")
    i.set_defaults(fn=cmd_init)
    d = sub.add_parser("doctor", help="check Docker, images, feeds, classifier")
    d.set_defaults(fn=cmd_doctor)
    b = sub.add_parser("build-images", help="build the isolated Docker images")
    b.set_defaults(fn=cmd_build_images)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)
    setup_logging(cfg.general.log_level)
    return args.fn(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
