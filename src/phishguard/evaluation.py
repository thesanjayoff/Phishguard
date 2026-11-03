"""Precision / recall / false-positive report on held-out data (offline: no network lookups, no containers)."""
from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .intel import Intel
from .layers.ml import Classifier
from .models import Message
from .pipeline import Analyzer
from .store import Store
from .synthetic import generate
from .training import UNREADABLE, load_ham, load_nazario, split


@dataclass
class Result:
    label: int
    score: int
    verdict: str
    subject: str
    top: str
    family: str = ""


def _run(analyzer: Analyzer, items: list[tuple[Message, int, str]]) -> list[Result]:
    out = []
    for msg, label, fam in items:
        v = analyzer.analyze(msg, deep=False)
        top = "; ".join(s.id for s in sorted(v.signals, key=lambda s: -s.points)[:3])
        out.append(Result(label, v.score, v.label, (msg.subject or msg.text[:50]).replace("\n", " ")[:60], top, fam))
    return out


def metrics(rs: list[Result], phishing_only: bool) -> dict:
    def pred(r: Result) -> bool:
        return r.verdict == "phishing" if phishing_only else r.verdict in ("phishing", "suspicious")

    tp = sum(1 for r in rs if r.label and pred(r))
    fp = sum(1 for r in rs if not r.label and pred(r))
    fn = sum(1 for r in rs if r.label and not pred(r))
    tn = sum(1 for r in rs if not r.label and not pred(r))
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if prec == prec and rec == rec and prec + rec else float("nan")
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1, fpr=fp / (fp + tn) if fp + tn else float("nan"))


def _fmt(m: dict) -> str:
    return (f"precision {m['precision']:.3f}  recall {m['recall']:.3f}  F1 {m['f1']:.3f}  "
            f"FP {m['fp']}/{m['fp'] + m['tn']} ({m['fpr'] * 100:.2f}%)  FN {m['fn']}/{m['tp'] + m['fn']}   [TP {m['tp']} FP {m['fp']} FN {m['fn']} TN {m['tn']}]")


def _url_only_set(corpora: Path, ham_test: list[Message]) -> list[tuple[Message, int, str]]:
    """Bare URLs as a user would paste them. Phishing: the OpenPhish public feed if it was downloaded
    (data/corpora/feeds/openphish.txt). Legitimate: links found in held-out legitimate mail, at most 2 per site."""
    from .parsing.email_parser import from_text
    from .urlutil import parse_url

    feed = corpora / "feeds" / "openphish.txt"
    if not feed.is_file():
        return []
    phish = [ln.strip() for ln in feed.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip().lower().startswith(("http://", "https://"))]
    seen_sites: dict[str, int] = {}
    benign: list[str] = []
    for m in ham_test:
        for u in m.urls[:4]:
            p = parse_url(u.url)
            if not p or not p.explicit_scheme or p.scheme not in ("http", "https"):
                continue
            if seen_sites.get(p.registrable, 0) >= 2 or u.url in benign:
                continue
            seen_sites[p.registrable] = seen_sites.get(p.registrable, 0) + 1
            benign.append(u.url)
    return [(from_text(u, kind="url"), 1, "openphish") for u in phish] + [(from_text(u, kind="url"), 0, "ham-link") for u in benign[:1000]]


def run_eval(cfg: Config, corpora: Path, out: Path | None = None, limit: int = 0) -> str:
    tmp = Path(tempfile.mkdtemp(prefix="pgeval-"))
    store = Store(tmp / "eval.db")
    clf = Classifier.load(cfg.path("classifier.joblib"))
    base = dict(cfg=cfg, store=store, intel=Intel.offline(store), use_feedback=False)
    full = Analyzer(classifier=clf, use_ml=clf is not None, **base)
    rules = Analyzer(classifier=None, use_ml=False, **base)

    lines: list[str] = ["# PhishGuard evaluation (offline, held-out)", "",
                        f"generated {time.strftime('%Y-%m-%d %H:%M')}; thresholds: suspicious>={cfg.thresholds.suspicious}, phishing>={cfg.thresholds.phishing}",
                        "No network lookups (domain age, feeds, Safe Browsing) and no containers were used, so these numbers cover the static layers only.", ""]
    sets: dict[str, list[tuple[Message, int, str]]] = {}
    phish, ham = load_nazario(corpora), load_ham(corpora)
    if UNREADABLE:
        lines += [f"NOTE: the OS refused to open {len(set(UNREADABLE))} Nazario file(s) ({', '.join(sorted(set(UNREADABLE)))}) - most likely "
                  "blocked by antivirus real-time protection. They were skipped, not worked around; results use the remaining files.", ""]
    if phish and ham:
        _, p_te = split(phish)
        _, h_te = split(ham)
        if limit:
            p_te, h_te = p_te[:limit], h_te[:limit]
        sets["real corpora: Nazario phishing vs SpamAssassin ham"] = [(m, 1, "nazario") for m in p_te] + [(m, 0, "spamassassin") for m in h_te]
        url_set = _url_only_set(corpora, h_te)
        if url_set:
            n_p = sum(1 for _, l, _ in url_set if l)
            sets[f"URL only: OpenPhish community feed ({n_p} live phishing URLs, never used for tuning) vs links found in legitimate mail"] = url_set
    synth = generate(n_per_family=10, variants=(1,), seed=4242)  # held-out wording, new random slots
    sets["synthetic held-out wording (GoPhish-style email, India SMS/chat scams, hard-negative legit mail)"] = [(s.msg, s.label, s.family) for s in synth]
    sets["synthetic India SMS/chat only"] = [(s.msg, s.label, s.family) for s in synth if s.channel in ("sms", "chat")]

    for name, items in sets.items():
        lines += [f"## {name}", f"{sum(1 for _, l, _ in items if l)} phishing / {sum(1 for _, l, _ in items if not l)} legitimate", ""]
        for mode, an in (("rules only (no classifier)", rules), ("rules + classifier", full)):
            if an is full and clf is None:
                continue
            rs = _run(an, items)
            lines.append(f"**{mode}**")
            lines.append(f"- flagged (suspicious or phishing): {_fmt(metrics(rs, False))}")
            lines.append(f"- phishing verdict only        : {_fmt(metrics(rs, True))}")
            fps = sorted((r for r in rs if not r.label and r.verdict != "safe"), key=lambda r: -r.score)[:8]
            fns = sorted((r for r in rs if r.label and r.verdict == "safe"), key=lambda r: r.score)[:8]
            if fps:
                lines.append("- worst false positives: " + " | ".join(f"{r.score} '{r.subject}' [{r.top}]" for r in fps))
            if fns:
                lines.append("- sample misses: " + " | ".join(f"{r.score} '{r.subject}' [{r.family}]" for r in fns))
            lines.append("")
    text = "\n".join(lines)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    return text
