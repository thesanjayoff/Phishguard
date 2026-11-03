"""Analyzer: runs every layer on a Message and returns one explained Verdict."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from . import knowledge
from .config import Config
from .ctx import Ctx
from .intel import Intel
from .layers import attachments as att_layer
from .layers import behavior as behavior_layer
from .layers import content as content_layer
from .layers import headers as headers_layer
from .layers import urls as urls_layer
from .layers.ml import Classifier, points_from_proba
from .models import Message, Signal, Verdict
from .feedback import auth_ok, sender_key
from .parsing.email_parser import collect_urls
from .scoring import combine, summarize
from .store import Store
from .urlutil import parse_url

log = logging.getLogger(__name__)


@dataclass
class Analyzer:
    cfg: Config
    store: Store
    intel: Intel
    sandbox: object | None = None  # LinkSandbox
    re_adapter: object | None = None  # REAdapter
    classifier: Classifier | None = None
    llm: object | None = None
    use_ml: bool = True
    use_feedback: bool = True
    learned: dict[str, float] = field(default_factory=dict)

    # ---- construction -------------------------------------------------------
    @classmethod
    def from_config(cls, cfg: Config, store: Store | None = None, online: bool = True, containers: bool = True) -> "Analyzer":
        from .feedback import learned_weights
        from .llm import LlmClient
        from .sandbox import make_re_adapter, make_sandbox

        store = store or Store(cfg.path("phishguard.db"))
        intel = Intel.from_config(cfg, store, online=online)
        sandbox = make_sandbox(cfg, store) if containers and cfg.sandbox.enabled else None
        re_adapter = make_re_adapter(cfg) if containers and cfg.attachments.enabled else None
        clf = Classifier.load(cfg.path("classifier.joblib"))
        llm = LlmClient.from_config(cfg) if online else None
        a = cls(cfg=cfg, store=store, intel=intel, sandbox=sandbox, re_adapter=re_adapter, classifier=clf, llm=llm)
        a.learned = learned_weights(store)
        return a

    def reload_learning(self) -> None:
        from .feedback import learned_weights

        self.learned = learned_weights(self.store)
        self.classifier = Classifier.load(self.cfg.path("classifier.joblib")) or self.classifier

    # ---- main entry -----------------------------------------------------------
    def analyze(self, msg: Message, deep: bool = True) -> Verdict:
        ctx = Ctx(cfg=self.cfg, store=self.store, intel=self.intel, weights=self.learned, sandbox=self.sandbox,
                  re_adapter=self.re_adapter, classifier=self.classifier, llm=self.llm)
        if not msg.urls:
            msg.urls = collect_urls(msg)
        signals: list[Signal] = []
        facts: dict = {}

        # 1. envelope + URLs (first pass: static, no network containers)
        hs, hfacts = headers_layer.analyze(msg, ctx)
        us, url_infos = urls_layer.analyze(msg, ctx)
        signals += hs + us
        facts["headers"] = hfacts

        # 2. expand shorteners inside the container, then re-evaluate the real destinations
        resolved: dict[str, str] = {}
        if deep and self.sandbox is not None and self.cfg.sandbox.expand_shorteners:
            shorts = [i["url"] for i in url_infos if i.get("shortener")]
            if shorts:
                try:
                    resolved = {k: v for k, v in self.sandbox.expand(shorts[:8]).items() if v}
                except Exception as e:  # sandbox failures must never break scanning
                    ctx.notes.append(f"Link shortener expansion unavailable ({type(e).__name__})")
                if resolved:
                    signals = [s for s in signals if s.layer != "urls"]
                    us, url_infos = urls_layer.analyze(msg, ctx, resolved)
                    signals += us
        elif deep and any(i.get("shortener") for i in url_infos):
            ctx.notes.append("Shortened links were not expanded (container sandbox not available).")

        # 3. content
        cs, cfacts = content_layer.analyze(msg, ctx, url_infos)
        signals += cs
        facts["content"] = cfacts
        # 4. classifier / optional LLM
        signals += self._ml_signals(msg, ctx)

        # 5. link behaviour in the isolated browser container
        link_reports: list[dict] = []
        if deep:
            pre_score, _, _ = combine(signals, self.cfg.thresholds.suspicious, self.cfg.thresholds.phishing, self.learned)
            bs, link_reports = behavior_layer.run(msg, ctx, url_infos, pre_score, resolved)
            signals += bs

        # 6. attachments in the isolated, no-network container
        attachment_reports: list[dict] = []
        if msg.attachments:
            as_, attachment_reports = att_layer.run(msg, ctx, deep=deep)
            signals += as_

        # 7. your past feedback
        if self.use_feedback:
            from .feedback import sender_signals

            signals += sender_signals(self.store, msg, ctx)

        score, label, layer_scores = combine(signals, self.cfg.thresholds.suspicious, self.cfg.thresholds.phishing, self.learned)
        if label == "safe" and url_infos and not link_reports and all(i.get("age_days") is None and not i.get("official_brand") for i in url_infos):
            # Static rules cannot see a brand-new site that has no lookalike features (on real phishing URLs they catch only a few percent).
            ctx.notes.append("Not verified: only static checks ran on the link(s). Domain age, phishing feeds and the isolated browser visit "
                             "were not available, so a newly created site without lookalike features can still look safe here.")
        signals.sort(key=lambda s: -abs(s.points))
        brands = sorted(set(hfacts.get("spoofed_brands", [])) | set(cfacts.get("spoofed_brands", []))
                        | {b for i in url_infos for b in i.get("brands", [])})
        bad_domains = self._bad_domains(msg, url_infos, signals, hfacts)
        return Verdict(
            score=score, label=label, signals=signals, layer_scores=layer_scores,
            summary=summarize(signals, label, score, self.learned), notes=list(dict.fromkeys(ctx.notes)),
            attachment_reports=attachment_reports, link_reports=link_reports, urls=url_infos, brands=brands,
            domains=bad_domains, facts={"sender_key": sender_key(msg), "auth_ok": auth_ok(msg)},
        )

    # ---- helpers ---------------------------------------------------------------
    def _ml_signals(self, msg: Message, ctx: Ctx) -> list[Signal]:
        out: list[Signal] = []
        if self.use_ml and self.classifier is not None and (msg.text or msg.subject):
            try:
                p = self.classifier.proba(msg)
                pts = points_from_proba(p)
                if abs(pts) >= 3:
                    out.append(ctx.sig("content", "content.ml_classifier", pts,
                                       f"Text classifier: {int(p * 100)}% similar to known phishing messages"
                                       if pts > 0 else f"Text classifier: reads like ordinary mail ({int((1 - p) * 100)}% confident)",
                                       f"p={p:.3f}"))
            except Exception as e:  # pragma: no cover
                log.warning("classifier failed: %s", e)
        if self.llm is not None and getattr(self.llm, "enabled", False):
            try:
                r = self.llm.assess(msg)
                if r:
                    pts = round(r["probability"] * 85 * self.cfg.llm.weight, 1)
                    if pts >= 5:
                        out.append(ctx.sig("content", "content.llm", pts, "LLM review: " + r["reason"], f"p={r['probability']:.2f}"))
                    elif r["probability"] < 0.15:
                        out.append(ctx.sig("content", "content.llm_benign", -8, "LLM review: looks like ordinary mail", r["reason"][:120]))
            except Exception as e:
                ctx.notes.append(f"LLM review failed ({type(e).__name__})")
        return out

    @staticmethod
    def _bad_domains(msg: Message, url_infos: list[dict], signals: list[Signal], hfacts: dict) -> list[str]:
        """Registrable domains worth listing on the dashboard as 'malicious'."""
        strong_ids = {"url.blocklist", "url.blocklist_host", "url.safe_browsing", "url.brand_homograph", "url.brand_typosquat",
                      "url.brand_combosquat", "url.brand_subdomain", "url.brand_tld", "url.text_mismatch", "url.ip_host",
                      "url.mixed_script", "url.userinfo_trick", "url.tld_keywords", "url.domain_age", "url.hosting_brand"}
        bad: set[str] = set()
        for info in url_infos:
            flags = set(info.get("flags", [])) | set(info.get("final_flags", []))
            if not (flags & strong_ids) or info.get("official_brand"):
                continue
            cands = [] if info.get("shortener") else [info.get("registrable")]
            if info.get("final_url"):
                p = parse_url(info["final_url"])
                cands.append(p.registrable if p else None)
            bad.update(c for c in cands if c)
        fd = hfacts.get("from_domain")
        if fd and any(s.id.startswith(("hdr.from_", "hdr.display_name")) for s in signals if s.points >= 40):
            bad.add(fd)
        # Shared infrastructure is not "a malicious domain": free mailboxes, mailing-list/tracking providers, hosts, shorteners.
        kb = knowledge.load()
        bad = {d for d in bad if d not in kb.freemail and d not in kb.esp_domains and d not in kb.free_hosting
               and d not in kb.shorteners and not kb.brand_of_domain(d)}
        return sorted(bad)[:12]
