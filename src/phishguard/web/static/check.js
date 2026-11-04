(function () {
  "use strict";
  const form = document.getElementById("check-form");
  const out = document.getElementById("result");
  const busy = document.getElementById("busy");

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  // Same ring as the report page (see the `ring` macro); all values are set as attributes / textContent.
  const SVGNS = "http://www.w3.org/2000/svg";
  function ring(score, label) {
    const s = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
    const wrap = el("div", "ring v-" + label);
    wrap.setAttribute("role", "img");
    wrap.setAttribute("aria-label", "Risk score " + s + " out of 100");
    const svg = document.createElementNS(SVGNS, "svg");
    svg.setAttribute("viewBox", "0 0 120 120");
    svg.setAttribute("aria-hidden", "true");
    const circle = (cls, extra) => {
      const c = document.createElementNS(SVGNS, "circle");
      c.setAttribute("class", cls);
      [["cx", "60"], ["cy", "60"], ["r", "52"], ["pathLength", "100"]].forEach(([k, v]) => c.setAttribute(k, v));
      for (const k in extra || {}) c.setAttribute(k, extra[k]);
      return c;
    };
    svg.append(circle("track"));
    if (s > 0) svg.append(circle("fill", { "stroke-dasharray": s + " 100" }));
    const num = el("span", "ring-num", String(s));
    num.dataset.countup = String(s);
    wrap.append(svg, num);
    return wrap;
  }

  function render(r) {
    out.replaceChildren();
    const head = el("div", "verdict-head v-" + r.label);
    const sb = el("div", "score-block");
    sb.append(ring(r.score, r.label), el("div", "muted small", "risk score, 0-100"));
    const main = el("div", "vh-main");
    const badge = el("span", "badge v-" + r.label);
    badge.append(el("span", "glyph", r.label === "safe" ? "✓" : r.label === "suspicious" ? "!" : "✕"), document.createTextNode(r.label[0].toUpperCase() + r.label.slice(1)));
    main.append(badge, el("p", "summary", r.summary || ""));
    if (r.message_id) {
      const a = el("a", "", "Open the full report");
      a.href = "/message/" + r.message_id;
      main.append(a);
    } else {
      main.append(el("p", "muted small", "Not saved to the inbox."));
    }
    head.append(sb, main);
    out.append(head);
    (r.notes || []).forEach((n) => out.append(el("p", "note", n)));
    out.append(el("h2", "", "Reasons"));
    if (!(r.signals || []).length) out.append(el("p", "muted", "Nothing unusual was found."));
    const ul = el("ul", "reasons");
    (r.signals || []).forEach((s) => {
      const li = el("li", s.points < 0 ? "neg" : "pos");
      li.append(el("span", "pts", (s.points >= 0 ? "+" : "") + Math.round(s.points)));
      const d = el("div");
      d.append(el("div", "", s.reason));
      if (s.evidence) d.append(el("code", "ev", s.evidence));
      li.append(d);
      ul.append(li);
    });
    out.append(ul);
    out.hidden = false;
    out.querySelectorAll("[data-countup]").forEach((n) => window.PG.countUp && window.PG.countUp(n));
    out.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    busy.hidden = false;
    try {
      const r = await PG.api("/api/check", { method: "POST", body: {
        text: document.getElementById("text").value, kind: document.getElementById("kind").value,
        sender: document.getElementById("sender").value, save: document.getElementById("save").checked,
        deep: document.getElementById("deep").checked } });
      render(r);
    } catch (e) {
      PG.toast("Error: " + e.message, 6000);
    } finally {
      submit.disabled = false;
      busy.hidden = true;
    }
  });
})();
