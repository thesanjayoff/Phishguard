// Dashboard charts: plain SVG, no libraries, no CDN. All data text is set with textContent (it is untrusted).
(function () {
  "use strict";
  const SVGNS = "http://www.w3.org/2000/svg";
  const dash = document.getElementById("dash");
  const tip = document.getElementById("tip");
  const LABELS = { safe: "Safe", suspicious: "Suspicious", phishing: "Phishing" };
  const ORDER = ["safe", "suspicious", "phishing"]; // bottom -> top of the stack
  let state = null;

  function h(tag, attrs, text) {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs || {}) e.setAttribute(k, attrs[k]);
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  const fmt = new Intl.NumberFormat();
  const dayLabel = (iso) => { const [y, m, d] = iso.split("-").map(Number); return new Date(y, m - 1, d).toLocaleDateString(undefined, { month: "short", day: "numeric" }); };

  // ---- tooltip (one for everything). rows: [{cls, label, value}] ----
  function showTip(title, rows, x, y) {
    tip.replaceChildren(el("div", "t", title));
    rows.forEach((r) => {
      const row = el("div", "r");
      row.append(el("span", "k " + r.cls), el("span", "", r.label), el("span", "v", fmt.format(r.value)));
      tip.append(row);
    });
    tip.hidden = false;
    const pad = 14, w = tip.offsetWidth, hgt = tip.offsetHeight;
    tip.style.left = Math.max(8, Math.min(x + pad, window.innerWidth - w - 8)) + "px";
    tip.style.top = Math.max(8, Math.min(y + pad, window.innerHeight - hgt - 8)) + "px";
  }
  const hideTip = () => { tip.hidden = true; };
  function bindTip(node, title, rows) {
    node.addEventListener("pointermove", (e) => showTip(title, rows, e.clientX, e.clientY));
    node.addEventListener("pointerleave", hideTip);
    node.addEventListener("focus", () => { const r = node.getBoundingClientRect(); showTip(title, rows, r.left + r.width / 2, r.top); });
    node.addEventListener("blur", hideTip);
  }

  // top-rounded rectangle path (square at the baseline, 4px rounded data end)
  function topRounded(x, y, w, hgt, r) {
    r = Math.max(0, Math.min(r, w / 2, hgt));
    return `M${x},${y + hgt} V${y + r} Q${x},${y} ${x + r},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + hgt} Z`;
  }
  function rightRounded(x, y, w, hgt, r) {
    r = Math.max(0, Math.min(r, hgt / 2, w));
    return `M${x},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + hgt - r} Q${x + w},${y + hgt} ${x + w - r},${y + hgt} H${x} Z`;
  }
  function niceMax(v) {
    if (v <= 4) return 4;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  // ---- stat tiles ----
  function tiles(d) {
    const box = document.getElementById("tiles");
    box.replaceChildren();
    const t = d.totals;
    const items = [
      ["Messages scanned", t.scanned, "last " + d.days + " days"],
      ["Phishing", t.phishing, "likely phishing"],
      ["Suspicious", t.suspicious, "worth a second look"],
      ["Quarantined", t.quarantined, "kept aside, never deleted"],
      ["Your corrections", d.corrections.false_alarms + d.corrections.missed,
        d.corrections.false_alarms + " false alarm(s), " + d.corrections.missed + " missed"],
    ];
    items.forEach(([label, value, sub]) => {
      const tile = el("div", "tile");
      tile.append(el("div", "label", label), el("div", "value", fmt.format(value)), el("div", "sub", sub));
      box.append(tile);
    });
  }

  function dataTable(container, headers, rows) {
    container.replaceChildren();
    const table = el("table");
    const thead = el("thead"), trh = el("tr");
    headers.forEach((x, i) => { const th = el("th", i ? "num" : "", x); th.scope = "col"; trh.append(th); });
    thead.append(trh);
    const tb = el("tbody");
    rows.forEach((r) => { const tr = el("tr"); r.forEach((c, i) => tr.append(el("td", i ? "num" : "", String(c)))); tb.append(tr); });
    table.append(thead, tb);
    container.append(table);
  }

  // ---- stacked daily columns ----
  function trend(d) {
    const box = document.getElementById("trend");
    box.replaceChildren();
    const legend = document.getElementById("trend-legend");
    legend.replaceChildren();
    ORDER.slice().reverse().forEach((k) => {
      const key = el("span", "key");
      key.append(el("span", "sw " + k), document.createTextNode(LABELS[k]));
      legend.append(key);
    });
    const series = d.series, n = series.length;
    dataTable(document.getElementById("trend-table"), ["Date", "Safe", "Suspicious", "Phishing"],
      series.map((s) => [s.date, s.safe, s.suspicious, s.phishing]));
    const maxTotal = Math.max(0, ...series.map((s) => s.safe + s.suspicious + s.phishing));
    if (!maxTotal) { box.append(el("p", "muted", "No scanned messages in this period yet.")); return; }
    const W = 900, H = 270, L = 38, R = 6, T = 10, B = 26;
    const pw = W - L - R, ph = H - T - B, top = niceMax(maxTotal), sc = ph / top;
    const svg = h("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Stacked columns of safe, suspicious and phishing messages per day over the last ${d.days} days. A table view is available.` });
    for (let i = 0; i <= 4; i++) {
      const v = (top / 4) * i, y = T + ph - v * sc;
      svg.append(h("line", { x1: L, x2: W - R, y1: y, y2: y, class: i ? "grid" : "axis" }));
      svg.append(h("text", { x: L - 6, y: y + 4, "text-anchor": "end" }, fmt.format(Math.round(v))));
    }
    const band = pw / n, bw = Math.min(24, band * 0.72), step = Math.ceil(n / 6);
    series.forEach((s, i) => {
      const cx = L + band * i + band / 2, x = cx - bw / 2;
      const g = h("g", { class: "band", tabindex: "0", role: "img", "aria-label": `${dayLabel(s.date)}: ${s.safe} safe, ${s.suspicious} suspicious, ${s.phishing} phishing` });
      let yb = T + ph; // running baseline of the stack
      const present = ORDER.filter((k) => s[k] > 0);
      present.forEach((k, idx) => {
        const hh = s[k] * sc, y = yb - hh, isTop = idx === present.length - 1;
        const gap = idx > 0 ? 2 : 0; // 2px surface gap below every segment that sits on another
        const sh = Math.max(1, hh - gap);
        const node = isTop ? h("path", { d: topRounded(x, y, bw, sh, 4), class: "mk " + k }) : h("rect", { x, y, width: bw, height: sh, class: "mk " + k });
        g.append(node);
        yb = y;
      });
      g.append(h("rect", { x: L + band * i, y: T, width: band, height: ph, class: "hit" })); // hit target = the whole day
      bindTip(g, dayLabel(s.date), ORDER.slice().reverse().map((k) => ({ cls: k, label: LABELS[k], value: s[k] })));
      svg.append(g);
      if (i % step === 0) svg.append(h("text", { x: cx, y: H - 8, "text-anchor": "middle" }, dayLabel(s.date)));
    });
    box.append(svg);
  }

  // ---- ranked horizontal bars (one hue, value at the tip) ----
  function ranked(id, items, noun) {
    const box = document.getElementById(id);
    box.replaceChildren();
    dataTable(document.getElementById(id + "-table"), [noun, "Flagged messages"], items.map((i) => [i.name, i.n]));
    if (!items.length) { box.append(el("p", "muted", "Nothing flagged in this period.")); return; }
    const W = 520, rowH = 30, bar = 16, gutter = 190, valW = 36, T = 4;
    const H = T + rowH * items.length + 4, max = Math.max(...items.map((i) => i.n)), sc = (W - gutter - valW) / max;
    const svg = h("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Ranked bars of ${noun.toLowerCase()} by number of flagged messages. A table view is available.` });
    svg.append(h("line", { x1: gutter, x2: gutter, y1: T, y2: H - 4, class: "axis" }));
    items.forEach((it, i) => {
      const y = T + rowH * i, by = y + (rowH - bar) / 2, w = Math.max(4, it.n * sc);
      const g = h("g", { tabindex: "0", role: "img", class: "band", "aria-label": `${it.name}: ${it.n} flagged message(s)` });
      const shown = it.name.length > 27 ? it.name.slice(0, 26) + "…" : it.name;
      g.append(h("text", { x: gutter - 8, y: y + rowH / 2 + 4, "text-anchor": "end", class: "lbl" }, shown));
      g.append(h("path", { d: rightRounded(gutter + 1, by, w, bar, 4), class: "mk ranked" }));
      g.append(h("text", { x: gutter + 1 + w + 6, y: y + rowH / 2 + 4, class: "val" }, fmt.format(it.n)));
      g.append(h("rect", { x: 0, y, width: W, height: rowH, class: "hit" }));
      bindTip(g, it.name, [{ cls: "ranked", label: "Flagged messages", value: it.n }]);
      svg.append(g);
    });
    box.append(svg);
  }

  function draw(d) {
    state = d;
    tiles(d);
    trend(d);
    ranked("brands", d.brands, "Brand");
    ranked("domains", d.domains, "Domain");
  }

  async function load(days) {
    dash.classList.add("loading"); // keep the previous render, dimmed, while refetching
    try { draw(await PG.api("/api/stats?days=" + days)); }
    catch (e) { PG.toast("Could not load statistics: " + e.message, 6000); }
    finally { dash.classList.remove("loading"); }
  }

  document.getElementById("range").addEventListener("click", (e) => {
    const b = e.target.closest("[data-days]");
    if (!b) return;
    document.querySelectorAll("#range .chip").forEach((c) => { c.classList.toggle("on", c === b); c.setAttribute("aria-pressed", c === b ? "true" : "false"); });
    load(Number(b.dataset.days));
  });

  function bindToggle(btn, chartId, tableId) {
    btn.addEventListener("click", () => {
      const showing = btn.getAttribute("aria-pressed") === "true";
      btn.setAttribute("aria-pressed", showing ? "false" : "true");
      btn.textContent = showing ? "Show table" : "Show chart";
      document.getElementById(chartId).hidden = !showing;
      document.getElementById(tableId).hidden = showing;
    });
  }
  bindToggle(document.getElementById("trend-toggle"), "trend", "trend-table");
  document.querySelectorAll("[data-table]").forEach((b) => bindToggle(b, b.dataset.table, b.dataset.table + "-table"));
  load(30);
})();
