// The one scripted animation: the risk number counts up while the ring (pure CSS) fills.
// The final value is already in the markup, so this is skipped under reduced motion and without JS.
(function () {
  "use strict";
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const easeOutQuart = (t) => 1 - Math.pow(1 - t, 4);
  const DURATION = 1100, DELAY = 150; // matches the CSS ring-fill timing

  function countUp(el) {
    const target = Number(el.dataset.countup);
    if (reduce || !Number.isFinite(target) || target <= 0) return;
    let t0 = null;
    el.textContent = "0";
    function frame(ts) {
      if (t0 === null) t0 = ts;
      const t = Math.min(1, Math.max(0, (ts - t0 - DELAY) / DURATION));
      el.textContent = String(t < 1 ? Math.round(target * easeOutQuart(t)) : target);
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  window.PG = Object.assign(window.PG || {}, { countUp });
  document.querySelectorAll("[data-countup]").forEach(countUp);
})();
