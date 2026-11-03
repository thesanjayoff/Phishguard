// Shared helpers. All dynamic text goes through textContent - message content is untrusted.
(function () {
  "use strict";
  const csrf = document.querySelector('meta[name="pg-csrf"]')?.content || "";

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      method: opts.method || "GET",
      headers: { "X-PG-CSRF": csrf, ...(opts.body ? { "Content-Type": "application/json" } : {}) },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      credentials: "same-origin",
    });
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON error body */ }
    if (!res.ok) throw new Error((data && (data.error || data.detail)) || ("request failed (" + res.status + ")"));
    return data;
  }

  function toast(text, ms = 3500) {
    const t = document.getElementById("toast");
    if (!t) return;
    t.textContent = text;
    t.hidden = false;
    clearTimeout(toast._h);
    toast._h = setTimeout(() => { t.hidden = true; }, ms);
  }

  window.PG = { api, toast };

  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    btn.disabled = true;
    try {
      if (action === "feedback") {
        const r = await api("/api/messages/" + encodeURIComponent(btn.dataset.id) + "/feedback", { method: "POST", body: { label: btn.dataset.label } });
        toast(r.changed ? "Thanks - noted. Similar messages will be scored with this in mind." : "Already recorded.");
        setTimeout(() => location.reload(), 700);
      } else if (action === "release") {
        await api("/api/messages/" + encodeURIComponent(btn.dataset.id) + "/release", { method: "POST" });
        toast("Released from quarantine.");
        setTimeout(() => location.reload(), 600);
      } else if (action === "scan") {
        toast("Scanning mailboxes...", 60000);
        const r = await api("/api/scan", { method: "POST" });
        toast((r.lines || []).slice(-3).join("  |  ") || "Done.", 6000);
        setTimeout(() => location.reload(), 1500);
      }
    } catch (e) {
      toast("Error: " + e.message, 6000);
    } finally {
      btn.disabled = false;
    }
  });
})();
