/* ============================================================
   AgentGuard — terminal.js
   Drives the animated terminal in the hero. Falls back to a
   scripted demo sequence; if AGENTGUARD_API_BASE is set and
   reachable, it can also poll real session logs.
   ============================================================ */

(function () {
  "use strict";

  // Scripted demo lines shown when no live backend is configured.
  // Each line: { html, delayAfter } — html is injected as-is so we
  // can keep the existing <span class="ok/warn/bad/path"> styling.
  const DEMO_SEQUENCE = [
    { html: '$ agent.call <span class="path">get_database_credentials</span>', delay: 500 },
    { html: '&nbsp;&nbsp;source: <span class="warn">untrusted_email_body</span>', delay: 400 },
    { html: '&nbsp;&nbsp;scanning payload for embedded instructions&hellip;', delay: 700 },
    { html: '<span class="bad">&#10007; TRIPPED — indirect injection signature matched</span>', delay: 1200 },
    { html: '&nbsp;', delay: 300 },
    { html: '$ agent.call <span class="path">search_orders</span> &times;14 (28s)', delay: 500 },
    { html: '&nbsp;&nbsp;similarity across calls: 96%', delay: 500 },
    { html: '<span class="bad">&#10007; TRIPPED — runaway loop, breaker open</span>', delay: 400 },
    { html: '&nbsp;&nbsp;session frozen, dev alerted', delay: 1100 },
    { html: '&nbsp;', delay: 300 },
    { html: '$ agent.call <span class="path">write_file</span> /tmp/report.csv', delay: 500 },
    { html: '&nbsp;&nbsp;routed via landlock sandbox', delay: 500 },
    { html: '<span class="ok">&#10003; ALLOWED — scoped to ephemeral dir</span>', delay: 1400 },
  ];

  const TYPE_SPEED_MS = 14; // ms per character while "typing" a line

  function typeLine(container, html, onDone) {
    const lineEl = document.createElement("div");
    container.appendChild(lineEl);

    // Strip tags for character-by-character typing, but preserve markup
    // by typing the raw text nodes and re-inserting tags at their spot.
    // Simpler approach: reveal via a temp element, then swap in real HTML.
    const plain = html.replace(/<[^>]+>/g, "");
    let i = 0;

    const typer = setInterval(() => {
      lineEl.textContent = plain.slice(0, i);
      i++;
      if (i > plain.length) {
        clearInterval(typer);
        lineEl.innerHTML = html; // swap in the styled version once fully typed
        onDone();
      }
    }, TYPE_SPEED_MS);
  }

  function runSequence(container, sequence, loop) {
    let idx = 0;

    function next() {
      if (idx >= sequence.length) {
        if (loop) {
          setTimeout(() => {
            container.innerHTML = "";
            idx = 0;
            next();
          }, 2500);
        }
        return;
      }
      const item = sequence[idx];
      idx++;
      typeLine(container, item.html, () => {
        setTimeout(next, item.delay);
      });
    }
    next();
  }

  function initDemoTerminal() {
    const container = document.querySelector("[data-agentguard-terminal]");
    if (!container) return;
    container.innerHTML = "";
    runSequence(container, DEMO_SEQUENCE, true);
  }

  // --- Optional live mode -------------------------------------------------
  // If a backend base URL is provided (e.g. via window.AGENTGUARD_API_BASE
  // set in a script tag before this file loads), poll recent session logs
  // and render them instead of the scripted demo. Expects the backend to
  // expose a read endpoint like GET {base}/logs/recent returning JSON:
  // [{ session_id, method, status, ts }, ...]
  async function tryLiveMode() {
    const base = window.AGENTGUARD_API_BASE;
    const container = document.querySelector("[data-agentguard-terminal]");
    if (!base || !container) return false;

    try {
      const res = await fetch(base.replace(/\/$/, "") + "/logs/recent", {
        method: "GET",
        headers: { Accept: "application/json" },
      });
      if (!res.ok) return false;

      const logs = await res.json();
      if (!Array.isArray(logs) || logs.length === 0) return false;

      const sequence = logs.slice(0, 12).map((entry) => {
        const statusClass =
          entry.status === "ALLOWED" ? "ok" :
          entry.status === "BLOCKED_BY_POLICY" ? "warn" : "bad";
        const symbol = statusClass === "ok" ? "&#10003;" : "&#10007;";
        return {
          html: `$ agent.call <span class="path">${escapeHtml(entry.method || "unknown")}</span> — <span class="${statusClass}">${symbol} ${escapeHtml(entry.status || "")}</span>`,
          delay: 900,
        };
      });

      container.innerHTML = "";
      runSequence(container, sequence, true);
      return true;
    } catch (e) {
      return false; // network error / CORS / backend down — fall back to demo
    }
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  document.addEventListener("DOMContentLoaded", async () => {
    const wentLive = await tryLiveMode();
    if (!wentLive) initDemoTerminal();

    // Optional: refresh live data every 8s if live mode is active
    if (wentLive) {
      setInterval(tryLiveMode, 8000);
    }
  });
})();