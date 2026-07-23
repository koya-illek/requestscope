(() => {
  "use strict";

  const API_BASE = (window.REQUESTSCOPE_CONFIG?.API_BASE || "").replace(/\/$/, "");
  const TURNSTILE_SITE_KEY = window.REQUESTSCOPE_CONFIG?.TURNSTILE_SITE_KEY || "";
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const state = { report: null, progressStep: 0, turnstileToken: "", turnstileWidget: null };

  const form = $("#trace-form");
  const input = $("#url-input");
  const traceButton = $("#trace-button");
  const progressPanel = $("#progress-panel");
  const errorPanel = $("#error-panel");
  const reportPanel = $("#report");
  const methodDialog = $("#method-dialog");

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runTrace(input.value);
  });
  input.addEventListener("input", updateQueryWarning);
  $("#new-trace").addEventListener("click", reset);
  $("#error-close").addEventListener("click", () => errorPanel.classList.add("hidden"));
  $("#copy-link").addEventListener("click", copyShareLink);
  $("#export-json").addEventListener("click", exportJson);
  $("#method-button").addEventListener("click", () => methodDialog.showModal());
  $("#footer-method-button").addEventListener("click", () => methodDialog.showModal());
  $("#dialog-close").addEventListener("click", () => methodDialog.close());
  methodDialog.addEventListener("click", (event) => {
    if (event.target === methodDialog) methodDialog.close();
  });
  $$(".filter").forEach((button) => button.addEventListener("click", () => {
    $$(".filter").forEach((item) => item.classList.toggle("active", item === button));
    renderDependencies(button.dataset.filter);
  }));
  initializeTurnstile();

  async function runTrace(url) {
    if (!url.trim()) return;
    beginProgress();
    errorPanel.classList.add("hidden");
    reportPanel.classList.add("hidden");
    traceButton.disabled = true;
    try {
      const response = await fetch(`${API_BASE}/api/scans/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), turnstileToken: state.turnstileToken })
      });
      if (!response.ok || !response.body) throw new Error(`Trace failed with HTTP ${response.status}`);
      const payload = await readTraceStream(response);
      finishProgress();
      displayReport(payload, true);
    } catch (error) {
      stopProgress();
      showError(error.message || "The trace could not be completed.");
    } finally {
      traceButton.disabled = false;
      resetTurnstile();
    }
  }

  async function loadReport(id) {
    beginProgress("Loading saved report");
    try {
      const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(id)}`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Saved report could not be loaded.");
      finishProgress();
      displayReport(payload, false);
    } catch (error) {
      stopProgress();
      showError(error.message);
    }
  }

  function beginProgress(title = "Tracing request path") {
    state.progressStep = 0;
    $("#progress-title").textContent = title;
    progressPanel.classList.remove("hidden");
    $("#progress-bar").style.width = "8%";
    updateProgressSteps();
    progressPanel.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function updateProgressSteps() {
    $$("#progress-steps li").forEach((item, index) => {
      item.classList.toggle("active", index === state.progressStep);
      item.classList.toggle("done", index < state.progressStep);
    });
    $$("#live-route .route-node").forEach((item, index) => {
      item.classList.toggle("active", index === state.progressStep);
      item.classList.toggle("done", index < state.progressStep);
    });
    $$("#live-route .route-wire").forEach((item, index) => {
      item.classList.toggle("active", index === state.progressStep - 1 || (state.progressStep === 0 && index === 0));
      item.classList.toggle("done", index < state.progressStep - 1);
    });
  }

  function finishProgress() {
    state.progressStep = 4;
    updateProgressSteps();
    $("#progress-bar").style.width = "100%";
    setTimeout(() => progressPanel.classList.add("hidden"), 250);
  }

  function stopProgress() {
    progressPanel.classList.add("hidden");
  }

  function showError(message) {
    $("#error-message").textContent = message;
    errorPanel.classList.remove("hidden");
    errorPanel.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function displayReport(report, updateLocation) {
    state.report = report;
    $("#report-host").textContent = report.hostname;
    $("#report-url").textContent = report.finalUrl || report.normalizedUrl;
    $("#report-url").href = report.finalUrl || report.normalizedUrl;
    const vantage = [report.observation.colo, report.observation.country].filter(Boolean).join(", ");
    $("#observation-note").textContent = `${report.observation.disclaimer}${vantage ? ` This trace executed through ${vantage}.` : ""}`;
    renderMetrics(report);
    renderTimeline(report.http.hops);
    renderDns(report.dns.queries);
    renderFindings(report.findings);
    renderDependencySummary(report.dependencies);
    renderDependencies("all");
    $$(".filter").forEach((item) => item.classList.toggle("active", item.dataset.filter === "all"));
    reportPanel.classList.remove("hidden");
    if (updateLocation) history.pushState({ reportId: report.id }, "", `#${report.id}`);
    document.title = `${report.hostname} — RequestScope`;
    setTimeout(() => reportPanel.scrollIntoView({ behavior: "smooth", block: "start" }), 280);
  }

  function renderMetrics(report) {
    const finalStatus = report.http.finalStatus ?? "—";
    const statusClass = Number(finalStatus) >= 200 && Number(finalStatus) < 400 ? "good" : "warn";
    const redirectCount = report.http.hops.filter((hop) => [301, 302, 303, 307, 308].includes(hop.status) && hop.location).length;
    const metrics = [
      ["Final status", finalStatus, statusClass],
      ["Total edge time", formatMs(report.totalDurationMs), ""],
      ["Redirects", redirectCount, redirectCount <= 2 ? "good" : "warn"],
      ["DNS addresses", report.dns.addresses.length, report.dns.addresses.length ? "good" : "warn"],
      ["HTML references", report.dependencies.total, ""]
    ];
    $("#metrics").innerHTML = metrics.map(([label, value, cls]) =>
      `<div class="metric"><small>${escapeHtml(label)}</small><strong class="${cls}">${escapeHtml(String(value))}</strong></div>`
    ).join("");
  }

  function renderTimeline(hops) {
    $("#timeline").innerHTML = hops.map((hop) => {
      const codeClass = hop.status === 0 || hop.status >= 400 ? "error" : hop.status >= 300 ? "redirect" : "";
      const details = [
        hop.cf?.httpProtocol,
        hop.cf?.tlsVersion,
        hop.cf?.colo ? `PoP ${hop.cf.colo}` : null,
        hop.error
      ].filter(Boolean);
      return `<article class="hop replay" style="animation-delay:${Math.min(hop.index * 130, 780)}ms">
        <span class="hop-index">${String(hop.index + 1).padStart(2, "0")}</span>
        <div class="hop-main">
          <strong title="${escapeAttr(hop.url)}">${escapeHtml(hop.url)}</strong>
          <div class="hop-detail">${details.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>
        </div>
        <div class="hop-status">
          <span class="status-code ${codeClass}">${hop.status || "ERR"}</span>
          <span class="elapsed">${formatMs(hop.elapsedMs)}</span>
        </div>
      </article>`;
    }).join("");
  }

  function renderDns(queries) {
    $("#dns-results").innerHTML = queries.map((query) => {
      const answers = query.answers.length
        ? query.answers.map((answer) => `<div class="dns-answer"><span>${escapeHtml(answer.type)}</span><code>${escapeHtml(answer.data)}</code><span>${answer.ttl}s</span></div>`).join("")
        : `<div class="dns-empty">${escapeHtml(query.error || (query.status === 0 ? "No records returned" : `DNS status ${query.status}`))}</div>`;
      return `<div class="dns-group">
        <div class="dns-title"><strong>${escapeHtml(query.type)} · ${escapeHtml(query.name)}</strong><span>${query.elapsedMs}ms${query.authenticatedData ? " · DNSSEC AD" : ""}</span></div>
        ${answers}
      </div>`;
    }).join("");
  }

  function renderFindings(findings) {
    $("#findings").innerHTML = findings.length ? findings.map((item) => `<article class="finding ${item.severity}">
      <span class="finding-dot" aria-hidden="true"></span>
      <div><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.detail)}</p><code>${escapeHtml(item.evidencePath)} · ${escapeHtml(item.confidence)} confidence</code></div>
    </article>`).join("") : `<div class="dns-group"><p class="dns-empty">No derived findings were generated.</p></div>`;
  }

  function renderDependencySummary(dependencies) {
    $("#dependency-summary").innerHTML = `
      <span><strong>${dependencies.total}</strong> HTML references</span>
      <span><strong>${dependencies.firstParty}</strong> first-party</span>
      <span><strong>${dependencies.thirdParty}</strong> third-party</span>
      <span><strong>${dependencies.uniqueHosts.length}</strong> hosts</span>`;
  }

  function renderDependencies(filter = "all") {
    if (!state.report) return;
    const items = state.report.dependencies.items.filter((item) => filter === "all" || item.party === filter);
    $("#dependencies").innerHTML = items.length ? items.map((item) => `<div class="dependency">
      <span class="type">${escapeHtml(item.type)}</span>
      <a href="${escapeAttr(item.url)}" target="_blank" rel="noopener noreferrer" title="${escapeAttr(item.url)}">${escapeHtml(item.url)}</a>
      <span class="party">${escapeHtml(item.party)}</span>
    </div>`).join("") : `<div class="dns-group"><p class="dns-empty">No matching resource references were extracted from the inspected HTML.</p></div>`;
  }

  async function copyShareLink() {
    if (!state.report) return;
    const link = `${location.origin}${location.pathname}#${state.report.id}`;
    try {
      await navigator.clipboard.writeText(link);
      flashButton($("#copy-link"), "Copied");
    } catch {
      prompt("Copy this report link:", link);
    }
  }

  function exportJson() {
    if (!state.report) return;
    const anchor = document.createElement("a");
    anchor.href = `${API_BASE}/api/scans/${encodeURIComponent(state.report.id)}/export`;
    anchor.download = `requestscope-${state.report.id}.json`;
    anchor.click();
  }

  function reset() {
    state.report = null;
    reportPanel.classList.add("hidden");
    errorPanel.classList.add("hidden");
    history.pushState({}, "", location.pathname);
    document.title = "RequestScope — See the journey behind a URL";
    input.value = "";
    updateQueryWarning();
    input.focus();
    scrollTo({ top: 0, behavior: "smooth" });
  }

  function flashButton(button, text) {
    const original = button.textContent;
    button.textContent = text;
    setTimeout(() => { button.textContent = original; }, 1400);
  }

  function formatMs(value) {
    return value >= 1000 ? `${(value / 1000).toFixed(2)}s` : `${value}ms`;
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/`/g, "&#96;");
  }

  async function readTraceStream(response) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let report = null;
    while (true) {
      const { done, value } = await reader.read();
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines) {
        if (!line.trim()) continue;
        const event = JSON.parse(line);
        if (event.type === "progress") applyProgress(event);
        if (event.type === "result") report = event.report;
        if (event.type === "error") throw new Error(event.error || "Trace failed.");
      }
      if (done) break;
    }
    if (!report) throw new Error("The trace ended without a report.");
    return report;
  }

  function applyProgress(event) {
    const stageMap = { accepted: 0, validated: 0, dns: 1, hop: 2, response: 3, complete: 4 };
    state.progressStep = stageMap[event.stage] ?? state.progressStep;
    $("#progress-title").textContent = event.message || "Tracing request path";
    $("#progress-bar").style.width = `${18 + state.progressStep * 20}%`;
    updateProgressSteps();
  }

  function updateQueryWarning() {
    let hasQuery = false;
    try {
      const raw = input.value.trim();
      if (raw) {
        const value = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
        hasQuery = new URL(value).search.length > 0;
      }
    } catch {
      hasQuery = false;
    }
    $("#query-warning").classList.toggle("hidden", !hasQuery);
  }

  function initializeTurnstile() {
    if (!TURNSTILE_SITE_KEY) return;
    traceButton.disabled = true;
    $("#turnstile-shell").classList.remove("hidden");
    const render = () => {
      if (!window.turnstile || state.turnstileWidget !== null) return;
      state.turnstileWidget = window.turnstile.render("#turnstile-widget", {
        sitekey: TURNSTILE_SITE_KEY,
        theme: "dark",
        size: "flexible",
        appearance: "always",
        action: "requestscope_scan",
        callback: (token) => {
          state.turnstileToken = token;
          traceButton.disabled = false;
        },
        "expired-callback": () => {
          state.turnstileToken = "";
          traceButton.disabled = true;
        },
        "error-callback": () => {
          state.turnstileToken = "";
          traceButton.disabled = true;
          showError("Human verification could not complete. Check browser privacy controls, then refresh the page.");
        }
      });
    };
    const timer = setInterval(() => {
      render();
      if (state.turnstileWidget !== null) clearInterval(timer);
    }, 100);
    setTimeout(() => {
      clearInterval(timer);
      if (state.turnstileWidget === null) {
        showError("Human verification could not load. Check content blockers or network filtering, then refresh the page.");
      }
    }, 10000);
  }

  function resetTurnstile() {
    state.turnstileToken = "";
    if (TURNSTILE_SITE_KEY) traceButton.disabled = true;
    if (window.turnstile && state.turnstileWidget !== null) window.turnstile.reset(state.turnstileWidget);
  }

  const initialId = location.hash.slice(1);
  if (/^[A-Za-z0-9_-]{16}$/.test(initialId)) loadReport(initialId);
})();
