(() => {
  "use strict";

  const API_BASE = (window.REQUESTSCOPE_CONFIG?.API_BASE || "").replace(/\/$/, "");
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const state = { report: null, progressTimer: null, progressStep: 0 };

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

  async function runTrace(url) {
    if (!url.trim()) return;
    beginProgress();
    errorPanel.classList.add("hidden");
    reportPanel.classList.add("hidden");
    traceButton.disabled = true;
    try {
      const response = await fetch(`${API_BASE}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() })
      });
      const payload = await response.json().catch(() => ({ error: "The API returned an unreadable response." }));
      if (!response.ok) throw new Error(payload.error || `Trace failed with HTTP ${response.status}`);
      finishProgress();
      displayReport(payload, true);
    } catch (error) {
      stopProgress();
      showError(error.message || "The trace could not be completed.");
    } finally {
      traceButton.disabled = false;
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
    clearInterval(state.progressTimer);
    state.progressStep = 0;
    $("#progress-title").textContent = title;
    progressPanel.classList.remove("hidden");
    $("#progress-bar").style.width = "8%";
    updateProgressSteps();
    progressPanel.scrollIntoView({ behavior: "smooth", block: "center" });
    state.progressTimer = setInterval(() => {
      state.progressStep = Math.min(4, state.progressStep + 1);
      $("#progress-bar").style.width = `${18 + state.progressStep * 18}%`;
      updateProgressSteps();
    }, 900);
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
    clearInterval(state.progressTimer);
    $("#progress-bar").style.width = "100%";
    setTimeout(() => progressPanel.classList.add("hidden"), 250);
  }

  function stopProgress() {
    clearInterval(state.progressTimer);
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
    const metrics = [
      ["Final status", finalStatus, statusClass],
      ["Total edge time", formatMs(report.totalDurationMs), ""],
      ["Redirects", Math.max(0, report.http.hops.length - 1), report.http.hops.length <= 3 ? "good" : "warn"],
      ["DNS addresses", report.dns.addresses.length, report.dns.addresses.length ? "good" : "warn"],
      ["Dependencies", report.dependencies.total, ""]
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
      <span><strong>${dependencies.total}</strong> references</span>
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
    </div>`).join("") : `<div class="dns-group"><p class="dns-empty">No matching dependencies were extracted from the inspected HTML.</p></div>`;
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

  const initialId = location.hash.slice(1);
  if (/^[A-Za-z0-9_-]{16}$/.test(initialId)) loadReport(initialId);
})();
