(() => {
  "use strict";

  const API_BASE = (window.REQUESTSCOPE_CONFIG?.API_BASE || "").replace(/\/$/, "");
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const state = { report: null, progressStep: 0 };

  const form = $("#trace-form");
  const input = $("#url-input");
  const traceButton = $("#trace-button");
  const mapDepsCheckbox = $("#map-deps");
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
  async function runTrace(url) {
    if (!url.trim()) return;
    beginProgress();
    errorPanel.classList.add("hidden");
    reportPanel.classList.add("hidden");
    $("#dep-map-panel").classList.add("hidden");
    traceButton.disabled = true;
    try {
      const response = await fetch(`${API_BASE}/api/scans/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), mapDependencies: mapDepsCheckbox.checked })
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
    const stepsEl = $("#progress-steps");
    if (mapDepsCheckbox.checked && stepsEl.children.length === 5) {
      const li = document.createElement("li");
      li.textContent = "Map dependencies";
      stepsEl.appendChild(li);
    } else if (!mapDepsCheckbox.checked && stepsEl.children.length === 6) {
      stepsEl.lastChild.remove();
    }
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
    state.progressStep = mapDepsCheckbox.checked ? 5 : 4;
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
    renderDepMap(report.dependencyMap);
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
    $("#dep-map-panel").classList.add("hidden");
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
    const stageMap = { accepted: 0, validated: 0, dns: 1, hop: 2, response: 3, complete: mapDepsCheckbox.checked ? 5 : 4 };
    // Deps stages map to step 4 ("Map dependencies")
    if (event.stage.startsWith("deps-")) {
      state.progressStep = 4;
    } else {
      state.progressStep = stageMap[event.stage] ?? state.progressStep;
    }
    $("#progress-title").textContent = event.message || "Tracing request path";
    const stepCount = mapDepsCheckbox.checked ? 5 : 4;
    $("#progress-bar").style.width = `${18 + (state.progressStep / stepCount) * 75}%`;
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

  function renderDepMap(depMap) {
    const panel = $("#dep-map-panel");
    if (!depMap) {
      panel.classList.add("hidden");
      return;
    }
    panel.classList.remove("hidden");

    const cats = depMap.summary.byCategory || {};
    $("#dep-map-summary").innerHTML = [
      ["Total domains", depMap.summary.totalDomains, ""],
      ["PII risk", depMap.summary.piiRisk, depMap.summary.piiRisk > 0 ? "warn" : "good"],
      ["Post-auth only", depMap.summary.postAuthOnly, ""],
      ["Analytics", cats.analytics || 0, ""],
      ["Advertising", cats.advertising || 0, ""],
      ["Payment", cats.payment || 0, ""],
      ["Communication", cats.communication || 0, ""],
    ].map(([label, value, cls]) =>
      `<span><strong class="${cls}">${escapeHtml(String(value))}</strong> ${escapeHtml(label)}</span>`
    ).join("");

    // SSL / TLS
    renderSsl(depMap.ssl);

    // SDKs
    renderSdks(depMap.sdks || []);

    // Domains count badge
    $("#domain-count").textContent = depMap.domains.length || "";
    $("#domain-count").classList.toggle("hidden", !depMap.domains.length);

    // CSP
    const csp = depMap.sources.csp;
    $("#dep-csp").innerHTML = !csp.present
      ? `<p class="dns-empty">No Content-Security-Policy header observed.</p>`
      : Object.entries(csp.directives).map(([name, sources]) =>
          `<div class="dep-directive"><span class="dep-d-name">${escapeHtml(name)}</span><code>${escapeHtml(sources.join(" "))}</code></div>`
        ).join("");

    // JS bundles
    const js = depMap.sources.jsBundles;
    $("#dep-js").innerHTML = js.bundlesFetched === 0
      ? `<p class="dns-empty">No external JavaScript bundles found.</p>`
      : `<p class="dep-meta">Scanned <strong>${js.bundlesFetched}</strong> bundle${js.bundlesFetched === 1 ? "" : "s"}, found <strong>${js.domains.length}</strong> domain${js.domains.length === 1 ? "" : "s"}.</p>` +
        (js.domains.length ? `<div class="dep-tag-list">${js.domains.map(d => `<span class="dep-tag">${escapeHtml(d)}</span>`).join("")}</div>` : "");

    // Cert Transparency
    const ct = depMap.sources.certTransparency;
    $("#dep-ct").innerHTML = ct.error
      ? `<p class="dns-empty">Error: ${escapeHtml(ct.error)}</p>`
      : ct.subdomains.length === 0
        ? `<p class="dns-empty">No subdomains found.</p>`
        : `<p class="dep-meta">Found <strong>${ct.total}</strong> subdomain${ct.total === 1 ? "" : "s"}.</p>` +
          `<div class="dep-tag-list">${ct.subdomains.slice(0, 30).map(s => `<span class="dep-tag">${escapeHtml(s)}</span>`).join("")}${ct.total > 30 ? `<span class="dep-tag dep-tag-more">+${ct.total - 30} more</span>` : ""}</div>`;

    // Domains table
    const domains = depMap.domains;
    $("#dep-map-domains").innerHTML = domains.length ? domains.map(d => {
      const svc = d.serviceName ? `<span class="dep-svc">${escapeHtml(d.serviceName)}</span>` : "";
      const flags = [
        d.piiRisk ? `<span class="dep-flag dep-flag-pii" title="Likely transmits PII">PII</span>` : "",
        d.postAuthOnly ? `<span class="dep-flag dep-flag-auth" title="Only visible after authentication">POST-AUTH</span>` : "",
      ].filter(Boolean).join("");
      return `<div class="dep-domain">
        <span class="dep-cat dep-cat-${escapeHtml(d.category)}">${escapeHtml(d.category)}</span>
        <span class="dep-host" title="${escapeAttr(d.evidence.join("; "))}">${escapeHtml(d.domain)}</span>
        ${svc}
        <span class="dep-src">${escapeHtml(d.source)}</span>
        ${flags}
      </div>`;
    }).join("") : `<p class="dns-empty">No external domains discovered.</p>`;

    // Takeover
    renderTakeover(depMap.takeover || []);
  }

  function renderSsl(ssl) {
    if (!ssl) {
      $("#dep-ssl").innerHTML = `<p class="dns-empty">SSL data unavailable.</p>`;
      return;
    }
    const expiry = ssl.daysUntilExpiry;
    const expiryClass = expiry === null ? "" : expiry < 0 ? "warn" : expiry < 30 ? "warn" : "good";
    const expiryText = expiry === null ? "Unknown" : expiry < 0 ? `EXPIRED ${Math.abs(expiry)}d ago` : `${expiry} days`;
    const rows = [
      ["Protocol", ssl.protocol || "Unknown"],
      ["Cipher", ssl.cipher || "Unknown"],
      ["Issuer", ssl.issuer || "Unknown"],
      ["Subject", ssl.subject || "Unknown"],
      ["Valid from", ssl.validFrom ? ssl.validFrom.slice(0, 10) : "Unknown"],
      ["Valid to", ssl.validTo ? ssl.validTo.slice(0, 10) : "Unknown"],
      ["Days to expiry", expiryText, expiryClass],
    ];
    $("#dep-ssl").innerHTML = `<div class="ssl-grid">${rows.map(([label, value, cls]) =>
      `<div class="ssl-row"><span class="ssl-label">${escapeHtml(label)}</span><span class="ssl-value ${cls || ""}">${escapeHtml(String(value))}</span></div>`
    ).join("")}</div>`;
  }

  function renderSdks(sdks) {
    const countEl = $("#sdk-count");
    countEl.textContent = sdks.length || "";
    countEl.classList.toggle("hidden", !sdks.length);
    if (!sdks.length) {
      $("#dep-sdks").innerHTML = `<p class="dns-empty">No known SDK initialisations detected in JavaScript bundles.</p>`;
      return;
    }
    $("#dep-sdks").innerHTML = `<div class="sdk-list">${sdks.map(s =>
      `<div class="sdk-item">
        <span class="dep-cat dep-cat-${escapeHtml(s.category)}">${escapeHtml(s.category)}</span>
        <span class="sdk-name">${escapeHtml(s.name)}</span>
        <span class="sdk-domain">${escapeHtml(s.domain)}</span>
      </div>`
    ).join("")}</div>`;
  }

  function renderTakeover(takeover) {
    const countEl = $("#takeover-count");
    const vulnerable = takeover.filter(t => t.vulnerable);
    countEl.textContent = vulnerable.length ? `${vulnerable.length} VULNERABLE` : (takeover.length || "");
    countEl.classList.toggle("hidden", !takeover.length);
    countEl.classList.toggle("cs-count-alert", vulnerable.length > 0);
    if (!takeover.length) {
      $("#dep-takeover").innerHTML = `<p class="dns-empty">No subdomains with vulnerable CNAME patterns found.</p>`;
      return;
    }
    $("#dep-takeover").innerHTML = takeover.map(t =>
      `<div class="takeover-row ${t.vulnerable ? "takeover-vuln" : ""}">
        <span class="takeover-status ${t.vulnerable ? "vuln" : "ok"}">${t.vulnerable ? "⚠ VULNERABLE" : "✓ OK"}</span>
        <div class="takeover-detail">
          <strong>${escapeHtml(t.subdomain)}</strong>
          <code>CNAME → ${escapeHtml(t.cname || "none")}</code>
          <span>${escapeHtml(t.evidence)}</span>
        </div>
      </div>`
    ).join("");
  }

  const initialId = location.hash.slice(1);
  if (/^[A-Za-z0-9_-]{16}$/.test(initialId)) loadReport(initialId);
})();
