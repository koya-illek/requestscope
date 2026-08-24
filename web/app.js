(() => {
  "use strict";

  const API_BASE = (window.REQUESTSCOPE_CONFIG?.API_BASE || "").replace(/\/$/, "");
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const state = { report: null, progressStep: 0, routeStep: 0, progressStages: [], rawUrl: null };

  const REPORT_ID_PATTERN = /^[A-Za-z0-9_-]{16}$/;
  const IDLE_TIMEOUT_MS = 45_000;
  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;

  let inFlight = false;
  let cancelRequested = false;
  let activeController = null;

  const form = $("#trace-form");
  const input = $("#url-input");
  const traceButton = $("#trace-button");
  const mapDepsCheckbox = $("#map-deps");
  const externalReputationCheckbox = $("#external-reputation");
  const claimedOrganisation = $("#claimed-organisation");
  const messageContext = $("#message-context");
  const progressPanel = $("#progress-panel");
  const errorPanel = $("#error-panel");
  const reportPanel = $("#report");
  const methodDialog = $("#method-dialog");
  const radarDialog = $("#radar-dialog");
  const linkDialog = $("#link-dialog");

  configureProviderAvailability();

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runTrace(input.value);
  });
  input.addEventListener("input", updateQueryWarning);
  [mapDepsCheckbox, externalReputationCheckbox].forEach((control) =>
    control?.addEventListener("change", updateAdvancedOptionState)
  );
  [claimedOrganisation, messageContext].forEach((control) =>
    control?.addEventListener("input", updateAdvancedOptionState)
  );
  updateAdvancedOptionState();
  $("#new-trace").addEventListener("click", () => reset());
  $("#error-close").addEventListener("click", () => {
    errorPanel.classList.add("hidden");
    const id = location.hash.slice(1);
    if (id && !REPORT_ID_PATTERN.test(id)) history.replaceState(state.historyState ?? null, "", location.pathname + location.search);
  });
  $("#error-new-trace").addEventListener("click", () => reset());
  $("#cancel-trace").addEventListener("click", () => {
    cancelRequested = true;
    activeController?.abort();
  });
  $("#copy-link").addEventListener("click", copyShareLink);
  $("#copy-markdown").addEventListener("click", copyReportMarkdown);
  $("#export-json").addEventListener("click", exportJson);
  $("#cloudflare-scan").addEventListener("click", openCloudflareScan);
  $("#radar-cancel").addEventListener("click", () => radarDialog.close());
  $("#radar-close").addEventListener("click", () => radarDialog.close());
  $("#radar-confirm").addEventListener("click", confirmRadarHandoff);
  radarDialog.addEventListener("click", (event) => {
    if (event.target === radarDialog) radarDialog.close();
  });
  $("#link-select").addEventListener("click", selectShareLink);
  $("#link-close").addEventListener("click", () => linkDialog.close());
  linkDialog.addEventListener("click", (event) => {
    if (event.target === linkDialog) linkDialog.close();
  });
  $("#method-button").addEventListener("click", () => methodDialog.showModal());
  $("#footer-method-button").addEventListener("click", () => methodDialog.showModal());
  $("#dialog-close").addEventListener("click", () => methodDialog.close());
  methodDialog.addEventListener("click", (event) => {
    if (event.target === methodDialog) methodDialog.close();
  });
  $$(".filter").forEach((button) => button.addEventListener("click", () => {
    $$(".filter").forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", String(active));
    });
    renderDependencies(button.dataset.filter);
  }));
  // Developer-tool convention: "/" jumps to the primary field from anywhere
  // that is not already text entry or an open dialog.
  window.addEventListener("keydown", (event) => {
    if (event.key !== "/" || event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return;
    const target = event.target;
    if (target instanceof HTMLElement && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
    if (methodDialog.open || radarDialog.open || linkDialog.open) return;
    event.preventDefault();
    input.focus();
  });
  window.addEventListener("hashchange", () => {
    if (inFlight) return;
    const id = location.hash.slice(1);
    if (REPORT_ID_PATTERN.test(id)) {
      if (state.report?.id !== id || reportPanel.classList.contains("hidden")) loadReport(id);
      return;
    }
    // The status pill, skip link, and section anchors all change the hash;
    // a hash that names an element on this page is navigation, not a broken
    // report link, so only unknown hashes surface the invalid-link notice.
    if (!id) {
      if (state.report) reset(false);
    } else if (!document.getElementById(id)) {
      showError("That report link looks incomplete or invalid.", "INVALID_LINK");
    }
  });

  function updateAdvancedOptionState() {
    const selected = Number(Boolean(mapDepsCheckbox?.checked))
      + Number(Boolean(externalReputationCheckbox?.checked))
      + Number(Boolean(claimedOrganisation?.value.trim() || messageContext?.value.trim()));
    $("#trace-options-state").textContent = selected ? `${selected} selected` : "Optional";
  }

  async function configureProviderAvailability() {
    try {
      const response = await fetch(`${API_BASE}/api/health`, { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const health = await response.json();
      const configured = Object.entries(health.reputationProviders || {}).filter(([, enabled]) => enabled).map(([name]) => name);
      if (configured.length === 0) {
        externalReputationCheckbox.disabled = true;
        $("#reputation-toggle-text strong").textContent = "External reputation unavailable";
        $("#reputation-toggle-text small").textContent = "Provider credentials are not configured on this deployment.";
      }
    } catch {
      // A health-check failure must not prevent the core trace UI from loading,
      // but the status pill should stop claiming readiness.
      $(".status-link").classList.add("degraded");
      $("#status-text").textContent = "Observer status unavailable";
    }
  }

  async function runTrace(url) {
    if (inFlight || !url.trim()) return;
    inFlight = true;
    cancelRequested = false;
    state.rawUrl = url.trim();
    beginProgress();
    errorPanel.classList.add("hidden");
    reportPanel.classList.add("hidden");
    $("#dep-map-panel").classList.add("hidden");
    traceButton.disabled = true;
    const controller = new AbortController();
    activeController = controller;
    let idleTimedOut = false;
    let idleTimer = 0;
    const armIdleTimer = () => {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        idleTimedOut = true;
        controller.abort();
      }, IDLE_TIMEOUT_MS);
    };
    armIdleTimer();
    try {
      const response = await fetch(`${API_BASE}/api/scans/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          url: url.trim(),
          mapDependencies: mapDepsCheckbox.checked,
          externalReputation: externalReputationCheckbox.checked,
          claimedOrganisation: claimedOrganisation.value.trim() || undefined,
          messageContext: messageContext.value.trim() || undefined
        })
      });
      if (!response.ok || !response.body) {
        // The boundary rejects invalid targets and exhausted quotas with a
        // JSON body before any byte streams; show that copy instead of a
        // bare HTTP status.
        let message = `Trace failed with HTTP ${response.status}`;
        try {
          const payload = await response.json();
          if (payload && typeof payload.error === "string") message = payload.error;
        } catch {
          // Non-JSON error body; keep the generic HTTP message.
        }
        throw Object.assign(new Error(message), { errorCode: response.status === 429 ? "RATE_LIMITED" : "TRACE_FAILED" });
      }
      const payload = await readTraceStream(response, armIdleTimer);
      finishProgress();
      displayReport(payload, true);
    } catch (error) {
      stopProgress();
      if (error.name === "AbortError") {
        showError(cancelRequested
          ? "Trace cancelled."
          : "The trace stalled with no updates for 45 seconds and was cancelled. Please try again.");
      } else if (error instanceof TypeError) {
        showError("Network request failed. Check your connection and try again.");
      } else {
        showError(error.message || "The trace could not be completed.", error.errorCode);
      }
    } finally {
      clearTimeout(idleTimer);
      activeController = null;
      inFlight = false;
      traceButton.disabled = false;
    }
  }

  async function loadReport(id) {
    if (inFlight) return;
    inFlight = true;
    cancelRequested = false;
    state.rawUrl = null;
    // The submit control must agree with the inFlight guard: runTrace bails
    // silently while a load is active, so leaving the button enabled would
    // turn a press into an invisible no-op.
    traceButton.disabled = true;
    beginProgress("Loading saved report", true);
    errorPanel.classList.add("hidden");
    const controller = new AbortController();
    activeController = controller;
    let idleTimedOut = false;
    let idleTimer = 0;
    const armIdleTimer = () => {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        idleTimedOut = true;
        controller.abort();
      }, IDLE_TIMEOUT_MS);
    };
    armIdleTimer();
    try {
      const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(id)}`, { signal: controller.signal });
      armIdleTimer();
      if (!response.ok) {
        let message = `Saved report could not be loaded (HTTP ${response.status}).`;
        try {
          const payload = await response.json();
          if (payload && typeof payload.error === "string") message = payload.error;
        } catch {
          // Non-JSON error body; keep the generic HTTP message.
        }
        throw new Error(message);
      }
      const payload = await response.json().catch(() => {
        throw new Error("Received an invalid response from the server.");
      });
      finishProgress();
      displayReport(payload, false);
    } catch (error) {
      stopProgress();
      if (error.name === "AbortError") {
        showError(cancelRequested
          ? "Loading cancelled."
          : idleTimedOut
            ? "Loading the saved report stalled with no updates for 45 seconds and was cancelled. Please try again."
            : "Loading the saved report timed out. Please try again.");
      } else if (error instanceof TypeError) {
        showError("Network request failed. Check your connection and try again.");
      } else {
        showError(error.message || "Saved report could not be loaded.");
      }
    } finally {
      clearTimeout(idleTimer);
      activeController = null;
      inFlight = false;
      traceButton.disabled = false;
    }
  }

  function beginProgress(title = "Tracing request path", minimal = false) {
    state.progressStep = 0;
    state.routeStep = 0;
    progressPanel.classList.toggle("minimal", minimal);
    if (minimal) {
      state.progressStages = [];
      $("#progress-steps").innerHTML = "";
    } else {
      state.progressStages = [
        { key: "input", label: "Validate target" },
        { key: "dns", label: "Resolve DNS" },
        { key: "edge", label: "Follow redirects" },
        { key: "page", label: "Inspect page" },
        ...(mapDepsCheckbox.checked ? [{ key: "deps", label: "Map dependencies" }] : []),
        ...(externalReputationCheckbox.checked ? [{ key: "reputation", label: "Check reputation" }] : []),
        { key: "report", label: "Build report" }
      ];
      $("#progress-steps").innerHTML = state.progressStages.map((step) => `<li>${escapeHtml(step.label)}</li>`).join("");
    }
    $("#progress-title").textContent = title;
    progressPanel.classList.remove("hidden");
    $("#progress-bar").style.width = minimal ? "40%" : "8%";
    updateProgressSteps();
    scrollToEl(progressPanel);
  }

  function updateProgressSteps() {
    $$("#progress-steps li").forEach((item, index) => {
      item.classList.toggle("active", index === state.progressStep);
      item.classList.toggle("done", index < state.progressStep);
    });
    $$("#live-route .route-node").forEach((item, index) => {
      const skipped = (item.dataset.optional === "dependencies" && !mapDepsCheckbox.checked)
        || (item.dataset.optional === "reputation" && !externalReputationCheckbox.checked);
      item.classList.toggle("skipped", skipped);
      item.classList.toggle("active", !skipped && index === state.routeStep);
      item.classList.toggle("done", !skipped && index < state.routeStep);
    });
    $$("#live-route .route-wire").forEach((item, index) => {
      item.classList.toggle("active", index === state.routeStep - 1 || (state.routeStep === 0 && index === 0));
      item.classList.toggle("done", index < state.routeStep - 1);
    });
  }

  function finishProgress() {
    state.progressStep = Math.max(0, state.progressStages.length - 1);
    state.routeStep = 6;
    updateProgressSteps();
    $("#progress-bar").style.width = "100%";
    setTimeout(() => progressPanel.classList.add("hidden"), 250);
  }

  function stopProgress() {
    progressPanel.classList.add("hidden");
  }

  function showError(message, code = "TRACE_FAILED") {
    $("#error-code").textContent = code;
    $("#error-message").textContent = message;
    errorPanel.classList.remove("hidden");
    $("#error-title").focus({ preventScroll: true });
    scrollToEl(errorPanel);
  }

  function displayReport(report, updateLocation) {
    state.report = report;
    $("#report-host").textContent = report.hostname;
    $("#report-url").textContent = report.finalUrl || report.normalizedUrl;
    const reportHref = safeHref(report.finalUrl || report.normalizedUrl);
    if (reportHref) {
      $("#report-url").href = reportHref;
    } else {
      $("#report-url").removeAttribute("href");
    }
    const vantage = [report.observation.colo, report.observation.country].filter(Boolean).join(", ");
    const coverage = report.coverage;
    const coverageText = coverage
      ? ` Coverage: core ${coverage.phases.core.status}, dependency map ${coverage.phases.dependencies.status}, reputation ${coverage.phases.reputation.status}.`
      : "";
    $("#observation-note").textContent = `${report.observation.disclaimer}${vantage ? ` This trace executed through ${vantage}.` : ""}${coverageText}`;
    const storedUntil = storedUntilText(report.expiresAt);
    const storedNote = $("#report-stored");
    // A share recipient must know how long the evidence stays retrievable
    // instead of discovering it through a 404 after expiry.
    if (storedUntil) {
      storedNote.textContent = `Stored until ${storedUntil}, then deleted automatically.`;
      storedNote.classList.remove("hidden");
    } else {
      storedNote.classList.add("hidden");
    }
    renderMetrics(report);
    renderUrlRisk(report.urlRisk);
    renderTimeline(report.http.hops);
    renderDns(report.dns.queries);
    renderFindings(report.findings);
    renderDependencySummary(report.dependencies);
    renderDependencies("all");
    $$(".filter").forEach((item) => {
      const active = item.dataset.filter === "all";
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", String(active));
    });
    renderDepMap(report.dependencyMap);
    reportPanel.classList.remove("hidden");
    $("#report-host").focus({ preventScroll: true });
    if (updateLocation) {
      history.pushState({ reportId: report.id }, "", `#${report.id}`);
      state.historyState = { reportId: report.id };
    }
    document.title = `${report.hostname}: RequestScope`;
    setTimeout(() => scrollToEl(reportPanel, "start"), 280);
  }

  function renderMetrics(report) {
    const finalStatus = report.http.finalStatus ?? "Unavailable";
    const statusClass = Number(finalStatus) >= 200 && Number(finalStatus) < 400 ? "good" : "warn";
    const redirectCount = report.http.hops.filter((hop) => [301, 302, 303, 307, 308].includes(hop.status) && hop.location).length;
    const metrics = [
      ["Final status", finalStatus, statusClass],
      ["Total trace time", formatMs(report.totalDurationMs), ""],
      ["Redirects", redirectCount, redirectCount <= 2 ? "good" : "warn"],
      ["DNS addresses", report.dns.addresses.length, report.dns.addresses.length ? "good" : "warn"],
      ["HTML references", report.dependencies.total, ""]
    ];
    $("#metrics").innerHTML = metrics.map(([label, value, cls]) =>
      `<div class="metric"><small>${escapeHtml(label)}</small><strong class="${cls}">${escapeHtml(String(value))}</strong></div>`
    ).join("");
  }

  function renderUrlRisk(risk) {
    const panel = $("#risk-panel");
    if (!risk) {
      panel.classList.add("hidden");
      return;
    }
    panel.classList.remove("hidden");
    const verdict = $("#risk-verdict");
    verdict.textContent = `${String(risk.verdict).toUpperCase()} · ${risk.riskScore}/100`;
    verdict.className = `risk-verdict ${enumToken(risk.verdict, ["low", "medium", "high"])}`;
    $("#risk-summary").innerHTML = `<strong>${escapeHtml(risk.summary)}</strong><span>${escapeHtml(risk.confidence)} confidence · ${risk.findings.length} evidence item${risk.findings.length === 1 ? "" : "s"}</span>`;
    renderReputation(risk.reputation);
    $("#risk-findings").innerHTML = risk.findings.length
      ? risk.findings.map((item) => `<article class="risk-finding ${enumToken(item.severity, ["low", "medium", "high"])}">
          <span>${escapeHtml(String(item.severity).toUpperCase())}</span>
          <div><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.detail)}</p><code>${escapeHtml(item.code)} · ${escapeHtml(item.source)} · +${Number(item.score) || 0}</code></div>
        </article>`).join("")
      : `<p class="dns-empty">No strong risk indicators were observed.</p>`;
    $("#risk-boundary").textContent = risk.limitations.join(" ");
  }

  function renderReputation(reputation) {
    const target = $("#reputation-results");
    if (!reputation) {
      target.innerHTML = "";
      return;
    }
    const providers = reputation.providers || [];
    target.innerHTML = `<div class="reputation-head"><strong>External reputation</strong><span class="reputation-status ${enumToken(reputation.status, ["matched", "not_listed", "partial", "unavailable", "not_configured", "not_requested"])}">${escapeHtml(String(reputation.status).replaceAll("_", " ").toUpperCase())}</span></div>
      <p>${escapeHtml(reputation.detail)}</p>` + (providers.length
        ? `<div class="provider-list">${providers.map((provider) => `<article class="provider-result ${enumToken(provider.status, ["matched", "not_listed", "inconclusive", "unavailable", "quota_limited", "not_configured"])}">
            <div><strong>${escapeHtml(providerName(provider.provider))}</strong><span>${escapeHtml(provider.target)} · ${escapeHtml(provider.hostname)}</span></div>
            <p>${escapeHtml(provider.detail)}</p>
            ${provider.status === "matched" && safeHref(provider.advisoryUrl) ? `<a href="${escapeAttr(provider.advisoryUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(provider.attribution)}</a>` : ""}
          </article>`).join("")}</div>`
        : "");
  }

  function providerName(provider) {
    if (provider === "google_web_risk") return "Google Web Risk";
    if (provider === "cloudflare_family_dns") return "Cloudflare malware-filtering DNS";
    if (provider === "phishtank") return "PhishTank";
    return "External reputation provider";
  }

  function renderTimeline(hops) {
    // The replay stagger is applied through CSSOM rather than a style
    // attribute so the production CSP can forbid inline styles entirely.
    $("#timeline").innerHTML = hops.map((hop) => {
      const codeClass = hop.status === 0 || hop.status >= 400 ? "error" : hop.status >= 300 ? "redirect" : "";
      const details = [
        hop.cf?.httpProtocol,
        hop.cf?.tlsVersion,
        hop.cf?.colo ? `PoP ${hop.cf.colo}` : null,
        hop.error
      ].filter(Boolean);
      return `<article class="hop replay">
        <span class="hop-index">${String(hop.index + 1).padStart(2, "0")}</span>
        <div class="hop-main">
          <strong title="${escapeAttr(hop.url)}">${escapeHtml(hop.url)}</strong>
          <div class="hop-detail">${details.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>
          ${renderHopHeaders(hop.responseHeaders)}
        </div>
        <div class="hop-status">
          <span class="status-code ${codeClass}">${Number.isFinite(hop.status) && hop.status !== 0 ? hop.status : "ERR"}</span>
          <span class="elapsed">${formatMs(hop.elapsedMs)}</span>
        </div>
      </article>`;
    }).join("");
    $$("#timeline .hop.replay").forEach((element) => {
      const index = Number(element.querySelector(".hop-index")?.textContent) - 1;
      element.style.animationDelay = `${Math.min(Math.max(0, index) * 130, 780)}ms`;
    });
  }

  /** The findings cite evidence paths like
   * http.hops.1.responseHeaders.cache-control; this is where that evidence
   * becomes visible. Values are already redacted server-side before storage. */
  function renderHopHeaders(headers) {
    const entries = Object.entries(headers || {});
    if (!entries.length) return "";
    return `<details class="hop-evidence">
      <summary>Response headers <span>${entries.length} recorded</span></summary>
      <dl class="hop-header-list">
        ${entries.map(([name, value]) => `<div class="hop-header"><dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}
      </dl>
    </details>`;
  }

  function renderDns(queries) {
    $("#dns-results").innerHTML = queries.map((query) => {
      const answers = query.answers.length
        ? query.answers.map((answer) => `<div class="dns-answer"><span>${escapeHtml(answer.type)}</span><code>${escapeHtml(answer.data)}</code><span>${Number(answer.ttl) || 0}s</span></div>`).join("")
        : `<div class="dns-empty">${escapeHtml(query.error || (query.status === 0 ? "No records returned" : `DNS status ${query.status}`))}</div>`;
      return `<div class="dns-group">
        <div class="dns-title"><strong>${escapeHtml(query.type)} · ${escapeHtml(query.name)}</strong><span>${Number(query.elapsedMs) || 0}ms${query.authenticatedData ? " · DNSSEC AD" : ""}</span></div>
        ${answers}
      </div>`;
    }).join("");
  }

  function renderFindings(findings) {
    $("#findings").innerHTML = findings.length ? findings.map((item) => `<article class="finding ${enumToken(item.severity, ["info", "positive", "warning", "critical"])}">
      <span class="finding-dot" aria-hidden="true"></span>
      <span class="visually-hidden">${escapeHtml(item.severity)}</span>
      <div><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.detail)}</p><code>${escapeHtml(item.evidencePath)} · ${escapeHtml(item.confidence)} confidence</code></div>
    </article>`).join("") : `<div class="dns-group"><p class="dns-empty">No derived findings were generated.</p></div>`;
  }

  function renderDependencySummary(dependencies) {
    $("#dependency-summary").innerHTML = `
      <span><strong>${Number(dependencies.total) || 0}</strong> HTML references</span>
      <span><strong>${Number(dependencies.firstParty) || 0}</strong> first-party</span>
      <span><strong>${Number(dependencies.thirdParty) || 0}</strong> third-party</span>
      <span><strong>${dependencies.uniqueHosts.length}</strong> hosts</span>`;
  }

  function renderDependencies(filter = "all") {
    if (!state.report) return;
    const items = state.report.dependencies.items.filter((item) => filter === "all" || item.party === filter);
    $("#dependencies").innerHTML = items.length ? items.map((item) => {
      const href = safeHref(item.url);
      const url = href
        ? `<a href="${escapeAttr(item.url)}" target="_blank" rel="noopener noreferrer" title="${escapeAttr(item.url)}">${escapeHtml(item.url)}</a>`
        : `<span title="${escapeAttr(item.url)}">${escapeHtml(item.url)}</span>`;
      return `<div class="dependency">
        <span class="type">${escapeHtml(item.type)}</span>
        ${url}
        <span class="party">${escapeHtml(item.party)}</span>
      </div>`;
    }).join("") : `<div class="dns-group"><p class="dns-empty">No matching resource references were extracted from the inspected HTML.</p></div>`;
  }

  async function copyShareLink() {
    if (!state.report) return;
    const link = `${location.origin}${location.pathname}#${state.report.id}`;
    try {
      await navigator.clipboard.writeText(link);
      flashButton($("#copy-link"), "Copied");
    } catch {
      // Clipboard permission or focus rules blocked the write; the link
      // becomes a designed, selectable surface instead of a blocking prompt.
      openManualCopyDialog({
        title: "Copy this report link",
        description: "Automatic copying was blocked by the browser. Select the link below and copy it manually.",
        fieldLabel: "Share link",
        value: link,
      });
    }
  }

  async function copyReportMarkdown() {
    if (!state.report) return;
    const markdown = buildReportMarkdown(state.report);
    try {
      await navigator.clipboard.writeText(markdown);
      flashButton($("#copy-markdown"), "Copied");
    } catch {
      openManualCopyDialog({
        title: "Copy this report as Markdown",
        description: "Automatic copying was blocked by the browser. Select the markdown below and copy it manually.",
        fieldLabel: "Markdown report",
        value: markdown,
      });
    }
  }

  /** One selectable fallback surface for every clipboard flow; the labels are
   * rewritten per call so the dialog never misdescribes its contents. The
   * field is a textarea because input values strip line breaks, which would
   * silently corrupt a markdown report. */
  function openManualCopyDialog({ title, description, fieldLabel, value }) {
    $("#link-dialog-title").textContent = title;
    $("#link-dialog-copy").textContent = description;
    $("#link-dialog-label").textContent = fieldLabel;
    const field = $("#link-field");
    field.value = value;
    linkDialog.showModal();
    selectShareLink();
  }

  /** A paste-ready evidence brief for tickets and AI chats, rendered from the
   * same redacted report the UI shows; nothing here is fetched or decrypted
   * beyond what the server already stored. */
  function buildReportMarkdown(report) {
    const lines = [`# RequestScope report: ${report.hostname}`, ""];
    const risk = report.urlRisk;
    if (risk) {
      lines.push(
        `**Verdict:** ${String(risk.verdict).toUpperCase()} · ${risk.riskScore}/100 (${risk.confidence} confidence)`,
        "",
        risk.summary,
        ""
      );
      if (risk.findings.length) {
        lines.push("## Risk evidence", "");
        for (const item of risk.findings) {
          lines.push(`- **${String(item.severity).toUpperCase()}** ${item.title} (+${Number(item.score) || 0})`);
          lines.push(`  ${item.detail}`);
        }
        lines.push("");
      }
      if (risk.reputation?.providers?.length) {
        lines.push("## External reputation", "");
        for (const provider of risk.reputation.providers) {
          lines.push(`- **${providerName(provider.provider)}** (${provider.target} URL): ${String(provider.status).replaceAll("_", " ")}`);
          lines.push(`  ${provider.detail}`);
        }
        lines.push("");
      }
    }
    lines.push("## Request path", "");
    report.http.hops.forEach((hop, index) => {
      const status = Number.isFinite(hop.status) && hop.status !== 0 ? hop.status : "ERR";
      lines.push(`${index + 1}. HTTP ${status} ${hop.url}${hop.location ? ` -> ${hop.location}` : ""} (${formatMs(hop.elapsedMs)})`);
    });
    lines.push("");
    if (report.dns.queries.length) {
      lines.push("## DNS observations", "");
      for (const query of report.dns.queries) {
        for (const answer of query.answers) {
          lines.push(`- ${answer.type} ${query.name} -> ${answer.data} (TTL ${Number(answer.ttl) || 0}s)`);
        }
        if (!query.answers.length) lines.push(`- ${query.type} ${query.name}: ${query.error || `DNS status ${query.status}`}`);
      }
      lines.push("");
    }
    if (report.findings.length) {
      lines.push("## Derived findings", "");
      for (const item of report.findings) {
        lines.push(`- **${String(item.severity).toUpperCase()}** ${item.title}`);
        lines.push(`  ${item.detail} (evidence: ${item.evidencePath})`);
      }
      lines.push("");
    }
    const deps = report.dependencies;
    lines.push(
      "## Page dependencies",
      "",
      `${deps.total} HTML references: ${deps.firstParty} first-party, ${deps.thirdParty} third-party across ${deps.uniqueHosts.length} hosts.`,
      ""
    );
    if (deps.uniqueHosts.length) {
      lines.push(`Hosts: ${deps.uniqueHosts.slice(0, 15).join(", ")}${deps.uniqueHosts.length > 15 ? ", …" : ""}`, "");
    }
    if (report.coverage) {
      const phases = report.coverage.phases;
      lines.push(
        "## Coverage",
        "",
        `- core trace: ${phases.core.status}`,
        `- dependency map: ${phases.dependencies.status}`,
        `- reputation: ${phases.reputation.status}`,
        ""
      );
    }
    lines.push(
      "---",
      "",
      `Full evidence: ${location.origin}${location.pathname}#${report.id}`
    );
    const storedUntil = storedUntilText(report.expiresAt);
    if (storedUntil) lines.push(`Stored until ${storedUntil}, then deleted automatically.`);
    lines.push(
      "Timings are Cloudflare edge observations, not browser measurements.",
      "A low risk verdict does not certify that a URL is safe."
    );
    return lines.join("\n");
  }

  function selectShareLink() {
    const field = $("#link-field");
    field.focus();
    field.select();
  }

  function exportJson() {
    if (!state.report) return;
    flashButton($("#export-json"), "Export started");
    const anchor = document.createElement("a");
    anchor.href = `${API_BASE}/api/scans/${encodeURIComponent(state.report.id)}/export`;
    anchor.download = `requestscope-${state.report.id}.json`;
    anchor.click();
  }

  function openCloudflareScan() {
    if (!state.report) return;
    state.radarUrl = state.rawUrl || state.report.finalUrl || state.report.normalizedUrl;
    radarDialog.showModal();
  }

  function confirmRadarHandoff() {
    const target = state.radarUrl;
    state.radarUrl = null;
    radarDialog.close();
    if (target) window.open(`https://radar.cloudflare.com/scan?url=${encodeURIComponent(target)}`, "_blank", "noopener,noreferrer");
  }

  function reset(pushHistory = true) {
    state.report = null;
    state.rawUrl = null;
    reportPanel.classList.add("hidden");
    errorPanel.classList.add("hidden");
    $("#dep-map-panel").classList.add("hidden");
    if (pushHistory) history.pushState({}, "", location.pathname);
    document.title = "RequestScope: See the journey behind a URL";
    input.value = "";
    claimedOrganisation.value = "";
    messageContext.value = "";
    mapDepsCheckbox.checked = false;
    externalReputationCheckbox.checked = false;
    updateAdvancedOptionState();
    updateQueryWarning();
    input.focus();
    scrollToEl(document.body, "start");
  }

  function flashButton(button, text) {
    if (!button.dataset.label) button.dataset.label = button.textContent;
    button.textContent = text;
    clearTimeout(Number(button.dataset.timer || 0));
    button.dataset.timer = String(setTimeout(() => {
      button.textContent = button.dataset.label;
      delete button.dataset.label;
      delete button.dataset.timer;
    }, 1400));
  }

  function formatMs(value) {
    const milliseconds = Number(value) || 0;
    return milliseconds >= 1000 ? `${(milliseconds / 1000).toFixed(2)}s` : `${milliseconds}ms`;
  }

  /** The viewer-facing storage date for a report's expiry timestamp, or null
   * when the field is missing or unparseable. */
  function storedUntilText(value) {
    const expiry = Date.parse(String(value ?? ""));
    if (!Number.isFinite(expiry)) return null;
    return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(expiry);
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/`/g, "&#96;");
  }

  /** Only http(s) URLs become links: dependency URLs come from inspected
   * third-party pages, so schemes like javascript: must never render. */
  function safeHref(value) {
    const candidate = String(value ?? "").trim();
    return /^https?:\/\//i.test(candidate) ? candidate : null;
  }

  /** Server-computed enums drive CSS classes; map anything unexpected to a
   * harmless token instead of interpolating it into markup. */
  function enumToken(value, allowed) {
    return allowed.includes(value) ? value : "unknown";
  }

  function scrollToEl(element, block = "center") {
    element.scrollIntoView({ behavior: prefersReducedMotion ? "auto" : "smooth", block });
  }

  async function readTraceStream(response, onActivity = () => {}) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let report = null;
    while (true) {
      const { done, value } = await reader.read();
      onActivity();
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines) {
        if (!line.trim()) continue;
        let event;
        try {
          event = JSON.parse(line);
        } catch {
          throw new Error("Received an invalid response from the server.");
        }
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
    const stageKey = event.stage.startsWith("deps-") ? "deps" : ({
      accepted: "input", validated: "input", dns: "dns", hop: "edge",
      response: "page", reputation: "reputation", complete: "report"
    })[event.stage];
    const progressIndex = state.progressStages.findIndex((step) => step.key === stageKey);
    if (progressIndex >= 0) state.progressStep = progressIndex;
    const routeIndex = ["input", "dns", "edge", "page", "deps", "reputation", "report"].indexOf(stageKey);
    if (routeIndex >= 0) state.routeStep = routeIndex;
    $("#progress-title").textContent = event.message || "Tracing request path";
    const finalStep = Math.max(1, state.progressStages.length - 1);
    $("#progress-bar").style.width = `${8 + (state.progressStep / finalStep) * 85}%`;
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
      ["Possible data-bearing services", depMap.summary.piiRisk, depMap.summary.piiRisk > 0 ? "warn" : "good"],
      ["Not observed in initial HTML", depMap.summary.postAuthOnly, ""],
      ["Analytics", cats.analytics || 0, ""],
      ["Advertising", cats.advertising || 0, ""],
      ["Payment", cats.payment || 0, ""],
      ["Communication", cats.communication || 0, ""],
    ].map(([label, value, cls]) =>
      `<span><strong class="${cls}">${escapeHtml(String(value))}</strong> ${escapeHtml(label)}</span>`
    ).join("");

    // Certificate Transparency history, not a live TLS handshake
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
      ? `<p class="dns-empty">No external JavaScript bundles were inspected. The phase may have been skipped by the request budget.</p>`
      : `<p class="dep-meta">Inspected <strong>${js.successful ?? js.bundlesFetched}</strong> of <strong>${js.attempted ?? js.bundlesFetched}</strong> bundle${(js.attempted ?? js.bundlesFetched) === 1 ? "" : "s"}, found <strong>${js.domains.length}</strong> domain${js.domains.length === 1 ? "" : "s"}. ${js.truncated ? "Inspection was truncated." : ""}</p>` +
        (js.domains.length ? `<div class="dep-tag-list">${js.domains.map(d => `<span class="dep-tag">${escapeHtml(d)}</span>`).join("")}</div>` : "");

    // Cert Transparency
    const ct = depMap.sources.certTransparency;
    $("#dep-ct").innerHTML = ct.error
      ? `<p class="dns-empty">Error: ${escapeHtml(ct.error)}</p>`
      : ct.subdomains.length === 0
        ? `<p class="dns-empty">No subdomains found.</p>`
        : `<p class="dep-meta">Found <strong>${ct.total}</strong> historical certificate name${ct.total === 1 ? "" : "s"}. This is Certificate Transparency history, not proof of a live service.</p>` +
          `<div class="dep-tag-list">${ct.subdomains.slice(0, 30).map(s => `<span class="dep-tag">${escapeHtml(s)}</span>`).join("")}${ct.total > 30 ? `<span class="dep-tag dep-tag-more">+${ct.total - 30} more</span>` : ""}</div>`;

    // Domains table
    const domains = depMap.domains;
    $("#dep-map-domains").innerHTML = domains.length ? domains.map(d => {
      const svc = d.serviceName ? `<span class="dep-svc">${escapeHtml(d.serviceName)}</span>` : "";
      const flags = [
        d.piiRisk ? `<span class="dep-flag dep-flag-pii" title="Hostname category suggests a possible data-bearing service">POSSIBLE DATA</span>` : "",
        d.postAuthOnly ? `<span class="dep-flag dep-flag-auth" title="Not observed in the initial HTML; dynamic visibility was not measured">NOT IN INITIAL HTML</span>` : "",
      ].filter(Boolean).join("");
      return `<div class="dep-domain">
        <span class="dep-cat dep-cat-${enumToken(d.category, DEP_CATEGORIES)}">${escapeHtml(d.category)}</span>
        <span class="dep-host" title="${escapeAttr(d.evidence.join("; "))}">${escapeHtml(d.domain)}</span>
        ${svc}
        <span class="dep-src">${escapeHtml(d.source)}</span>
        ${flags}
      </div>`;
    }).join("") : `<p class="dns-empty">No external domains discovered.</p>`;

    // Takeover
    renderTakeover(depMap.takeover || []);
  }

  const DEP_CATEGORIES = [
    "functional", "analytics", "advertising", "cdn", "payment", "communication",
    "monitoring", "security", "marketing", "social", "testing", "video",
    "auth", "consent", "hosting", "unknown"
  ];

  function renderSsl(ssl) {
    if (!ssl) {
      $("#dep-ssl").innerHTML = `<p class="dns-empty">Certificate Transparency history unavailable.</p>`;
      return;
    }
    const rows = [
      ["Source", "Certificate Transparency"],
      ["Historical first seen", ssl.validFrom ? ssl.validFrom.slice(0, 10) : "Unknown"],
      ["Historical last seen", ssl.validTo ? ssl.validTo.slice(0, 10) : "Unknown"],
      ["Live protocol", "Not measured"],
      ["Live issuer", "Not measured"],
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
        <span class="dep-cat dep-cat-${enumToken(s.category, DEP_CATEGORIES)}">${escapeHtml(s.category)}</span>
        <span class="sdk-name">${escapeHtml(s.name)}</span>
        <span class="sdk-domain">${escapeHtml(s.domain)}</span>
      </div>`
    ).join("")}</div>`;
  }

  function renderTakeover(takeover) {
    const countEl = $("#takeover-count");
    const vulnerable = takeover.filter(t => t.vulnerable);
    countEl.textContent = vulnerable.length ? `${vulnerable.length} POTENTIAL` : (takeover.length || "");
    countEl.classList.toggle("hidden", !takeover.length);
    countEl.classList.toggle("cs-count-alert", vulnerable.length > 0);
    if (!takeover.length) {
      $("#dep-takeover").innerHTML = `<p class="dns-empty">No subdomains with vulnerable CNAME patterns found.</p>`;
      return;
    }
    $("#dep-takeover").innerHTML = takeover.map(t =>
      `<div class="takeover-row ${t.vulnerable ? "takeover-vuln" : ""}">
        <span class="takeover-status ${t.vulnerable ? "vuln" : "ok"}">${t.vulnerable ? "⚠ POTENTIAL" : "✓ NO SIGNATURE"}</span>
        <div class="takeover-detail">
          <strong>${escapeHtml(t.subdomain)}</strong>
          <code>CNAME → ${escapeHtml(t.cname || "none")}</code>
          <span>${escapeHtml(t.evidence)}</span>
        </div>
      </div>`
    ).join("");
  }

  const initialId = location.hash.slice(1);
  if (REPORT_ID_PATTERN.test(initialId)) {
    loadReport(initialId);
  } else if (initialId && !document.getElementById(initialId)) {
    showError("That report link looks incomplete or invalid.", "INVALID_LINK");
  }
})();
