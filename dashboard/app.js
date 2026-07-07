const state = {
  events: [],
  rules: [],
  alerts: [],
};

const els = {
  refresh: document.getElementById("refresh-button"),
  summaryState: document.getElementById("summary-state"),
  summaryGrid: document.getElementById("summary-grid"),
  eventsState: document.getElementById("events-state"),
  eventsWrap: document.getElementById("events-table-wrap"),
  eventsBody: document.getElementById("events-body"),
  eventDetail: document.getElementById("event-detail"),
  rulesState: document.getElementById("rules-state"),
  rulesList: document.getElementById("rules-list"),
  alertsState: document.getElementById("alerts-state"),
  alertsList: document.getElementById("alerts-list"),
};

els.refresh.addEventListener("click", () => {
  loadDashboard();
});

loadDashboard();

async function loadDashboard() {
  setLoading();
  const results = await Promise.allSettled([
    fetchJson("/summary"),
    fetchJson("/events"),
    fetchJson("/rules"),
    fetchJson("/alerts"),
  ]);

  renderSummary(results[0]);
  renderEvents(results[1]);
  renderRules(results[2]);
  renderAlerts(results[3]);
}

function setLoading() {
  showState(els.summaryState, "Loading summary...");
  showState(els.eventsState, "Loading events...");
  showState(els.rulesState, "Loading rules...");
  showState(els.alertsState, "Loading fixture alerts...");
  els.summaryGrid.hidden = true;
  els.eventsWrap.hidden = true;
  els.rulesList.hidden = true;
  els.alertsList.hidden = true;
}

async function fetchJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `Request failed: ${path}`);
  }
  return payload;
}

function renderSummary(result) {
  if (result.status === "rejected") {
    showState(els.summaryState, `Error loading summary: ${result.reason.message}`);
    return;
  }
  const payload = result.value;
  const counts = payload.data.counts || {};
  els.summaryGrid.replaceChildren(
    metricCard("Normalized events", counts.normalized_events ?? 0, "stored"),
    metricCard("Rules", counts.rules ?? 0, "metadata"),
    metricCard("Fixture alerts", counts.fixture_alerts ?? 0, "fixture")
  );
  appendWarnings(els.summaryGrid, payload.warnings);
  hideState(els.summaryState);
  els.summaryGrid.hidden = false;
}

function renderEvents(result) {
  if (result.status === "rejected") {
    showState(els.eventsState, `Error loading events: ${result.reason.message}`);
    return;
  }
  const payload = result.value;
  state.events = Array.isArray(payload.data) ? payload.data : [];
  els.eventsBody.replaceChildren();
  appendWarnings(els.eventsState, payload.warnings);
  if (state.events.length === 0) {
    showState(els.eventsState, "No stored normalized events found. Run the Phase 3B smoke check with ClickHouse available.");
    els.eventsWrap.hidden = true;
    return;
  }
  hideState(els.eventsState);
  state.events.forEach((event) => {
    const row = document.createElement("tr");
    row.append(
      cell(event.event_id, true, () => renderEventDetail(event)),
      cell(event.timestamp),
      cell(event.host),
      cell(event.source),
      cell(event.event_type),
      cell(event.severity)
    );
    els.eventsBody.append(row);
  });
  els.eventsWrap.hidden = false;
  renderEventDetail(state.events[0]);
}

function renderEventDetail(event) {
  const detail = document.createElement("div");
  detail.className = "detail";

  const title = document.createElement("h3");
  title.textContent = event.event_id || "Unknown event";
  detail.append(title);

  const meta = document.createElement("dl");
  meta.className = "meta-grid";
  addMeta(meta, "Timestamp", event.timestamp);
  addMeta(meta, "Host", event.host);
  addMeta(meta, "Source", event.source);
  addMeta(meta, "Type", event.event_type);
  addMeta(meta, "Severity", event.severity);
  detail.append(meta);

  const pre = document.createElement("pre");
  const code = document.createElement("code");
  code.textContent = JSON.stringify(event.normalized_event || event, null, 2);
  pre.append(code);
  detail.append(pre);

  els.eventDetail.replaceChildren(detail);
}

function renderRules(result) {
  if (result.status === "rejected") {
    showState(els.rulesState, `Error loading rules: ${result.reason.message}`);
    return;
  }
  const payload = result.value;
  state.rules = Array.isArray(payload.data) ? payload.data : [];
  els.rulesList.replaceChildren();
  if (state.rules.length === 0) {
    showState(els.rulesState, "No rule metadata files found.");
    return;
  }
  state.rules.forEach((rule) => {
    els.rulesList.append(itemCard({
      title: rule.name || rule.id,
      kicker: rule.id,
      fields: [
        ["Severity", rule.severity],
        ["Risk", rule.risk_score],
        ["MITRE", formatTechniques(rule.mitre)],
      ],
      badge: "metadata",
    }));
  });
  appendWarnings(els.rulesList, payload.warnings);
  hideState(els.rulesState);
  els.rulesList.hidden = false;
}

function renderAlerts(result) {
  if (result.status === "rejected") {
    showState(els.alertsState, `Error loading fixture alerts: ${result.reason.message}`);
    return;
  }
  const payload = result.value;
  state.alerts = Array.isArray(payload.data) ? payload.data : [];
  els.alertsList.replaceChildren();
  if (state.alerts.length === 0) {
    showState(els.alertsState, "No fixture alerts found under datasets/alerts.");
    return;
  }
  state.alerts.forEach((alert) => {
    els.alertsList.append(itemCard({
      title: alert.rule_name || alert.rule_id,
      kicker: alert.alert_id,
      fields: [
        ["Rule", alert.rule_id],
        ["Severity", alert.severity],
        ["Risk", alert.risk_score],
        ["MITRE", formatTechniques(alert.mitre)],
      ],
      badge: "fixture",
    }));
  });
  appendWarnings(els.alertsList, payload.warnings);
  hideState(els.alertsState);
  els.alertsList.hidden = false;
}

function metricCard(label, value, source) {
  const card = document.createElement("div");
  card.className = "metric-card";
  const valueEl = document.createElement("strong");
  valueEl.textContent = value;
  const labelEl = document.createElement("span");
  labelEl.textContent = label;
  const sourceEl = document.createElement("span");
  sourceEl.className = `source-label source-${source}`;
  sourceEl.textContent = source;
  card.append(valueEl, labelEl, sourceEl);
  return card;
}

function itemCard({ title, kicker, fields, badge }) {
  const card = document.createElement("article");
  card.className = "item-card";
  const head = document.createElement("div");
  head.className = "item-head";
  const titleWrap = document.createElement("div");
  const kickerEl = document.createElement("p");
  kickerEl.className = "kicker";
  kickerEl.textContent = kicker || "unknown";
  const titleEl = document.createElement("h3");
  titleEl.textContent = title || "Untitled";
  titleWrap.append(kickerEl, titleEl);
  const badgeEl = document.createElement("span");
  badgeEl.className = `source-label source-${badge}`;
  badgeEl.textContent = badge;
  head.append(titleWrap, badgeEl);

  const meta = document.createElement("dl");
  meta.className = "meta-grid";
  fields.forEach(([key, value]) => addMeta(meta, key, value));
  card.append(head, meta);
  return card;
}

function cell(value, asButton = false, onClick = null) {
  const td = document.createElement("td");
  if (asButton) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "link-button";
    button.textContent = value || "unknown";
    button.addEventListener("click", onClick);
    td.append(button);
    return td;
  }
  td.textContent = value ?? "unknown";
  return td;
}

function addMeta(parent, key, value) {
  const term = document.createElement("dt");
  term.textContent = key;
  const desc = document.createElement("dd");
  desc.textContent = value ?? "unknown";
  parent.append(term, desc);
}

function formatTechniques(mitre) {
  if (!mitre || !Array.isArray(mitre.techniques)) {
    return "none";
  }
  return mitre.techniques.join(", ");
}

function showState(element, message) {
  element.hidden = false;
  element.textContent = message;
}

function hideState(element) {
  element.hidden = true;
  element.textContent = "";
}

function appendWarnings(parent, warnings) {
  if (!Array.isArray(warnings) || warnings.length === 0) {
    return;
  }
  const warning = document.createElement("p");
  warning.className = "warning";
  warning.textContent = warnings.join(" ");
  parent.append(warning);
}
