import { useEffect, useMemo, useState } from "react";

import { AlertTable } from "@/components/AlertTable";
import { KpiCard } from "@/components/KpiCard";
import { TimelineBars } from "@/components/TimelineBars";
import { type Severity, useDashboardData } from "@/hooks/useDashboardData";

export default function DashboardHome() {
  const [isClient, setIsClient] = useState(false);
  const [severity, setSeverity] = useState<Severity>("all");
  const [host, setHost] = useState("all");
  const [ruleId, setRuleId] = useState("all");
  const [q, setQ] = useState("");

  useEffect(() => {
    setIsClient(true);
  }, []);

  const filters = useMemo(
    () => ({
      severity,
      host,
      ruleId,
      q,
      limit: 80,
    }),
    [severity, host, ruleId, q],
  );

  const { data, loading, error, reload } = useDashboardData(filters);
  const notableQueue = data.alerts.filter((item) => item.severity === "critical" || item.severity === "high").slice(0, 6);
  const topHostPressure = data.breakdown.byHost.slice(0, 5);
  const topAnalytic = data.breakdown.byRule[0];

  return (
    <main className="soc-shell">
      <aside className="soc-nav">
        <h1>AEGIS SOC</h1>
        <p>Security Operations Platform</p>
        <nav>
          <button type="button" className="nav-item active">Security Posture</button>
          <button type="button" className="nav-item">Incident Review</button>
          <button type="button" className="nav-item">Risk Analysis</button>
          <button type="button" className="nav-item">Asset Investigator</button>
          <button type="button" className="nav-item">Detections</button>
        </nav>
      </aside>

      <div className="soc-main">
        <header className="soc-topbar">
          <div className="search-strip">
            <label htmlFor="spl-input">Search Processing Language</label>
            <input
              id="spl-input"
              className="mono"
              value={q}
              onChange={(event) => setQ(event.target.value)}
              placeholder="index=security sourcetype=notable severity=high host=*"
            />
          </div>
          <div className="top-actions">
            <span className="stamp" suppressHydrationWarning>
              Generated {isClient ? new Date(data.generatedAt).toLocaleString() : "--"}
            </span>
            <button type="button" onClick={reload}>Run Search</button>
          </div>
        </header>

        <section className="hero">
          <div>
            <p className="eyebrow">Enterprise Security Console</p>
            <h2>SIEM Detection Command Deck</h2>
            <p className="subtitle">
              Splunk-style SOC workspace for triage, correlation, and notable event handling.
              Prioritize by urgency, pivot by host, and narrate the full investigation flow.
            </p>
          </div>
          <div className="hero-meta">
            <div>
              <p className="meta-label">Primary analytic</p>
              <p className="meta-value">{topAnalytic ? topAnalytic.ruleName : "N/A"}</p>
            </div>
            <div>
              <p className="meta-label">Current queue</p>
              <p className="meta-value">{notableQueue.length} high-priority events</p>
            </div>
          </div>
        </section>

        <section className="panel filter-panel">
          <div className="panel-head">
            <h2>Investigation Filters</h2>
            <span>Context narrowing</span>
          </div>
          <div className="filters-grid">
            <label>
              Severity
              <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity)}>
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>

            <label>
              Asset / Host
              <select value={host} onChange={(event) => setHost(event.target.value)}>
                <option value="all">All hosts</option>
                {data.filterOptions.hosts.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
            </label>

            <label>
              Correlation Search
              <select value={ruleId} onChange={(event) => setRuleId(event.target.value)}>
                <option value="all">All rules</option>
                {data.filterOptions.rules.map((rule) => (
                  <option key={rule.ruleId} value={rule.ruleId}>
                    {rule.ruleName}
                  </option>
                ))}
              </select>
            </label>

            <label>
              Analyst Notes Search
              <input
                value={q}
                onChange={(event) => setQ(event.target.value)}
                placeholder="rule id, summary, ip..."
              />
            </label>
          </div>
        </section>

        {error ? <p className="error">Dashboard error: {error}</p> : null}
        {loading ? <p className="loading">Loading dashboard feed...</p> : null}

        <section className="kpi-grid">
          <KpiCard title="Notable (24h)" value={data.kpis.totalAlerts24h} subtitle="Filtered scope" tone="neutral" />
          <KpiCard title="Open Incidents" value={data.kpis.openAlerts} subtitle="Open + Investigating" tone="alert" />
          <KpiCard title="Critical Queue" value={data.kpis.criticalAlerts} subtitle="Immediate action" tone="critical" />
          <KpiCard title="Assets Exposed" value={data.kpis.hostsImpacted} subtitle="Distinct assets" tone="neutral" />
          <KpiCard title="Risk Mean" value={data.kpis.meanRiskScore} subtitle="Risk score average" tone="alert" />
        </section>

        <div className="soc-grid">
          <section className="panel queue-panel">
            <div className="panel-head">
              <h2>Incident Queue</h2>
              <span>High and critical</span>
            </div>
            <ul className="queue-list">
              {notableQueue.map((entry) => (
                <li key={entry.id}>
                  <strong>{entry.ruleName}</strong>
                  <p>{entry.summary}</p>
                  <small className="mono">{entry.host} / {entry.sourceIp} / {entry.severity}</small>
                </li>
              ))}
            </ul>
          </section>

          <TimelineBars points={data.timeline} />

          <section className="panel breakdown-panel">
            <div className="panel-head">
              <h2>Top Correlation Searches</h2>
              <span>By notable volume</span>
            </div>
            <ul className="breakdown-list">
              {data.breakdown.byRule.slice(0, 8).map((entry) => (
                <li key={entry.ruleId}>
                  <div>
                    <p>{entry.ruleName}</p>
                    <small className="mono">{entry.ruleId}</small>
                  </div>
                  <strong>{entry.count}</strong>
                </li>
              ))}
            </ul>
          </section>

          <section className="panel host-panel">
            <div className="panel-head">
              <h2>Asset Risk Pressure</h2>
              <span>Top affected hosts</span>
            </div>
            <ul className="breakdown-list">
              {topHostPressure.map((entry) => (
                <li key={entry.host}>
                  <div>
                    <p>{entry.host}</p>
                    <small className="mono">asset</small>
                  </div>
                  <strong>{entry.count}</strong>
                </li>
              ))}
            </ul>
          </section>
        </div>

        <AlertTable alerts={data.alerts} />
      </div>
    </main>
  );
}
