import { useEffect, useLayoutEffect, useRef } from "react";

import type { DemoAlert } from "@/hooks/useDashboardData";

type Props = {
  alerts: DemoAlert[];
};

function severityClass(severity: DemoAlert["severity"]) {
  if (severity === "critical") return "sev-critical";
  if (severity === "high") return "sev-high";
  if (severity === "medium") return "sev-medium";
  return "sev-low";
}

function statusClass(status: DemoAlert["status"]) {
  if (status === "open") return "status-open";
  if (status === "investigating") return "status-investigating";
  return "status-closed";
}

export function AlertTable({ alerts }: Props) {
  const tableScrollTopRef = useRef(0);
  const tableWrapRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const node = tableWrapRef.current;
    if (!node) return;

    const onScroll = () => {
      tableScrollTopRef.current = node.scrollTop;
    };

    onScroll();
    node.addEventListener("scroll", onScroll, { passive: true });
    return () => node.removeEventListener("scroll", onScroll);
  }, []);

  useLayoutEffect(() => {
    const node = tableWrapRef.current;
    if (!node) return;
    node.scrollTop = tableScrollTopRef.current;
  }, [alerts]);

  return (
    <section className="panel table-panel">
      <div className="panel-head">
        <h2>Notable Events Queue</h2>
        <span>{alerts.length} results</span>
      </div>

      <div className="table-wrap" ref={tableWrapRef}>
        <table>
          <thead>
            <tr>
              <th>_time</th>
              <th>Urgency</th>
              <th>Correlation Search</th>
              <th>Asset</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Risk</th>
              <th>Disposition</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td className="mono">{new Date(alert.ts).toLocaleString()}</td>
                <td>
                  <span className={`sev-pill ${severityClass(alert.severity)}`}>{alert.severity}</span>
                </td>
                <td>
                  <div className="rule-name">{alert.ruleName}</div>
                  <div className="rule-id mono">{alert.ruleId}</div>
                </td>
                <td className="mono">{alert.host}</td>
                <td className="mono">{alert.sourceIp}</td>
                <td className="mono">{alert.dstIp}</td>
                <td>{alert.riskScore}</td>
                <td>
                  <span className={`status-pill ${statusClass(alert.status)}`}>{alert.status}</span>
                </td>
                <td>{alert.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
