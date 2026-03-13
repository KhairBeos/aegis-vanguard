import type { NextApiRequest, NextApiResponse } from "next";
import { ensureAlertStreamStarted, getAlertSnapshot, type DashboardAlert } from "../../server/alertStream";

type Severity = "critical" | "high" | "medium" | "low";
type AlertStatus = "open" | "investigating" | "closed";

type TimelinePoint = {
  bucket: string;
  count: number;
};

type ApiResponse = {
  generatedAt: string;
  kpis: {
    totalAlerts24h: number;
    openAlerts: number;
    criticalAlerts: number;
    hostsImpacted: number;
    meanRiskScore: number;
  };
  timeline: TimelinePoint[];
  breakdown: {
    byRule: Array<{ ruleId: string; ruleName: string; count: number }>;
    byHost: Array<{ host: string; count: number }>;
  };
  filterOptions: {
    hosts: string[];
    rules: Array<{ ruleId: string; ruleName: string }>;
  };
  alerts: DashboardAlert[];
};

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<ApiResponse | { error: string }>
) {
  try {
    await ensureAlertStreamStarted();
    const snapshot = getAlertSnapshot();

    const alerts: DashboardAlert[] = snapshot.alerts;

    // Apply filters
    const severity = typeof req.query.severity === "string" ? req.query.severity : "all";
    const host = typeof req.query.host === "string" ? req.query.host : "all";
    const ruleId = typeof req.query.ruleId === "string" ? req.query.ruleId : "all";
    const q = typeof req.query.q === "string"
      ? req.query.q.toLowerCase().trim()
      : typeof req.query.search === "string"
        ? req.query.search.toLowerCase().trim()
        : "";
    const limit = Math.max(1, Math.min(200, Number(req.query.limit ?? 100)));

    let filtered = alerts;

    if (severity !== "all") {
      filtered = filtered.filter((a) => a.severity === severity);
    }

    if (host !== "all") {
      filtered = filtered.filter((a) => a.host === host);
    }

    if (ruleId !== "all") {
      filtered = filtered.filter((a) => a.ruleId === ruleId);
    }

    if (q.length > 0) {
      filtered = filtered.filter(
        (a) =>
          a.summary.toLowerCase().includes(q) ||
          a.host.toLowerCase().includes(q) ||
          a.ruleName.toLowerCase().includes(q) ||
          a.ruleId.toLowerCase().includes(q) ||
          a.sourceIp.toLowerCase().includes(q) ||
          a.dstIp.toLowerCase().includes(q)
      );
    }

    filtered.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

    // Calculate KPIs
    const now = new Date();
    const oneDay = 24 * 60 * 60 * 1000;
    const alerts24h = filtered.filter(
      (a) => new Date(a.ts).getTime() > now.getTime() - oneDay
    );

    const kpis = {
      totalAlerts24h: alerts24h.length,
      openAlerts: filtered.filter((a) => a.status === "open").length,
      criticalAlerts: filtered.filter((a) => a.severity === "critical").length,
      hostsImpacted: new Set(filtered.map((a) => a.host)).size,
      meanRiskScore:
        filtered.length > 0
          ? Math.round(
              filtered.reduce((sum, a) => sum + a.riskScore, 0) / filtered.length
            )
          : 0,
    };

    // Timeline (2-hour buckets)
    const timeline: Record<string, number> = {};
    for (const alert of filtered) {
      const ts = new Date(alert.ts);
      const bucket = new Date(Math.floor(ts.getTime() / (2 * 60 * 60 * 1000)) * (2 * 60 * 60 * 1000))
        .toISOString()
        .split(".")[0];

      timeline[bucket] = (timeline[bucket] || 0) + 1;
    }

    const timelinePoints: TimelinePoint[] = Object.entries(timeline)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([bucket, count]) => ({ bucket, count }));

    // Breakdown
    const byRule: Record<string, { count: number; name: string }> = {};
    const byHost: Record<string, number> = {};

    for (const alert of filtered) {
      byRule[alert.ruleId] = {
        count: (byRule[alert.ruleId]?.count || 0) + 1,
        name: alert.ruleName,
      };
      byHost[alert.host] = (byHost[alert.host] || 0) + 1;
    }

    // Filter options
    const allHosts = new Set(alerts.map((a) => a.host));
    const allRules = new Map<string, string>();

    for (const alert of alerts) {
      allRules.set(alert.ruleId, alert.ruleName);
    }

    const response: ApiResponse = {
      generatedAt: new Date().toISOString(),
      kpis,
      timeline: timelinePoints,
      breakdown: {
        byRule: Object.entries(byRule).map(([ruleId, data]) => ({
          ruleId,
          ruleName: data.name,
          count: data.count,
        })),
        byHost: Object.entries(byHost).map(([host, count]) => ({
          host,
          count,
        })),
      },
      filterOptions: {
        hosts: Array.from(allHosts).sort(),
        rules: Array.from(allRules.entries()).map(([id, name]) => ({
          ruleId: id,
          ruleName: name,
        })),
      },
      alerts: filtered.slice(0, limit),
    };

    res.status(200).json(response);
  } catch (error) {
    console.error("Error in /api/alerts:", error);
    res.status(500).json({ error: "Failed to load alerts" });
  }
}
