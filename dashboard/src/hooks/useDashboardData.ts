import { useEffect, useMemo, useRef, useState } from "react";

export type Severity = "all" | "critical" | "high" | "medium" | "low";

export type DemoAlert = {
  id: string;
  ts: string;
  severity: Exclude<Severity, "all">;
  ruleId: string;
  ruleName: string;
  host: string;
  sourceIp: string;
  dstIp: string;
  summary: string;
  riskScore: number;
  status: "open" | "investigating" | "closed";
};

export type DashboardData = {
  generatedAt: string;
  kpis: {
    totalAlerts24h: number;
    openAlerts: number;
    criticalAlerts: number;
    hostsImpacted: number;
    meanRiskScore: number;
  };
  timeline: Array<{ bucket: string; count: number }>;
  breakdown: {
    byRule: Array<{ ruleId: string; ruleName: string; count: number }>;
    byHost: Array<{ host: string; count: number }>;
  };
  filterOptions: {
    hosts: string[];
    rules: Array<{ ruleId: string; ruleName: string }>;
  };
  alerts: DemoAlert[];
};

export type DashboardFilters = {
  severity: Severity;
  host: string;
  ruleId: string;
  q: string;
  limit?: number;
};

const EMPTY: DashboardData = {
  generatedAt: new Date(0).toISOString(),
  kpis: {
    totalAlerts24h: 0,
    openAlerts: 0,
    criticalAlerts: 0,
    hostsImpacted: 0,
    meanRiskScore: 0,
  },
  timeline: [],
  breakdown: {
    byRule: [],
    byHost: [],
  },
  filterOptions: {
    hosts: [],
    rules: [],
  },
  alerts: [],
};

export function useDashboardData(filters: DashboardFilters) {
  const [data, setData] = useState<DashboardData>(EMPTY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);
  const hasLoadedOnceRef = useRef(false);

  const queryString = useMemo(() => {
    const qs = new URLSearchParams();
    qs.set("severity", filters.severity);
    qs.set("host", filters.host);
    qs.set("ruleId", filters.ruleId);
    qs.set("q", filters.q);
    qs.set("limit", String(filters.limit ?? 50));
    return qs.toString();
  }, [filters.host, filters.limit, filters.q, filters.ruleId, filters.severity]);

  useEffect(() => {
    const ac = new AbortController();
    let intervalId: NodeJS.Timeout | null = null;

    async function fetchWithTimeout(url: string, timeoutMs: number) {
      const timeoutController = new AbortController();
      const onAbort = () => timeoutController.abort();
      const timeoutId = setTimeout(() => timeoutController.abort(), timeoutMs);

      ac.signal.addEventListener("abort", onAbort, { once: true });

      try {
        return await fetch(url, { signal: timeoutController.signal });
      } finally {
        clearTimeout(timeoutId);
        ac.signal.removeEventListener("abort", onAbort);
      }
    }

    async function load(options?: { silent?: boolean }) {
      const silent = options?.silent ?? false;
      const showLoading = !silent && !hasLoadedOnceRef.current;

      if (showLoading) {
        setLoading(true);
      }
      setError(null);
      try {
        const res = await fetchWithTimeout(`/api/alerts?${queryString}`, 3000);

        if (!res.ok) {
          throw new Error(`/api/alerts returned ${res.status}`);
        }
        const json = (await res.json()) as DashboardData;

        setData(json);
        hasLoadedOnceRef.current = true;
      } catch (err) {
        if (ac.signal.aborted) return;
        const message = err instanceof Error ? err.message : "Unknown dashboard error";
        setError(message);
      } finally {
        if (!ac.signal.aborted && showLoading) {
          setLoading(false);
        }
      }
    }

    load();
    intervalId = setInterval(() => {
      void load({ silent: true });
    }, 3000);

    return () => {
      ac.abort();
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [queryString, reloadNonce]);

  return {
    data,
    loading,
    error,
    reload: () => setReloadNonce((value) => value + 1),
  };
}
