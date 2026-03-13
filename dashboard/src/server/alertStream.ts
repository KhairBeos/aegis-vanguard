import { Kafka, logLevel } from "kafkajs";

type Severity = "critical" | "high" | "medium" | "low";
type AlertStatus = "open" | "investigating" | "closed";

type RawAlert = Record<string, unknown>;

export type DashboardAlert = {
  id: string;
  ts: string;
  severity: Severity;
  ruleId: string;
  ruleName: string;
  host: string;
  sourceIp: string;
  dstIp: string;
  summary: string;
  riskScore: number;
  status: AlertStatus;
};

type AlertStreamState = {
  started: boolean;
  starting: boolean;
  alerts: DashboardAlert[];
  lastError: string | null;
};

declare global {
  var __aegisAlertStreamState__: AlertStreamState | undefined;
}

const MAX_ALERTS = 500;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

const state: AlertStreamState = global.__aegisAlertStreamState__ ?? {
  started: false,
  starting: false,
  alerts: [],
  lastError: null,
};

global.__aegisAlertStreamState__ = state;

function normalizeSeverity(value: string): Severity {
  return SEVERITIES.includes(value as Severity) ? (value as Severity) : "medium";
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function readString(record: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value;
    }
    if (typeof value === "number") {
      return String(value);
    }
  }
  return "";
}

function readNumber(record: Record<string, unknown>, ...keys: string[]): number | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number") {
      return value;
    }
    if (typeof value === "string" && value.trim().length > 0) {
      const parsed = Number(value);
      if (!Number.isNaN(parsed)) {
        return parsed;
      }
    }
  }
  return null;
}

function fallbackRiskBySeverity(severity: Severity): number {
  if (severity === "critical") return 90;
  if (severity === "high") return 75;
  if (severity === "medium") return 55;
  return 30;
}

function extractHostFromRawLog(rawLog?: string): string | null {
  if (!rawLog) {
    return null;
  }

  const parts = rawLog.split(/\s+/);
  return parts.length >= 4 ? parts[3] : null;
}

function renderSummary(summary: string, host: string, context: Record<string, unknown>): string {
  return summary
    .replaceAll("{{host}}", host)
    .replaceAll("{{event.process.user_name}}", readString(context, "user", "user_name") || "unknown")
    .replaceAll("{{event.process.cmdline}}", readString(context, "cmdline", "raw_log", "process") || "n/a");
}

function normalizeAlert(alert: RawAlert): DashboardAlert {
  const context = asRecord(alert.context);
  const matched = asRecord(alert.matched_fields);
  const nestedEvent = asRecord(context.event);
  const nestedAuth = asRecord(nestedEvent.auth);
  const nestedNetwork = asRecord(nestedEvent.network);

  const severity = normalizeSeverity(readString(alert, "severity") || "medium");

  const sourceIp =
    readString(context, "src_ip", "source_ip") ||
    readString(matched, "source_ip", "src_ip", "event.auth.src_ip") ||
    readString(nestedAuth, "src_ip") ||
    readString(nestedNetwork, "src_ip") ||
    "-";

  const dstIp =
    readString(context, "dst_ip", "dest_ip", "destination_ip") ||
    readString(matched, "dst_ip", "dest_ip", "destination_ip") ||
    readString(nestedNetwork, "dst_ip") ||
    "-";

  const rawLog = readString(matched, "raw_log");
  const host =
    readString(alert, "host") ||
    readString(context, "host") ||
    readString(matched, "host") ||
    extractHostFromRawLog(rawLog) ||
    "unknown";

  const ruleId = readString(alert, "rule_id", "ruleId") || "unknown-rule";
  const ruleName = readString(alert, "rule_name", "ruleName") || ruleId;
  const ts = readString(alert, "ts", "timestamp") || new Date(0).toISOString();
  const id =
    readString(alert, "alert_id", "id") ||
    `${ruleId}:${host}:${ts}`;

  const summaryRaw = readString(alert, "summary") || `Rule matched: ${ruleName}`;
  const riskScore = readNumber(alert, "risk_score", "riskScore") ?? fallbackRiskBySeverity(severity);
  const statusValue = readString(alert, "status");
  const status: AlertStatus = statusValue === "closed" || statusValue === "investigating" ? statusValue : "open";

  return {
    id,
    ts,
    severity,
    ruleId,
    ruleName,
    host,
    sourceIp,
    dstIp,
    summary: renderSummary(summaryRaw, host, { ...context, ...matched }),
    riskScore,
    status,
  };
}

function upsertAlert(alert: DashboardAlert) {
  const existingIndex = state.alerts.findIndex((item) => item.id === alert.id);
  if (existingIndex >= 0) {
    state.alerts[existingIndex] = alert;
  } else {
    state.alerts.unshift(alert);
  }

  state.alerts.sort((left, right) => new Date(right.ts).getTime() - new Date(left.ts).getTime());
  if (state.alerts.length > MAX_ALERTS) {
    state.alerts.length = MAX_ALERTS;
  }
}

async function seedFromKafka(kafka: Kafka, topic: string) {
  const admin = kafka.admin();
  await admin.connect();

  try {
    const metadata = await admin.fetchTopicMetadata({ topics: [topic] });
    if (!metadata.topics.length || !metadata.topics[0].partitions.length) {
      return;
    }
  } finally {
    await admin.disconnect();
  }
}

export async function ensureAlertStreamStarted() {
  if (state.started || state.starting) {
    return state;
  }

  const brokers = (process.env.KAFKA_BOOTSTRAP_SERVERS || "").split(",").map((item) => item.trim()).filter(Boolean);
  const topic = process.env.KAFKA_TOPIC_ALERTS || "siem.alerts";

  if (!brokers.length) {
    state.lastError = "Kafka bootstrap servers not configured";
    return state;
  }

  state.starting = true;

  try {
    const kafka = new Kafka({
      brokers,
      logLevel: logLevel.NOTHING,
      clientId: "aegis-dashboard",
    });

    await seedFromKafka(kafka, topic);

    const consumer = kafka.consumer({
      groupId: `aegis-dashboard-${process.pid}`,
    });

    await consumer.connect();
    await consumer.subscribe({ topic, fromBeginning: true });

    consumer.run({
      eachMessage: async ({ message }) => {
        if (!message.value) {
          return;
        }

        try {
          const parsed = JSON.parse(message.value.toString()) as RawAlert;
          upsertAlert(normalizeAlert(parsed));
          state.lastError = null;
        } catch (error) {
          state.lastError = error instanceof Error ? error.message : String(error);
        }
      },
    }).catch((error) => {
      state.lastError = error instanceof Error ? error.message : String(error);
      state.started = false;
    });

    state.started = true;
  } catch (error) {
    state.lastError = error instanceof Error ? error.message : String(error);
  } finally {
    state.starting = false;
  }

  return state;
}

export function getAlertSnapshot() {
  return {
    alerts: [...state.alerts],
    lastError: state.lastError,
  };
}