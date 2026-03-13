type Props = {
  title: string;
  value: string | number;
  subtitle: string;
  tone?: "neutral" | "alert" | "critical";
};

export function KpiCard({ title, value, subtitle, tone = "neutral" }: Props) {
  return (
    <article className={`kpi-card kpi-${tone}`}>
      <p className="kpi-title">{title}</p>
      <p className="kpi-value">{value}</p>
      <p className="kpi-subtitle">{subtitle}</p>
    </article>
  );
}
