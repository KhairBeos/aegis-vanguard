type Point = {
  bucket: string;
  count: number;
};

type Props = {
  points: Point[];
};

export function TimelineBars({ points }: Props) {
  const maxCount = Math.max(1, ...points.map((p) => p.count));

  return (
    <section className="panel timeline-panel">
      <div className="panel-head">
        <h2>Alert Timeline (24h)</h2>
        <span>2-hour buckets</span>
      </div>
      <div className="timeline-grid">
        {points.map((point) => {
          const height = Math.max(8, Math.round((point.count / maxCount) * 100));
          return (
            <div key={point.bucket} className="bar-cell" title={`${point.bucket}  ${point.count} alerts`}>
              <div className="bar-rail">
                <div className="bar-fill" style={{ height: `${height}%` }} />
              </div>
              <span className="bar-count">{point.count}</span>
              <span className="bar-label">{point.bucket}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
