import { STATUS, plural, tone } from "./ui.jsx";

export const GROUPS = [
  ["safe", "Post-quantum"],
  ["warn", "Classical"],
  ["risk", "Legacy or plaintext"],
  ["idle", "Unreachable"],
];

export function counts(services) {
  const c = { safe: 0, warn: 0, risk: 0, idle: 0 };
  for (const s of services) if (s.status) c[tone(s.status)] += 1;
  return c;
}

/** Every server as one tile, in risk order. The same picture on the home page, the overview and a live run. */
export default function FleetMap({ services, filter = null, onFilter, onSelect, focus = null, caption, pending = 0 }) {
  const c = counts(services);
  const scanned = services.filter((s) => s.status).length;
  return (
    <div className="fleet">
      <div className="fleet-top">
        <div className="fleet-total">
          {caption || (
            <>
              <b>{c.safe}</b>of {plural(scanned, "server")} use post-quantum key exchange
            </>
          )}
        </div>
        <div className="legend" role="group" aria-label="Filter servers by status">
          {GROUPS.map(([t, label]) =>
            onFilter ? (
              <button key={t} type="button" aria-pressed={filter === t} onClick={() => onFilter(filter === t ? null : t)}>
                <span className={`dot ${t}`} aria-hidden="true" />
                {label} <span className="n">{c[t]}</span>
              </button>
            ) : (
              <span key={t} className="status">
                <span className={`dot ${t}`} aria-hidden="true" />
                {label} <span className="n">{c[t]}</span>
              </span>
            ),
          )}
        </div>
      </div>
      <div className={`tiles ${filter ? "dim" : ""}`} role="list" aria-label="Servers">
        {services.map((s, i) => {
          const t = s.status ? tone(s.status) : "pending";
          const label = s.name ? `${s.name}: ${STATUS[s.status]?.label || "waiting"}` : "waiting";
          return (
            <button
              key={s.name || `p${i}`}
              type="button"
              role="listitem"
              className={`tile ${t} ${filter && t === filter ? "match" : ""} ${focus && s.name === focus ? "focus" : ""}`}
              title={label}
              aria-label={label}
              disabled={!s.status || !onSelect}
              onClick={() => onSelect && onSelect(s)}
            />
          );
        })}
        {Array.from({ length: pending }, (_, i) => (
          <span key={`w${i}`} className="tile pending" aria-hidden="true" />
        ))}
      </div>
    </div>
  );
}
