import { useEffect, useMemo } from "react";
import { AnimatePresence, animate, motion, useMotionValue } from "framer-motion";

const MUTE = "#A1A1AA";
const OUT = [0.16, 1, 0.3, 1];
const SAFE = new Set(["pq_ready"]);
const WEAK = new Set(["classical", "tls12_only"]);
const BAD = new Set(["legacy_tls", "plaintext"]);

const GRID = (() => {
  const out = [];
  for (let i = -9; i <= 9; i++) {
    for (let j = -6; j <= 6; j++) {
      const x = i * 34 + j * 12;
      const y = j * 30;
      if (Math.hypot(x, y) <= 160) out.push([x, y]);
    }
  }
  return out;
})();

function layout(n) {
  if (!n) return [];
  if (n <= 12) {
    return Array.from({ length: n }, (_, k) => {
      const a = ((-90 + (k * 360) / n) * Math.PI) / 180;
      return [Math.cos(a) * 122, Math.sin(a) * 122, Math.cos(a), Math.sin(a)];
    });
  }
  return Array.from({ length: n }, (_, k) => {
    const r = 46 + 108 * Math.sqrt((k + 0.5) / n);
    const a = k * 2.39996;
    return [Math.cos(a) * r, Math.sin(a) * r, Math.cos(a), Math.sin(a)];
  });
}

function Mark({ status, small }) {
  const r = small ? 2.6 : 4;
  if (!status) return <circle r={small ? 1.2 : 1.7} fill="#FFFFFF" opacity={0.35} />;
  if (SAFE.has(status)) return <circle r={r} fill="#FFFFFF" />;
  if (WEAK.has(status)) return <circle r={r} fill="#000000" stroke="#FFFFFF" strokeWidth={1} />;
  if (BAD.has(status)) return (
    <g>
      <circle r={r} fill="#000000" stroke={MUTE} strokeWidth={1} strokeDasharray="1.6 1.6" />
      <circle r={1} fill={MUTE} />
    </g>
  );
  return <circle r={small ? 1.6 : 2.2} fill="none" stroke={MUTE} strokeWidth={0.8} opacity={0.7} />;
}

function Node({ x, y, ux, uy, k, node, phase, focused, labels, small }) {
  const linked = phase >= 1 && node.status;
  const safe = SAFE.has(node.status);
  return (
    <g>
      {linked && (
        safe ? (
          <motion.line
            x1={0} y1={0} x2={x} y2={y}
            stroke="#FFFFFF" strokeWidth={0.7}
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 0.6 }}
            transition={{ duration: 1.1, delay: k * 0.06, ease: OUT }}
          />
        ) : (
          <motion.line
            x1={0} y1={0} x2={x} y2={y}
            stroke={MUTE} strokeWidth={0.6} strokeDasharray="2 5"
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.4 }}
            transition={{ duration: 1.1, delay: k * 0.06, ease: OUT }}
          />
        )
      )}
      <g transform={`translate(${x} ${y})`}>
        {focused && (
          <motion.circle
            r={6}
            fill="none"
            stroke="#FFFFFF"
            strokeWidth={0.8}
            initial={{ scale: 0.6, opacity: 0.7 }}
            animate={{ scale: 3.4, opacity: 0 }}
            transition={{ duration: 1.6, repeat: Infinity, ease: OUT }}
          />
        )}
        <AnimatePresence initial={false}>
          <motion.g
            key={node.status || "pending"}
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            transition={{ type: "spring", stiffness: 320, damping: 18 }}
          >
            <Mark status={node.status} small={small} />
          </motion.g>
        </AnimatePresence>
        {labels && node.name && (
          <motion.text
            x={ux * 14}
            y={uy * 14 + 3}
            textAnchor={ux > 0.3 ? "start" : ux < -0.3 ? "end" : "middle"}
            fontSize={8}
            fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
            fill={node.status ? MUTE : "#52525B"}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6 }}
          >
            {node.name}
          </motion.text>
        )}
      </g>
    </g>
  );
}

export default function LiveLattice({ nodes, phase, focus, sealed, className = "h-[min(92vw,62vh,560px)] w-[min(92vw,62vh,560px)] overflow-visible", label = "Live scan of your services" }) {
  const pos = useMemo(() => layout(nodes.length), [nodes.length]);
  const ax = useMotionValue(0);
  const ay = useMotionValue(0);
  const idx = focus ? nodes.findIndex((n) => n.name === focus) : -1;
  const labels = nodes.length <= 12;
  const small = nodes.length > 24;

  useEffect(() => {
    const [x, y] = idx >= 0 && pos[idx] ? pos[idx] : [0, 0];
    const o = { type: "spring", stiffness: 70, damping: 16, mass: 1 };
    const a = animate(ax, x, o);
    const b = animate(ay, y, o);
    return () => { a.stop(); b.stop(); };
  }, [idx, pos]);

  return (
    <svg viewBox="-200 -200 400 400" className={className} role="img" aria-label={label}>
      {GRID.map(([x, y]) => (
        <motion.circle
          key={`${x}:${y}`}
          cx={x}
          cy={y}
          r={1}
          fill="#FFFFFF"
          animate={{ opacity: sealed ? 0.1 : 0.18 }}
          transition={{ duration: 1.4 }}
        />
      ))}

      {phase === 0 && !sealed && (
        <motion.g animate={{ rotate: 360 }} transition={{ duration: 3.2, repeat: Infinity, ease: "linear" }}>
          <circle r={34} fill="none" stroke="#FFFFFF" strokeWidth={0.8} strokeDasharray="26 188" opacity={0.7} />
        </motion.g>
      )}

      {nodes.map((n, k) => (
        <Node
          key={k}
          k={k}
          x={pos[k][0]}
          y={pos[k][1]}
          ux={pos[k][2]}
          uy={pos[k][3]}
          node={n}
          phase={phase}
          focused={n.name && n.name === focus && !sealed}
          labels={labels}
          small={small}
        />
      ))}

      <AnimatePresence>
        {!sealed && (
          <motion.g key="agent" exit={{ opacity: 0 }} transition={{ duration: 0.4 }}>
            <motion.circle cx={ax} cy={ay} r={9} fill="none" stroke="#FFFFFF" strokeWidth={0.6} opacity={0.35} />
            <motion.circle cx={ax} cy={ay} r={3} fill="#FFFFFF" />
          </motion.g>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {sealed && (
          <motion.g key="seal" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <motion.circle r={44} fill="none" stroke={MUTE} strokeWidth={0.6} transform="rotate(90)" initial={{ pathLength: 0 }} animate={{ pathLength: 1, opacity: 0.55 }} transition={{ duration: 1.6, ease: OUT }} />
            <motion.circle r={24} fill="none" stroke="#FFFFFF" strokeWidth={0.9} transform="rotate(-90)" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1.2, ease: OUT }} />
            <motion.circle fill="#FFFFFF" initial={{ r: 3 }} animate={{ r: 6 }} transition={{ type: "spring", stiffness: 240, damping: 13 }} />
          </motion.g>
        )}
      </AnimatePresence>
    </svg>
  );
}
