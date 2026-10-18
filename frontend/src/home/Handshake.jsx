import { useEffect, useRef, useState } from "react";
import { AnimatePresence, animate, motion, useMotionValue, useReducedMotion, useTransform } from "framer-motion";

const B1 = [34, 0];
const B2 = [12, 30];
const R = 150;
const EASE = [0.65, 0, 0.35, 1];
const OUT = [0.16, 1, 0.3, 1];
const SNAP = [0.83, 0, 0.17, 1];
const MUTE = "#A1A1AA";

const PHASES = [
  "Scanning lattice",
  "Exchanging ML‑KEM‑768 key shares",
  "Verifying handshake",
  "Secured · sealed to audit chain",
];

const pt = (i, j) => [i * B1[0] + j * B2[0], i * B1[1] + j * B2[1]];
const mag = (x, y) => Math.hypot(x, y);
const pick = (a) => a[Math.floor(Math.random() * a.length)];

const LATTICE = (() => {
  const out = [];
  for (let i = -9; i <= 9; i++) {
    for (let j = -6; j <= 6; j++) {
      const [x, y] = pt(i, j);
      if (mag(x, y) <= R) out.push({ i, j, x, y });
    }
  }
  return out;
})();

const IN = new Set(LATTICE.map((p) => `${p.i}:${p.j}`));

function route() {
  const a = pick(LATTICE.filter((p) => { const d = mag(p.x, p.y); return d > 70 && d < 112; }));
  const s = pick(LATTICE.filter((p) => mag(p.x, p.y) > 118 && mag(p.x - a.x, p.y - a.y) > 120 && mag(p.x + a.x, p.y + a.y) > 60));
  let { i, j } = s;
  const steps = [[i, j]];
  while (i !== a.i || j !== a.j) {
    const di = Math.sign(a.i - i);
    const dj = Math.sign(a.j - j);
    const moves = [di && [i + di, j], dj && [i, j + dj]].filter(Boolean);
    const inside = moves.filter(([x, y]) => IN.has(`${x}:${y}`));
    [i, j] = pick(inside.length ? inside : moves);
    steps.push([i, j]);
  }
  const pts = steps.map(([x, y]) => pt(x, y));
  const cum = [0];
  for (let k = 1; k < pts.length; k++) cum.push(cum[k - 1] + mag(pts[k][0] - pts[k - 1][0], pts[k][1] - pts[k - 1][1]));
  const total = cum[cum.length - 1];
  return {
    pts,
    total,
    a: pts[pts.length - 1],
    b: [-pts[pts.length - 1][0], -pts[pts.length - 1][1]],
    d: pts.map(([x, y], k) => `${k ? "L" : "M"}${x} ${y}`).join(" "),
    at(t) {
      const L = Math.min(Math.max(t, 0), 1) * total;
      let k = 1;
      while (k < cum.length - 1 && cum[k] < L) k++;
      const f = (L - cum[k - 1]) / (cum[k] - cum[k - 1] || 1);
      return [pts[k - 1][0] + (pts[k][0] - pts[k - 1][0]) * f, pts[k - 1][1] + (pts[k][1] - pts[k - 1][1]) * f];
    },
  };
}

function Dot({ x, y, ax, ay, scan, lat }) {
  const opacity = useTransform([ax, ay, scan, lat], ([px, py, s, l]) => {
    const k = Math.max(0, 1 - mag(px - x, py - y) / 46);
    return (0.3 + 0.7 * k * k * s) * l;
  });
  return <motion.circle cx={x} cy={y} r={1.15} fill="#FFFFFF" style={{ opacity }} />;
}

function Pulse({ x, y, u }) {
  const r = useTransform(u, (v) => 3.5 + v * 22);
  const opacity = useTransform(u, (v) => (v > 0 && v < 1 ? 0.55 * (1 - v) : 0));
  return <motion.circle cx={x} cy={y} r={r} fill="none" stroke="#FFFFFF" strokeWidth={0.75} style={{ opacity }} />;
}

export default function Handshake({ once = false, onSealed }) {
  const reduce = useReducedMotion();
  const [geo, setGeo] = useState(null);
  const [phase, setPhase] = useState(0);
  const g = useRef(null);
  g.current = geo;

  const lat = useMotionValue(0);
  const act = useMotionValue(0);
  const scan = useMotionValue(0);
  const p = useMotionValue(0);
  const conv = useMotionValue(0);
  const trailO = useMotionValue(1);
  const agentO = useMotionValue(0);
  const peerO = useMotionValue(0);
  const link = useMotionValue(0);
  const pkt = useMotionValue(0);
  const pktO = useMotionValue(0);
  const u = useMotionValue(0);
  const coreR = useMotionValue(0);
  const ring = useMotionValue(0);
  const ring2 = useMotionValue(0);
  const jx = useMotionValue(0);
  const jy = useMotionValue(0);
  const shock = useMotionValue(0);
  const sealed = useRef(onSealed);
  sealed.current = onSealed;

  const ax = useTransform([p, conv], ([t, c]) => (g.current ? g.current.at(t)[0] * (1 - c) : 0));
  const ay = useTransform([p, conv], ([t, c]) => (g.current ? g.current.at(t)[1] * (1 - c) : 0));
  const bx = useTransform(conv, (c) => (g.current ? g.current.b[0] * (1 - c) : 0));
  const by = useTransform(conv, (c) => (g.current ? g.current.b[1] * (1 - c) : 0));
  const linkD = useTransform([ax, ay, bx, by], ([x1, y1, x2, y2]) => `M${x1} ${y1} L${x2} ${y2}`);
  const kx = useTransform([ax, bx, pkt], ([x1, x2, t]) => x1 + (x2 - x1) * t);
  const ky = useTransform([ay, by, pkt], ([y1, y2, t]) => y1 + (y2 - y1) * t);
  const haloR = useTransform(scan, (s) => 5 + s * 9);
  const haloO = useTransform(scan, (s) => s * 0.35);
  const peerR = useTransform(peerO, (o) => 1.5 + o * 1.7);
  const ring2O = useTransform(ring2, (v) => v * 0.55);
  const shockR = useTransform(shock, (v) => 24 + v * 300);
  const shockO = useTransform(shock, (v) => (v > 0 && v < 1 ? 0.9 * (1 - v) : 0));
  const shockR2 = useTransform(shock, (v) => 44 + v * 420);
  const shockO2 = useTransform(shock, (v) => (v > 0 && v < 1 ? 0.5 * (1 - v) : 0));

  useEffect(() => {
    if (reduce) {
      lat.set(0.4); act.set(1); coreR.set(6); ring.set(1); ring2.set(1); agentO.set(0);
      setPhase(3);
      if (once) {
        const t = setTimeout(() => sealed.current?.(), 1600);
        return () => clearTimeout(t);
      }
      return;
    }
    setGeo(route());
  }, [reduce]);

  useEffect(() => {
    if (!geo || reduce) return;
    let alive = true;
    const live = [];
    const run = (mv, to, o) => { const c = animate(mv, to, o); live.push(c); return c; };
    const wait = (ms) => new Promise((r) => { const t = setTimeout(r, ms); live.push({ stop: () => clearTimeout(t) }); });
    const step = (n) => alive && setPhase(n);

    (async () => {
      [p, conv, link, pkt, pktO, u, coreR, ring, ring2, peerO, agentO, scan].forEach((m) => m.set(0));
      trailO.set(1);
      step(0);
      run(act, 1, { duration: 0.6, ease: OUT });
      await run(lat, 1, { duration: 1.2, ease: OUT });
      if (!alive) return;
      run(agentO, 1, { duration: 0.6, ease: OUT });
      run(scan, 1, { duration: 0.8, ease: OUT });
      await run(p, 1, { duration: Math.min(Math.max(geo.total / 95, 2.8), 4.6), ease: EASE });
      if (!alive) return;
      step(1);
      run(scan, 0, { duration: 0.9, ease: OUT });
      run(peerO, 1, { duration: 0.7, ease: OUT });
      await run(link, 1, { duration: 1.1, ease: OUT });
      if (!alive) return;
      run(pktO, 1, { duration: 0.25 });
      await run(pkt, 1, { duration: 0.95, ease: EASE });
      if (!alive) return;
      await run(pkt, 0, { duration: 0.95, ease: EASE });
      if (!alive) return;
      run(pktO, 0, { duration: 0.25 });
      step(2);
      await run(u, [0, 1], { duration: 1.1, ease: OUT });
      if (!alive) return;
      await run(u, [0, 1], { duration: 1.1, ease: OUT });
      if (!alive) return;
      run(trailO, 0, { duration: 0.9, ease: OUT });
      run(lat, 0.35, { duration: 1.4, ease: EASE });
      await run(conv, 1, { duration: 1.25, ease: SNAP });
      if (!alive) return;
      step(3);
      run(agentO, 0, { duration: 0.3 });
      run(peerO, 0, { duration: 0.3 });
      coreR.set(3.2);
      run(coreR, 6, { type: "spring", stiffness: 240, damping: 13 });
      run(ring2, 1, { duration: 1.6, ease: OUT });
      await run(ring, 1, { duration: 1.2, ease: OUT });
      if (!alive) return;
      await run(coreR, [6, 6.9, 6], { duration: once ? 1.6 : 2.6, ease: "easeInOut" });
      if (!alive) return;
      if (once) {
        run(jy, [0, 3.5, -4.5, 5, -3.5, 6, -5, 4.5, -6, 3, -2, 0], { duration: 1.1, ease: "linear" });
        run(coreR, [6, 7.2, 6.4, 7.6, 6.6, 8, 7], { duration: 1.1, ease: "linear" });
        run(lat, [0.35, 0.7, 0.3, 0.8, 0.25], { duration: 1.1, ease: "linear" });
        await run(jx, [0, -5, 5, -6, 6, -4, 5.5, -7, 7, -3.5, 3, 0], { duration: 1.1, ease: "linear" });
        if (!alive) return;
        run(lat, 0, { duration: 0.7, ease: OUT });
        run(ring, 0, { duration: 0.5, ease: OUT });
        run(ring2, 0, { duration: 0.5, ease: OUT });
        run(coreR, [7, 14, 0], { duration: 0.9, ease: SNAP });
        await run(shock, [0, 1], { duration: 1.0, ease: OUT });
        if (!alive) return;
        sealed.current?.();
        return;
      }
      await wait(400);
      if (!alive) return;
      await run(act, 0, { duration: 1.1, ease: EASE });
      if (!alive) return;
      setGeo(route());
    })();

    return () => { alive = false; live.forEach((c) => c.stop()); };
  }, [geo, reduce]);

  return (
    <>
      <svg
        viewBox="-200 -200 400 400"
        className="h-[min(88vw,52vh,500px)] w-[min(88vw,52vh,500px)] overflow-visible"
        role="img"
        aria-label="An agent scans a lattice, completes a post-quantum key handshake with a peer, and locks into a secured state."
      >
        {LATTICE.map((d) => <Dot key={`${d.i}:${d.j}`} x={d.x} y={d.y} ax={ax} ay={ay} scan={scan} lat={lat} />)}

        <motion.g style={{ opacity: act }}>
          {geo && (
            <motion.path
              key={geo.d}
              d={geo.d}
              fill="none"
              stroke="#FFFFFF"
              strokeWidth={0.7}
              strokeLinejoin="round"
              style={{ pathLength: p, opacity: trailO }}
            />
          )}

          <motion.path d={linkD} fill="none" stroke="#FFFFFF" strokeWidth={0.8} style={{ pathLength: link, opacity: agentO }} />

          <Pulse x={ax} y={ay} u={u} />
          <Pulse x={bx} y={by} u={u} />

          <motion.circle cx={ax} cy={ay} r={haloR} fill="none" stroke="#FFFFFF" strokeWidth={0.6} style={{ opacity: haloO }} />
          <motion.circle cx={ax} cy={ay} r={3.2} fill="#FFFFFF" style={{ opacity: agentO }} />
          <motion.circle cx={bx} cy={by} r={peerR} fill="#FFFFFF" style={{ opacity: peerO }} />
          <motion.circle cx={kx} cy={ky} r={1.7} fill="#FFFFFF" style={{ opacity: pktO }} />

          <motion.g style={{ x: jx, y: jy }}>
            <motion.circle cx={0} cy={0} r={44} fill="none" stroke={MUTE} strokeWidth={0.6} transform="rotate(90)" style={{ pathLength: ring2, opacity: ring2O }} />
            <motion.circle cx={0} cy={0} r={24} fill="none" stroke="#FFFFFF" strokeWidth={0.9} transform="rotate(-90)" style={{ pathLength: ring }} />
            <motion.circle cx={0} cy={0} r={coreR} fill="#FFFFFF" />
          </motion.g>
          <motion.circle cx={0} cy={0} r={shockR} fill="none" stroke="#FFFFFF" strokeWidth={1.2} style={{ opacity: shockO }} />
          <motion.circle cx={0} cy={0} r={shockR2} fill="none" stroke={MUTE} strokeWidth={0.6} style={{ opacity: shockO2 }} />
        </motion.g>
      </svg>

      <div className="pointer-events-none mt-6 flex flex-col items-center gap-4 px-6 sm:mt-8 sm:gap-5" aria-live="polite">
        <div className="flex items-center gap-2" aria-hidden="true">
          {PHASES.map((_, i) => (
            <motion.span
              key={i}
              className="block h-[2px] rounded-full"
              initial={false}
              animate={{ width: i === phase ? 44 : 16, backgroundColor: i <= phase ? "#FFFFFF" : "#3F3F46" }}
              transition={{ duration: 0.6, ease: OUT }}
            />
          ))}
        </div>
        <div className="relative h-[60px] w-[min(86vw,640px)] overflow-hidden sm:h-11">
          <AnimatePresence initial={false}>
            <motion.div
              key={phase}
              initial={{ y: 22, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: -22, opacity: 0 }}
              transition={{ duration: 0.7, ease: OUT }}
              className="absolute inset-x-0 top-0 text-balance text-center text-[22px] font-light leading-tight tracking-tight text-paper sm:text-[30px]"
            >
              {PHASES[phase]}
            </motion.div>
          </AnimatePresence>
        </div>
        <div className="font-mono text-[11px] tabular-nums tracking-[0.2em] text-mute">
          STEP 0{phase + 1} / 04
        </div>
      </div>
    </>
  );
}
