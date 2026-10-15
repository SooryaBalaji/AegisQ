import { AnimatePresence, motion } from "framer-motion";

const DOCS = "https://github.com/SooryaBalaji/AegisQ#readme";
const LINK = "text-[11px] tracking-wide text-zinc-400 no-underline transition-colors duration-300 hover:text-paper sm:text-xs";

export default function Header({ active, signedIn, showDashboard = false, onHome }) {
  const home = (e) => {
    if (!onHome) return;
    e.preventDefault();
    onHome();
  };
  return (
    <header className="fixed inset-x-0 top-0 z-20 flex items-center justify-between bg-ink/80 px-6 py-6 sm:px-10 sm:py-8">
      <a href="#intro" onClick={home} className="text-[11px] font-medium tracking-[0.42em] text-paper no-underline" title="Replay the intro">
        AEGISQ
      </a>
      <nav className="flex items-center gap-4 sm:gap-9">
        <a href={DOCS} className={`${LINK} max-sm:hidden`}>Documentation</a>
        <AnimatePresence initial={false}>
          {showDashboard && (
            <motion.a
              key="dash"
              href={signedIn ? "#overview" : "#signin"}
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.6 }}
              className={LINK}
            >
              Dashboard
            </motion.a>
          )}
        </AnimatePresence>
        <a
          href="#run"
          className={`rounded-full border px-3.5 py-1.5 text-[11px] tracking-wide no-underline transition-colors duration-300 sm:text-xs ${
            active === "console" ? "border-paper bg-paper text-ink" : "border-white/25 text-paper hover:border-paper"
          }`}
        >
          Run
        </a>
      </nav>
    </header>
  );
}
