import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Handshake from "./Handshake.jsx";
import Home from "./Home.jsx";
import { Mark } from "../ui.jsx";
import "./intro.css";

export default function Landing({ signedIn }) {
  const [view, setView] = useState("intro");
  const [cycle, setCycle] = useState(0);

  useEffect(() => {
    document.body.classList.toggle("intro", view === "intro");
    return () => document.body.classList.remove("intro");
  }, [view]);

  const done = () => {
    window.scrollTo({ top: 0 });
    setView("home");
  };
  const replay = () => {
    window.scrollTo({ top: 0 });
    setCycle((c) => c + 1);
    setView("intro");
  };

  if (view === "home") return <Home signedIn={signedIn} onReplay={replay} />;
  return (
    <div id="aq" className="relative min-h-[100svh] w-full">
      <header className="fixed inset-x-0 top-0 z-20 flex items-center justify-between px-6 py-6 sm:px-10 sm:py-8">
        <span className="flex items-center gap-2.5 text-[15px] font-semibold text-paper">
          <Mark />
          AegisQ
        </span>
        <button type="button" onClick={done} className="text-[13px] text-zinc-400 transition-colors hover:text-paper">
          Skip intro
        </button>
      </header>
      <AnimatePresence mode="wait">
        <motion.div
          key={`intro-${cycle}`}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.5 }}
          className="fixed inset-0 flex flex-col items-center justify-center pt-10"
        >
          <Handshake once onSealed={done} />
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
