import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Header from "./Header.jsx";
import Handshake from "./Handshake.jsx";
import Info from "./Info.jsx";
import "./ui.css";

export default function Landing({ signedIn }) {
  const [view, setView] = useState("intro");
  const [cycle, setCycle] = useState(0);

  useEffect(() => {
    document.body.classList.add("aq-dark");
    return () => document.body.classList.remove("aq-dark");
  }, []);

  const replay = () => {
    window.scrollTo({ top: 0 });
    setView("intro");
    setCycle((c) => c + 1);
  };
  const done = () => {
    window.scrollTo({ top: 0 });
    setView("info");
  };

  return (
    <div id="aq" className="relative min-h-[100svh] w-full">
      <Header active="landing" signedIn={signedIn} showDashboard={view === "info"} onHome={replay} />
      <AnimatePresence mode="wait">
        {view === "intro" ? (
          <motion.div
            key={`intro-${cycle}`}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5 }}
            className="fixed inset-0 flex flex-col items-center justify-center pt-10"
          >
            <Handshake once onSealed={done} />
            <button
              type="button"
              onClick={done}
              className="fixed bottom-6 right-6 font-mono text-[11px] text-zinc-500 transition-colors hover:text-paper sm:bottom-8 sm:right-10"
            >
              Skip intro →
            </button>
          </motion.div>
        ) : (
          <motion.div
            key="info"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.8 }}
          >
            <Info signedIn={signedIn} onReplay={replay} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
