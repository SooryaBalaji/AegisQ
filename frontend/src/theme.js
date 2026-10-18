import { useEffect, useState } from "react";

const KEY = "aegisq.theme";
const media = () => window.matchMedia("(prefers-color-scheme: dark)");

function stored() {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

function apply(choice) {
  const dark = choice === "dark" || (choice === "system" && media().matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

apply(stored());

export function useTheme() {
  const [choice, setChoice] = useState(stored);
  useEffect(() => {
    apply(choice);
    if (choice !== "system") return undefined;
    const m = media();
    const on = () => apply("system");
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, [choice]);
  const set = (v) => {
    try { localStorage.setItem(KEY, v); } catch { /* storage blocked: still applies for this visit */ }
    setChoice(v);
  };
  return [choice, set];
}
