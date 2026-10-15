export default {
  content: ["./src/aq/**/*.jsx"],
  important: "#aq",
  corePlugins: { preflight: false },
  theme: {
    extend: {
      colors: { ink: "#000000", paper: "#FFFFFF", mute: "#A1A1AA" },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Helvetica Neue", "sans-serif"],
        mono: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Helvetica Neue", "sans-serif"],
      },
    },
  },
};
