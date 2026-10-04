import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

export default defineConfig({
  plugins: [react()],
  publicDir: false,
  build: {
    outDir: fileURLToPath(new URL("../src/aegisq/web/static", import.meta.url)),
    emptyOutDir: false,
    copyPublicDir: false,
    sourcemap: false,
    rollupOptions: {
      input: fileURLToPath(new URL("./src/main.jsx", import.meta.url)),
      output: { format: "iife", entryFileNames: "app.js", inlineDynamicImports: true },
    },
  },
});
