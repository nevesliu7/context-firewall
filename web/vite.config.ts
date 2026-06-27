import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/scan": "http://127.0.0.1:8000",
      "/gateway": "http://127.0.0.1:8000",
      "/v1": "http://127.0.0.1:8000",
      "/audit": "http://127.0.0.1:8000",
      "/approvals": "http://127.0.0.1:8000",
      "/metrics": "http://127.0.0.1:8000",
      "/config": "http://127.0.0.1:8000",
      "/policies": "http://127.0.0.1:8000",
      "/health": "http://127.0.0.1:8000"
    }
  }
});
