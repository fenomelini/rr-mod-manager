import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["spikes/phase0/test/**/*.spec.ts"],
    coverage: {
      reporter: ["text", "html"],
    },
  },
});
