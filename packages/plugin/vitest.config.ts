import { readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  // Mirror esbuild's `.md` text loader. Production build (esbuild.config.mjs)
  // imports `./SKILL.md` as a string; tests need the same shape so the
  // installer module's `import skillBody from "./SKILL.md"` resolves to
  // the file's contents under vitest as well.
  plugins: [
    {
      name: 'vaultguard:md-as-text',
      enforce: 'pre',
      transform(_code, id) {
        if (!id.endsWith('.md')) return null;
        const raw = readFileSync(id, 'utf-8');
        return {
          code: `export default ${JSON.stringify(raw)};`,
          map: null,
        };
      },
    },
  ],
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup.ts'],
    testTimeout: 15000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      // Count production files even when no test imports them. Without an
      // explicit include, never-loaded admin/UI/Lambda modules disappear from
      // the denominator and the reported percentage is optimistically high.
      include: ['src/**/*.ts', 'infrastructure/lambda/**/*.ts'],
      thresholds: {
        // Honest baseline measured 2026-08-12: 60.29 lines, 55.15 branches,
        // 58.06 functions, 58.75 statements. These floors leave a small
        // platform/coverage-provider buffer and should only ratchet upward.
        lines: 55,
        branches: 50,
        functions: 55,
        statements: 55,
      },
    },
  },
});
