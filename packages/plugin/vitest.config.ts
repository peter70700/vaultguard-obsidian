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
      thresholds: {
        lines: 70,
        branches: 65,
        functions: 70,
        statements: 70,
      },
    },
  },
});
