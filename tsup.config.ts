import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'adapters/express': 'src/adapters/express.ts',
    'adapters/hono': 'src/adapters/hono.ts',
    'adapters/cloudflare': 'src/adapters/cloudflare.ts',
    'analyzer/index': 'src/analyzer/index.ts',
    'rules/index': 'src/rules/index.ts',
    'cli/index': 'src/cli/index.ts'
  },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  treeshake: true,
  target: 'es2022'
});
