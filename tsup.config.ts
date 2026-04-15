import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node18',
  platform: 'node',
  dts: false,
  clean: true,
  splitting: false,
  banner: { js: '#!/usr/bin/env node' },
});
