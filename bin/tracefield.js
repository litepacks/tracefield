#!/usr/bin/env node
import { runCli } from '../dist/cli/index.js';

runCli(process.argv).catch((err) => {
  console.error('[tracefield] CLI Error:', err);
  process.exit(1);
});
