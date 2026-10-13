#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runCli } from '../src/cli.mjs';
if(process.argv[1]&&realpathSync(process.argv[1])===fileURLToPath(import.meta.url)) {
  process.exitCode=await runCli(process.argv.slice(2),{stdout:process.stdout,stderr:process.stderr});
}
