#!/usr/bin/env node
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runCli } from '../src/cli.mjs';
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  process.exitCode=await runCli(process.argv.slice(2),{stdout:process.stdout,stderr:process.stderr});
}
