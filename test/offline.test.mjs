import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { withFixture, cli, argsFor, packageRoot } from './support.mjs';
test('preload intercepts calls without native network side effects',()=>{
  const probe=spawnSync(process.execPath,['--import',join(packageRoot,'test/offline-preload.mjs'),'--input-type=module','-e',"import {connect} from 'node:net';import {lookup} from 'node:dns';for(const call of [()=>connect(null),()=>lookup('fixture.invalid'),()=>fetch('data:text/plain,probe')]){try{await call();}catch(e){if(e.message!=='OFFLINE_BARRIER')throw e;}}if(globalThis.__scopeGuardNetworkAttempts!==3)process.exitCode=1;"],{encoding:'utf8'});
  assert.equal(probe.status,0,probe.stderr);
});
test('real check uses no network entry point under a verified barrier',()=>withFixture(({paths})=>{
  const out=cli(argsFor(paths),{preload:true});assert.equal(out.code,0);assert.equal(out.report.decision,'allow');assert.equal(out.stderr.includes('NETWORK_ATTEMPT'),false);
}));
