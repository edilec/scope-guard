import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, cp } from 'node:fs/promises';
import { join } from 'node:path';
import { check, verifyLog } from '../src/index.mjs';
import { checkWithIo } from '../src/check.mjs';
import { withFixture, validScope, validRequest, signedFixture, cli, argsFor, clock, faultIo, packageRoot } from './support.mjs';
import { spawnSync } from 'node:child_process';
import { exitFor } from '../src/report.mjs';
test('real CLI returns silent allow only with durable records and verifies checkpoint',()=>withFixture(async({paths})=>{
  const out=cli(argsFor(paths));assert.equal(out.code,0);assert.equal(out.report.decision,'allow');assert.deepEqual(out.report.findings,[]);assert.equal(out.report.audit.recordCount,1);
  const verify=cli(['verify-log','--log',paths.logPath,'--expect-count','1','--expect-head',out.report.audit.head]);assert.equal(verify.code,0);
  assert.equal((await readFile(paths.logPath,'utf8')).includes('api.example.invalid'),false);
}));
test('CLI executes when installed under the linked temporary parent',()=>withFixture(async({dir,paths})=>{
  const installed=join(dir,'package');await cp(join(packageRoot,'src'),join(installed,'src'),{recursive:true});await cp(join(packageRoot,'bin'),join(installed,'bin'),{recursive:true});
  const out=spawnSync(process.execPath,[join(installed,'bin/scope-guard.mjs'),...argsFor(paths)],{encoding:'utf8',timeout:30000});
  assert.equal(out.status,0);assert.ok(out.stdout.length>0,'Executable failed to emit its report through the temporary parent.');assert.equal(JSON.parse(out.stdout).decision,'allow');
}));
test('real CLI distinguishes usage errors from unreadable subject and mixed unknown',()=>withFixture(async({paths})=>{
  for(const args of [[],['check'],['wat'],['verify-log','--log',paths.logPath,'--expect-count','1'],[...argsFor(paths),'--scope',paths.scopePath],[...argsFor(paths),'--unknown','private-sentinel']]){
    const out=cli(args);assert.equal(out.code,2);assert.equal(out.stdout,'');assert.equal(out.stderr.includes('private-sentinel'),false);
  }
  const missing=cli(argsFor({...paths,scopePath:join(paths.scopePath,'absent')}));assert.equal(missing.code,2);assert.equal(missing.report.status,'incomplete');assert.ok(missing.report.findings.some(f=>f.ruleId==='input-unreadable'));
  const r=validRequest();r.requests=[{target:'192.0.2.129'},{target:'api.example.invalid'}];await writeFile(paths.requestPath,JSON.stringify(r));
  const mixed=cli(argsFor(paths));assert.equal(mixed.code,2);assert.deepEqual(mixed.report.decisions.map(x=>x.decision),['deny','unknown']);
}));
test('every complete policy refusal has CLI exit 1 with an allow control',async()=>{
  for(const [modify,rule] of [[r=>r.requests[0].target='blocked.example.invalid','excluded-domain'],[r=>r.requests[0].destinationIp='192.0.2.128','excluded-ip'],[r=>r.requests[0].target='outside.invalid','domain-not-allowed'],[r=>r.requests[0].destinationIp='192.0.3.1','ip-not-allowed']]){
    const r=validRequest();modify(r);await withFixture(({paths})=>{const out=cli(argsFor(paths));assert.equal(out.code,1);assert.equal(out.report.decisions[0].ruleId,rule);},signedFixture(validScope(),r));
  }
});
test('signature changes and self-declared key cannot authorize targets',()=>withFixture(async({paths,fixture})=>{
  await writeFile(paths.scopePath,Buffer.from(JSON.stringify(JSON.parse(fixture.scopeBytes),null,2)));
  const out=cli(argsFor(paths));assert.equal(out.code,1);assert.equal(out.report.decisions[0].ruleId,'scope-signature-invalid');
}));
test('library audit faults convert every provisional allow into unknown',async()=>{
  for(const method of ['sync','write'])await withFixture(async({paths})=>{
    const io=faultIo(method,()=>{if(method==='write')return {bytesWritten:0};throw new Error('secret-fault');});
    const report=await checkWithIo({...paths,clock},io);assert.equal(exitFor(report),2);assert.equal(report.decision,'unknown');assert.equal(JSON.stringify(report).includes('"decision":"allow"'),false);
  });
  await withFixture(async({paths})=>{const out=await check({...paths,clock});assert.equal(out.decision,'allow');assert.equal((await verifyLog({logPath:paths.logPath,expected:out.audit,clock})).status,'pass');});
});
