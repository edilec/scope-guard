import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { checkWithIo } from '../src/check.mjs';
import { verifyLog } from '../src/index.mjs';
import { makeRecord, verifyLogBytes, serializeRecord } from '../src/log-records.mjs';
import { makeBudget } from '../src/budget.mjs';
import { withFixture, clock } from './support.mjs';
function body(ruleId='target-allowed') {return {sequence:1,checkTime:'2026-10-13T10:00:00Z',scopeDigest:'a'.repeat(64),keyFingerprint:'b'.repeat(64),runId:'c84b1a10-3112-4a81-a0b3-000000000001',targetSourceOrdinal:1,decision:'allow',ruleId,previousRecordHash:'0'.repeat(64)};}
test('persistently failed parent sync blocks the first check and every retry',()=>withFixture(async({dir,paths})=>{
  const parent=await fs.realpath(dir);let syncs=0;
  const io={...fs,open:async(...args)=>{const h=await fs.open(...args);return new Proxy(h,{get(target,key){const value=target[key];if(key==='sync'&&String(args[0])===parent)return async()=>{syncs++;throw new Error('persistently unsupported directory sync');};return typeof value==='function'?value.bind(target):value;}});}};
  for(let i=0;i<2;i++){const out=await checkWithIo({...paths,clock},io);assert.equal(out.decision,'unknown');assert.ok(out.findings.some(f=>f.ruleId==='log-durability-failed'));}
  assert.equal(syncs,2);
}));
test('non-string rule identifiers cannot masquerade as a canonical catalog member',()=>{
  for(const id of [['target-allowed'],null,7,true,{},['x']]) {
    const raw=body(id),record={...raw,recordHash:crypto.createHash('sha256').update('scope-guard-log-v1\n').update(JSON.stringify(raw)).digest('hex')};
    const result=verifyLogBytes(Buffer.from(JSON.stringify(record)+'\n'),makeBudget(clock));
    assert.equal(result.valid,false);assert.equal(result.complete,true);assert.equal(result.findings[0].ruleId,'log-record-invalid');
    assert.throws(()=>makeRecord(raw),e=>e.ruleId==='log-record-invalid');
  }
});
test('public verification checks the deadline after its final native hash',async()=>{
  for(const [elapsed,status] of [[5000,'pass'],[5001,'incomplete']])await withFixture(async({paths})=>{
    await fs.writeFile(paths.logPath,serializeRecord(makeRecord(body())));
    const original=crypto.createHash;let now=0;
    try {
      crypto.createHash=function(...args){const hash=original(...args),digest=hash.digest;hash.digest=function(...options){const result=digest.apply(this,options);now=elapsed;return result;};return hash;};syncBuiltinESMExports();
      const result=await verifyLog({logPath:paths.logPath,clock:()=>now});assert.equal(result.status,status);
      if(elapsed>5000){assert.equal(result.findings[0].ruleId,'evaluation-deadline');assert.equal(result.findings[0].location.file,'@log');}
    }finally{crypto.createHash=original;syncBuiltinESMExports();}
  });
});
