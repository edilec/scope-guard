import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { appendDecisions } from '../src/log-store.mjs';
import { verifyLogBytes } from '../src/log-records.mjs';
import { makeBudget } from '../src/budget.mjs';
import { withFixture, faultIo } from './support.mjs';
export function options(paths) {return {logPath:paths.logPath,protectedInputs:[paths.scopePath,paths.signaturePath,paths.publicKeyPath,paths.requestPath],registry:new Map(),decisions:[{targetSourceOrdinal:1,decision:'allow',ruleId:'target-allowed'}],context:{checkTime:'2026-10-13T10:00:00Z',runId:'c84b1a10-3112-4a81-a0b3-000000000001',scopeDigest:'a'.repeat(64),keyFingerprint:'b'.repeat(64)},budget:makeBudget(()=>0)};}
test('real appends retain records and return durable count/head',()=>withFixture(async({paths})=>{
  const first=await appendDecisions(options(paths));assert.equal(first.recordCount,1);
  const second=await appendDecisions(options(paths));assert.equal(second.recordCount,2);assert.notEqual(first.head,second.head);
  const result=verifyLogBytes(await fs.readFile(paths.logPath),makeBudget(()=>0),second);assert.equal(result.valid,true);
  assert.equal((await fs.stat(paths.logPath)).mode&0o777,0o600);
}));
test('broken and busy logs cannot be appended or silently repaired',()=>withFixture(async({paths})=>{
  await fs.writeFile(paths.logPath,'broken');await assert.rejects(()=>appendDecisions(options(paths)),e=>e.ruleId==='log-existing-invalid');assert.equal(await fs.readFile(paths.logPath,'utf8'),'broken');
  await fs.unlink(paths.logPath);await fs.writeFile(paths.logPath+'.lock','owned-elsewhere');await assert.rejects(()=>appendDecisions(options(paths)),e=>e.ruleId==='log-busy');assert.equal(await fs.readFile(paths.logPath+'.lock','utf8'),'owned-elsewhere');
}));
test('zero writes and failed sync/close deny completion; short writes are completed',async()=>{
  for(const [method,rule] of [['write','log-io-failed'],['sync','log-durability-failed'],['close','log-durability-failed']])await withFixture(async({paths})=>{
    const io=faultIo(method,()=>{if(method==='write')return {bytesWritten:0};throw new Error('private-error-sentinel');});
    await assert.rejects(()=>appendDecisions({...options(paths),io}),e=>e.ruleId===rule&&!e.message.includes('private'));
  });
  await withFixture(async({paths})=>{
    const io=faultIo('write',(h,buffer,offset,length,position)=>h.write(buffer,offset,Math.min(11,length),position));
    await appendDecisions({...options(paths),io});assert.equal(verifyLogBytes(await fs.readFile(paths.logPath),makeBudget(()=>0)).valid,true);
  });
});
test('log hard links to every protected input preserve original bytes',async()=>{
  for(const key of ['scopePath','signaturePath','publicKeyPath','requestPath'])await withFixture(async({paths})=>{
    const before=await fs.readFile(paths[key]);await fs.link(paths[key],paths.logPath);
    await assert.rejects(()=>appendDecisions(options(paths)),e=>e.ruleId==='destination-unsafe');assert.deepEqual(await fs.readFile(paths[key]),before);
  });
});
test('held exclusive lock makes concurrent writer unknown; retry preserves sequence',()=>withFixture(async({paths})=>{
  let release,signal;const held=new Promise(r=>release=r),created=new Promise(r=>signal=r);
  const io={...fs,open:async(...args)=>{const h=await fs.open(...args);if(String(args[0]).endsWith('.lock')){signal();await held;}return h;}};
  const first=appendDecisions({...options(paths),io});await created;
  await assert.rejects(()=>appendDecisions(options(paths)),e=>e.ruleId==='log-busy');release();await first;
  const retry=await appendDecisions(options(paths));assert.equal(retry.recordCount,2);
}));
test('parent durability and owned-lock cleanup failures cannot produce completion',async()=>{
  await withFixture(async({dir,paths})=>{
    const io={...fs,open:async(...args)=>{const h=await fs.open(...args);return new Proxy(h,{get(target,key){const value=target[key];if(key==='sync'&&String(args[0])===awaitableRealDir)return async()=>{throw new Error('directory sync failed');};return typeof value==='function'?value.bind(target):value;}});}};
    const awaitableRealDir=await fs.realpath(dir);await assert.rejects(()=>appendDecisions({...options(paths),io}),e=>e.ruleId==='log-durability-failed');
  });
  await withFixture(async({paths})=>{
    const io={...fs,unlink:async path=>{if(String(path).endsWith('.lock'))throw new Error('cleanup failed');return fs.unlink(path);}};
    await assert.rejects(()=>appendDecisions({...options(paths),io}),e=>e.ruleId==='log-durability-failed');
    assert.equal((await fs.stat(paths.logPath+'.lock')).isFile(),true);
  });
});
test('symlink substitution between check and open never overwrites the input',()=>withFixture(async({paths})=>{
  const before=await fs.readFile(paths.scopePath);let replaced=false;
  const io={...fs,open:async(...args)=>{
    if(String(args[0]).endsWith('decisions.jsonl')&&!replaced){replaced=true;await fs.symlink(paths.scopePath,args[0]);}
    return fs.open(...args);
  }};
  await assert.rejects(()=>appendDecisions({...options(paths),io}),e=>['log-io-failed','destination-unsafe'].includes(e.ruleId));assert.deepEqual(await fs.readFile(paths.scopePath),before);
}));
