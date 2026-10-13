import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import * as fs from 'node:fs/promises';
import { checkWithIo } from '../src/check.mjs';
import { check } from '../src/index.mjs';
import { withFixture, validScope, validRequest, signedFixture, clock } from './support.mjs';
test('exact scope 1 MiB authenticates and permits; one extra byte is incomplete',async()=>{
  const content=Buffer.from(JSON.stringify(validScope()));
  for(const [size,want] of [[1048576,'allow'],[1048577,'unknown']]){
    const bytes=Buffer.concat([content,Buffer.alloc(size-content.length,0x20)]);
    await withFixture(async({paths})=>{const report=await check({...paths,clock});assert.equal(report.decision,want);if(want==='allow')assert.deepEqual(report.findings,[]);else assert.ok(report.findings.some(f=>f.ruleId==='input-byte-limit'));},signedFixture(validScope(),validRequest(),bytes));
  }
});
test('1000 total target rules permit; 1001 never silently truncates',async()=>{
  for(const [n,want] of [[1000,'allow'],[1001,'unknown']]){
    const s=validScope();s.allowedDomains=Array.from({length:n-4},(_,i)=>({name:'h'+i+'.example.invalid',includeSubdomains:false}));
    const r=validRequest();r.requests[0].target='h0.example.invalid';
    await withFixture(async({paths})=>{const out=await check({...paths,clock});assert.equal(out.decision,want);if(want==='unknown')assert.ok(out.findings.some(f=>f.ruleId==='scope-rule-limit'));},signedFixture(s,r));
  }
});
test('1000 request rows are all durably allowed; 1001 writes no partial batch',async()=>{
  for(const [n,want] of [[1000,'allow'],[1001,'unknown']]){
    const r=validRequest();r.requests=Array.from({length:n},()=>({...r.requests[0]}));
    await withFixture(async({paths})=>{const out=await check({...paths,clock});assert.equal(out.decision,want);if(want==='allow'){assert.equal(out.summary.allowed,1000);assert.equal(out.audit.recordCount,1000);}else {assert.ok(out.findings.some(f=>f.ruleId==='request-limit'));await assert.rejects(()=>fs.stat(paths.logPath),e=>e.code==='ENOENT');}},signedFixture(validScope(),r));
  }
});
test('request and pinned key byte limits have accepted exact controls',async()=>{
  for(const [type,max] of [['requestPath',1048576],['publicKeyPath',16384]])for(const [extra,want] of [[0,'allow'],[1,'unknown']])await withFixture(async({paths})=>{
    const original=await fs.readFile(paths[type]);await writeFile(paths[type],Buffer.concat([original,Buffer.alloc(max+extra-original.length,0x20)]));
    const out=await check({...paths,clock});assert.equal(out.decision,want);if(extra)assert.ok(out.findings.some(f=>f.ruleId==='input-byte-limit'));
  });
});
test('exact 5000 ms passes; final sync finishing after deadline prevents allow',async()=>{
  await withFixture(async({paths})=>{let first=true;const out=await check({...paths,clock:()=>{if(first){first=false;return 0;}return 5000;}});assert.equal(out.decision,'allow');});
  await withFixture(async({paths})=>{
    let late=false;const io={...fs,open:async(...args)=>{const handle=await fs.open(...args);return new Proxy(handle,{get(h,key){const v=h[key];if(key==='sync'&&String(args[0]).endsWith('decisions.jsonl'))return async()=>{await h.sync();late=true;};return typeof v==='function'?v.bind(h):v;}});}};
    const out=await checkWithIo({...paths,clock:()=>late?5001:0},io);assert.equal(out.decision,'unknown');assert.ok(out.findings.some(f=>f.ruleId==='evaluation-deadline'));assert.equal(JSON.stringify(out).includes('"decision":"allow"'),false);
  });
});
