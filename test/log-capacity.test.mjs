import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { verifyLogBytes, makeRecord, serializeRecord } from '../src/log-records.mjs';
import { makeBudget } from '../src/budget.mjs';
import { readBytes } from '../src/documents.mjs';
import { check } from '../src/index.mjs';
import { withFixture, clock } from './support.mjs';
const b=()=>makeBudget(clock);
function baseBody(sequence=1,targetSourceOrdinal=1) {return {sequence,checkTime:'2026-10-13T10:00:00Z',scopeDigest:'a'.repeat(64),keyFingerprint:'b'.repeat(64),runId:'c84b1a10-3112-4a81-a0b3-000000000001',targetSourceOrdinal,decision:'allow',ruleId:'target-allowed',previousRecordHash:'0'.repeat(64)};}
function exactValidLog(size) {
  const minimum=Buffer.byteLength(JSON.stringify({...baseBody(),recordHash:'a'.repeat(64)})+'\n');
  let count=0,used=0;
  while(used+minimum+String(count+1).length-1<=size){count++;used+=minimum+String(count).length-1;}
  const extra=size-used;if(extra>count)throw new Error('Cannot construct requested fixture.');
  let head='0'.repeat(64);const lines=[];
  for(let i=1;i<=count;i++){const record=makeRecord({...baseBody(i,i<=extra?10:1),previousRecordHash:head});lines.push(serializeRecord(record));head=record.recordHash;}
  const output=Buffer.concat(lines);assert.equal(output.length,size);return output;
}
test('line and record-count preflight bounds accept N before schema checks, reject N+1',()=>{
  const record=JSON.stringify(makeRecord(baseBody()));
  const line=Buffer.from(' '.repeat(4096-Buffer.byteLength(record)-1)+record+'\n');
  const exact=verifyLogBytes(line,b());assert.equal(exact.complete,true);assert.equal(exact.findings[0].ruleId,'log-record-invalid');
  const over=verifyLogBytes(Buffer.concat([Buffer.from(' '),line]),b());assert.equal(over.complete,false);assert.equal(over.findings[0].ruleId,'log-limit');
  const nodes=verifyLogBytes(Buffer.from('{}\n'.repeat(100000)),b());assert.equal(nodes.complete,true);assert.equal(nodes.findings[0].ruleId,'log-record-invalid');
  const nodesOver=verifyLogBytes(Buffer.from('{}\n'.repeat(100001)),b());assert.equal(nodesOver.complete,false);assert.equal(nodesOver.findings[0].ruleId,'log-limit');
  assert.equal(serializeRecord({v:'x'.repeat(4087)}).length,4096);
  assert.throws(()=>serializeRecord({v:'x'.repeat(4088)}),e=>e.ruleId==='log-limit');
});
test('valid retained log at 16 MiB verifies; projected append overflow preserves every byte',()=>withFixture(async({paths})=>{
  const full=exactValidLog(16777216);assert.equal(verifyLogBytes(full,b()).valid,true);
  const extra=verifyLogBytes(Buffer.concat([full,Buffer.from('\n')]),b());assert.equal(extra.complete,false);assert.equal(extra.findings[0].ruleId,'log-limit');
  await writeFile(paths.logPath,full);
  assert.equal((await readBytes(paths.logPath,'@log',16777216,new Map(),b())).length,16777216);
  const report=await check({...paths,clock});assert.equal(report.decision,'unknown');assert.ok(report.findings.some(f=>f.ruleId==='log-limit'));assert.deepEqual(await readFile(paths.logPath),full);
  await writeFile(paths.logPath,Buffer.concat([full,Buffer.from('\n')]));await assert.rejects(()=>readBytes(paths.logPath,'@log',16777216,new Map(),b()),e=>e.ruleId==='input-byte-limit');
}));
