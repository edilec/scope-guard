import test from 'node:test';
import assert from 'node:assert/strict';
import { makeRecord, serializeRecord, verifyLogBytes } from '../src/log-records.mjs';
import { makeBudget } from '../src/budget.mjs';
const b=()=>makeBudget(()=>0);
export function records() {
  const out=[];let previousRecordHash='0'.repeat(64);
  for(let sequence=1;sequence<=3;sequence++){
    const r=makeRecord({sequence,checkTime:'2026-10-13T10:00:00Z',scopeDigest:'a'.repeat(64),keyFingerprint:'b'.repeat(64),runId:'c84b1a10-3112-4a81-a0b3-000000000001',targetSourceOrdinal:sequence,decision:'allow',ruleId:'target-allowed',previousRecordHash});
    out.push(r);previousRecordHash=r.recordHash;
  }return out;
}
const bytes=rows=>Buffer.concat(rows.map(serializeRecord));
test('canonical retained chain verifies; reorder middle removal and edits fail',()=>{
  const r=records();assert.equal(verifyLogBytes(bytes(r),b()).valid,true);
  for(const broken of [[r[1],r[0],r[2]],[r[0],r[2]],[r[0],{...r[1],decision:'deny'},r[2]],[{...r[0],sequence:2},r[1],r[2]],[{...r[0],recordHash:'c'.repeat(64)},r[1],r[2]]]){
    const result=verifyLogBytes(Buffer.from(broken.map(x=>JSON.stringify(x)).join('\n')+'\n'),b());assert.equal(result.valid,false);assert.equal(result.complete,true);assert.ok(result.findings.length);
  }
});
test('tail loss needs an external checkpoint; an unanchored prefix is honest',()=>{
  const r=records();const prefix=bytes(r.slice(0,2));assert.equal(verifyLogBytes(prefix,b()).valid,true);
  const out=verifyLogBytes(prefix,b(),{recordCount:3,head:r[2].recordHash});assert.equal(out.valid,false);assert.equal(out.findings[0].ruleId,'log-checkpoint-mismatch');
  assert.equal(verifyLogBytes(Buffer.alloc(0),b()).complete,false);
});
test('unparseable tail and duplicates are incomplete; noncanonical parsed records fail',()=>{
  const r=records(),good=bytes(r);
  assert.equal(verifyLogBytes(good.subarray(0,good.length-1),b()).complete,false);
  assert.equal(verifyLogBytes(Buffer.from('{"sequence":1,"sequence":1}\n'),b()).complete,false);
  const text=JSON.stringify(r[0],null,0).replace('{','{ ');const out=verifyLogBytes(Buffer.from(text+'\n'),b());assert.equal(out.complete,true);assert.equal(out.valid,false);
});
