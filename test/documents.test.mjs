import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { parseUniqueJson, readBytes } from '../src/documents.mjs';
import { makeBudget } from '../src/budget.mjs';
import { withFixture } from './support.mjs';
export const budget=()=>makeBudget(()=>0);
const parse=x=>parseUniqueJson(Buffer.isBuffer(x)?x:Buffer.from(x),'@scope',budget());
test('strict JSON distinguishes duplicate keys and bad decoding from literal replacement characters',()=>{
  for(const s of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"n":{"x":1,"x":2}}'])assert.throws(()=>parse(s),e=>e.ruleId==='json-duplicate-key');
  assert.deepEqual(parse('{"a":"\uFFFD"}'),{a:'\uFFFD'});
  assert.throws(()=>parse(Buffer.from([0xc3,0x28])),e=>e.ruleId==='input-utf8-invalid');
  for(const s of ['\uFEFF{}','at position 1 secret-example','{"v": Infinity}'])assert.throws(()=>parse(s),e=>e.ruleId==='json-invalid'&&!e.message.includes('secret'));
});
test('depth and node bounds accept N and refuse N+1',()=>{
  assert.doesNotThrow(()=>parse('['.repeat(10)+'0'+']'.repeat(10)));
  assert.throws(()=>parse('['.repeat(11)+'0'+']'.repeat(11)),e=>e.ruleId==='json-depth-limit');
  assert.doesNotThrow(()=>parse('['+Array(99999).fill(0).join(',')+']'));
  assert.throws(()=>parse('['+Array(100000).fill(0).join(',')+']'),e=>e.ruleId==='json-node-limit');
});
test('evaluation uses injected monotonic time and exact deadline',()=>{
  const times=[0,5000,5001],b=makeBudget(()=>times.shift());
  assert.doesNotThrow(()=>b.checkpoint());assert.throws(()=>b.checkpoint(),e=>e.ruleId==='evaluation-deadline');
});
test('bounded regular-file reads preserve registry for failed names',()=>withFixture(async({dir})=>{
  const p=join(dir,'bounded');const r=new Map();
  await writeFile(p,Buffer.alloc(16));assert.equal((await readBytes(p,'@scope',16,r,budget())).length,16);
  await writeFile(p,Buffer.alloc(17));await assert.rejects(()=>readBytes(p,'@scope',16,r,budget()),e=>e.ruleId==='input-byte-limit');
  const missing=join(dir,'missing');await assert.rejects(()=>readBytes(missing,'@request',16,r,budget()),e=>e.ruleId==='input-unreadable');assert.equal(r.has(missing),true);
  const d=join(dir,'directory');await mkdir(d);await assert.rejects(()=>readBytes(d,'@scope',16,r,budget()),e=>e.ruleId==='input-not-regular');
}));
