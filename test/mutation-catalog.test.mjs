import test from 'node:test';
import assert from 'node:assert/strict';
import { RULES } from '../src/rules.mjs';
import { DENIAL_IDS, refusalFixture } from './refusal-fixtures.mjs';
import { withFixture, cli, argsFor } from './support.mjs';
test('every catalog denial has a unique real-entry refusal fixture',()=>{assert.deepEqual(Object.keys(RULES).filter(id=>RULES[id].disposition==='deny').sort(),DENIAL_IDS.toSorted());});
for(const id of DENIAL_IDS)test('refusal '+id,()=>withFixture(({paths})=>{
  const out=cli(argsFor(paths));assert.equal(out.code,1);assert.equal(out.report.status,'fail');assert.equal(out.report.decision,'deny');assert.equal(out.report.decisions[0].ruleId,id);assert.ok(out.report.findings.some(f=>f.ruleId===id&&f.severity==='error'));
},refusalFixture(id)));
