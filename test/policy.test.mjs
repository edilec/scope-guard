import test from 'node:test';
import assert from 'node:assert/strict';
import { compileScope, compileRequests } from '../src/policy.mjs';
import { makeBudget } from '../src/budget.mjs';
import { validScope, validRequest } from './support.mjs';
const b=()=>makeBudget(()=>0);
test('signed scope rejects missing and unsupported fields without normalizing away bad data',()=>{
  for(const field of Object.keys(validScope())){const s=validScope();delete s[field];assert.throws(()=>compileScope(s,b()),e=>e.ruleId==='scope-schema-invalid');}
  for(const change of [s=>s.publicKey='attacker',s=>s.allowedDomains=[],s=>s.emergencyContacts=[],s=>s.scopeId='\u0085',s=>s.allowedDomains[0].includeSubdomains='true',s=>s.allowedDomains.push({name:'EXAMPLE.INVALID.',includeSubdomains:true}),s=>s.testWindows.push({...s.testWindows[0]}),s=>s.validUntil='2026-02-30T00:00:00Z',s=>s.testWindows[0]={start:'2026-10-13T18:00:00Z',end:'2026-10-13T19:00:00Z'}]) {
    const s=validScope();change(s);if(!s.allowedDomains.length)s.allowedCidrs=[];
    assert.throws(()=>compileScope(s,b()),e=>e.ruleId==='scope-schema-invalid');
  }
  const s=validScope();s.allowedCidrs.push('192.0.2.12/24');assert.throws(()=>compileScope(s,b()));
});
test('windows may extend validity; their usable intersection is unambiguous',()=>{
  const s=validScope();s.testWindows=[{start:'2026-10-13T08:00:00Z',end:'2026-10-13T18:00:00Z'}];
  assert.doesNotThrow(()=>compileScope(s,b()));
});
test('strict UTC and inclusive windows reject impossible dates, offsets and overlap',()=>{
  for(const time of ['2026-02-30T00:00:00Z','2026-10-13T10:00:60Z','2026-10-13T10:00:00+00:00','2026-10-13T10:00:00.000Z','2026-10-13T10:00:00Z ']){
    const r=validRequest();r.decisionTime=time;assert.throws(()=>compileRequests(r,b()),e=>e.ruleId==='request-schema-invalid');
  }
  const s=validScope();s.testWindows.push({start:'2026-10-13T12:00:00Z',end:'2026-10-13T13:00:00Z'});assert.throws(()=>compileScope(s,b()));
  s.testWindows[1].start='2026-10-13T12:00:01Z';assert.doesNotThrow(()=>compileScope(s,b()));
});
test('shared request schema and limit never produce a vacuous allow',()=>{
  const r=validRequest();r.requests=[];assert.throws(()=>compileRequests(r,b()),e=>e.ruleId==='no-requests');
  r.requests=Array.from({length:1001},()=>validRequest().requests[0]);assert.throws(()=>compileRequests(r,b()),e=>e.ruleId==='request-limit');
  assert.throws(()=>compileRequests({...validRequest(),extra:true},b()),e=>e.ruleId==='request-schema-invalid');
});
