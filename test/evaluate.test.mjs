import test from 'node:test';
import assert from 'node:assert/strict';
import { compileScope, compileRequests } from '../src/policy.mjs';
import { evaluateRequests } from '../src/evaluate.mjs';
import { makeBudget } from '../src/budget.mjs';
import { validScope, validRequest } from './support.mjs';
const b=()=>makeBudget(()=>0);
function evaluate(s=validScope(),r=validRequest()){return evaluateRequests(compileScope(s,b()),compileRequests(r,b()),b());}
test('permitted window boundaries are silent and one second outside denies',()=>{
  for(const [time,want,rule] of [['2026-10-13T10:00:00Z','allow','target-allowed'],['2026-10-13T12:00:00Z','allow','target-allowed'],['2026-10-13T09:59:59Z','deny','outside-test-window'],['2026-10-13T12:00:01Z','deny','outside-test-window'],['2026-10-13T08:59:59Z','deny','scope-not-yet-valid'],['2026-10-13T17:00:01Z','deny','scope-expired']]){
    const r=validRequest();r.decisionTime=time;r.requests[0].destinationIpCheckedAt=time;
    const out=evaluate(validScope(),r);assert.equal(out.decisions[0].decision,want);assert.equal(out.decisions[0].ruleId,rule);if(want==='allow')assert.deepEqual(out.findings,[]);
  }
});
test('domain and actual address cannot launder each other and exclusions win',()=>{
  for(const [changes,rule] of [[{target:'blocked.example.invalid'},'excluded-domain'],[{destinationIp:'192.0.2.128'},'excluded-ip'],[{target:'outside.invalid'},'domain-not-allowed'],[{destinationIp:'192.0.3.1'},'ip-not-allowed']]){
    const r=validRequest();Object.assign(r.requests[0],changes);const out=evaluate(validScope(),r);assert.equal(out.decisions[0].decision,'deny');assert.equal(out.decisions[0].ruleId,rule);
  }
  const s=validScope();s.allowedCidrs=[];s.excludedCidrs=[];assert.equal(evaluate(s).decisions[0].decision,'allow');
  s.excludedCidrs=['198.51.100.0/24'];assert.equal(evaluate(s).decisions[0].ruleId,'ip-not-allowed');
  const ipRequest=validRequest();ipRequest.requests=[{target:'192.0.2.0'},{target:'2001:db8::1'}];assert.deepEqual(evaluate(validScope(),ipRequest).decisions.map(x=>x.decision),['allow','allow']);
});
test('missing stale future and invalid tuples remain unknown before domain denial',()=>{
  for(const [change,rule] of [[r=>delete r.destinationIp,'destination-ip-missing'],[r=>delete r.destinationIpCheckedAt,'destination-ip-missing'],[r=>r.destinationIp='broken','destination-ip-invalid'],[r=>r.destinationIpCheckedAt='2026-10-13T09:59:59Z','destination-ip-stale'],[r=>r.destinationIpCheckedAt='2026-10-13T10:00:01Z','destination-ip-stale']]){
    const r=validRequest();change(r.requests[0]);r.requests[0].target='outside.invalid';const out=evaluate(validScope(),r);assert.equal(out.decisions[0].decision,'unknown');assert.equal(out.decisions[0].ruleId,rule);
  }
  const r=validRequest();r.requests.push({target:'192.0.2.129'},{target:'api.example.invalid'});
  assert.deepEqual(evaluate(validScope(),r).decisions.map(x=>x.decision),['allow','deny','unknown']);
});
