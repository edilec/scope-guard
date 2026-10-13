import test from 'node:test';
import assert from 'node:assert/strict';
import { TOOL_ID } from '../src/index.mjs';
import { signedFixture } from './support.mjs';
import { verify, createPublicKey } from 'node:crypto';
import { makeReport, makeLogReport, exitFor, finding } from '../src/report.mjs';
test('package identity and exact signed synthetic evidence',()=>{
  assert.equal(TOOL_ID,'scope-guard');
  const f=signedFixture();
  assert.equal(verify(null,f.scopeBytes,createPublicKey(f.publicKeyBytes),f.signatureBytes),true);
});
const row=(decision,ruleId,n=1)=>({targetSourceOrdinal:n,decision,ruleId});
test('fully evidenced allow stays silent; unknown dominates denial',()=>{
  const pass=makeReport([row('allow','target-allowed')],[]);
  assert.equal(exitFor(pass),0);assert.deepEqual(pass.findings,[]);
  const fail=makeReport([row('deny','excluded-ip')],[finding('excluded-ip','/requests/0/target')]);
  assert.equal(exitFor(fail),1);assert.equal(fail.decision,'deny');
  const mixed=makeReport([row('deny','excluded-ip'),row('unknown','destination-ip-missing',2)],[finding('destination-ip-missing')]);
  assert.equal(exitFor(mixed),2);assert.equal(mixed.decision,'unknown');
  assert.equal(exitFor(makeReport([], [finding('no-requests')])),2);
  assert.equal(exitFor(makeReport([row('deny','excluded-ip')],[finding('log-io-failed')])),2);
  assert.throws(()=>finding('unregistered'),/internal-rule/);
});
test('code-unit report order differs from locale collation',()=>{
  const names=['a_b','a-b','a','Z'];
  const r=makeReport([row('deny','excluded-ip')],names.map(n=>finding('excluded-ip','/requests/'+n)));
  assert.deepEqual(r.findings.map(f=>f.location.pointer),['/requests/Z','/requests/a','/requests/a-b','/requests/a_b']);
});
test('log reports do not use the empty-target vacuous check',()=>{
  assert.equal(exitFor(makeLogReport({complete:true,valid:true,recordCount:3,head:'a'.repeat(64),findings:[]})),0);
  assert.equal(exitFor(makeLogReport({complete:true,valid:false,recordCount:2,head:null,findings:[finding('log-chain-invalid')]})),1);
});
test('logical provenance includes a root pointer for whole-input failures',()=>{
  for(const [id,role] of [['scope-signature-invalid','@signature'],['public-key-invalid','@public-key'],['log-io-failed','@log']]) {
    const report=makeReport([{targetSourceOrdinal:1,decision:'unknown',ruleId:id}],[finding(id)]);
    assert.deepEqual(report.findings[0].location,{file:role,pointer:''});
  }
});
