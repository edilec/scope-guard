import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { withFixture, signedFixture, validScope, validRequest, argsFor, cli } from './support.mjs';
test('private hostname/contact/unknown keys and malformed parse content never reach streams',async()=>{
  const s=validScope();s.allowedDomains=[{name:'private-sentinel.invalid',includeSubdomains:false}];s.emergencyContacts=[{name:'contact-sentinel',channel:'phone-sentinel'}];
  const r=validRequest();r.requests[0].target='private-sentinel.invalid';
  await withFixture(async({paths})=>{
    const pass=cli(argsFor(paths));assert.equal(pass.code,0);for(const secret of ['private-sentinel','contact-sentinel','phone-sentinel',paths.scopePath])assert.equal((pass.stdout+pass.stderr).includes(secret),false);
    await writeFile(paths.requestPath,'at position 1 "payload-secret"');const bad=cli(argsFor(paths));assert.equal(bad.code,2);assert.ok(bad.report.findings.some(f=>f.ruleId==='json-invalid'));assert.equal((bad.stdout+bad.stderr).includes('payload-secret'),false);
  },signedFixture(s,r));
});
test('every forbidden output character class in an identifier gives a located schema finding',async()=>{
  for(const character of ['\u0001','\u007f','\u0085','\u009b','\u2028','\u2029','\u202e','\u2066','\u200e','\u200b']){
    const s=validScope();s.scopeId='private'+character+'sentinel';
    await withFixture(({paths})=>{const out=cli(argsFor(paths));assert.equal(out.code,2);assert.ok(out.report.findings.some(f=>f.ruleId==='scope-schema-invalid'));assert.equal(out.stdout.includes('private'),false);assert.equal(out.stdout.includes(character),false);},signedFixture(s));
  }
});
