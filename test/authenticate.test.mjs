import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { authenticateScope } from '../src/authenticate.mjs';
import { makeBudget } from '../src/budget.mjs';
import { signedFixture, validScope } from './support.mjs';
const b=()=>makeBudget(()=>0);
test('only exact scope bytes and independent pinned key authenticate',()=>{
  const f=signedFixture();const a=authenticateScope(f.scopeBytes,f.signatureBytes,f.publicKeyBytes,b());
  assert.equal(a.authenticated,true);assert.equal(a.scopeDigest,createHash('sha256').update(f.scopeBytes).digest('hex'));
  assert.equal(a.keyFingerprint,createHash('sha256').update(createPublicKey(f.publicKeyBytes).export({type:'spki',format:'der'})).digest('hex'));
  const pretty=Buffer.from(JSON.stringify(JSON.parse(f.scopeBytes),null,2));
  assert.equal(authenticateScope(pretty,f.signatureBytes,f.publicKeyBytes,b()).authenticated,false);
  assert.equal(authenticateScope(f.scopeBytes,f.signatureBytes,signedFixture().publicKeyBytes,b()).authenticated,false);
  const embedded=signedFixture({...validScope(),publicKey:f.publicKeyBytes.toString()});
  assert.equal(authenticateScope(embedded.scopeBytes,embedded.signatureBytes,f.publicKeyBytes,b()).authenticated,false);
});
test('malformed signatures and non-public non-Ed25519 keys are unknown evidence',()=>{
  const f=signedFixture();for(const n of [0,63,65])assert.throws(()=>authenticateScope(f.scopeBytes,Buffer.alloc(n),f.publicKeyBytes,b()),e=>e.ruleId==='signature-format-invalid');
  const pair=generateKeyPairSync('ed25519');const rsa=generateKeyPairSync('rsa',{modulusLength:2048});
  for(const key of [Buffer.from('private sentinel'),Buffer.from(pair.privateKey.export({type:'pkcs8',format:'pem'})),Buffer.concat([f.publicKeyBytes,f.publicKeyBytes]),Buffer.from(rsa.publicKey.export({type:'spki',format:'pem'}))])
    assert.throws(()=>authenticateScope(f.scopeBytes,f.signatureBytes,key,b()),e=>e.ruleId==='public-key-invalid'&&!e.message.includes('sentinel'));
});
