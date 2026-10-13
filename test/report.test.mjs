import test from 'node:test';
import assert from 'node:assert/strict';
import { TOOL_ID } from '../src/index.mjs';
import { signedFixture } from './support.mjs';
import { verify, createPublicKey } from 'node:crypto';
test('package identity and exact signed synthetic evidence',()=>{
  assert.equal(TOOL_ID,'scope-guard');
  const f=signedFixture();
  assert.equal(verify(null,f.scopeBytes,createPublicKey(f.publicKeyBytes),f.signatureBytes),true);
});
