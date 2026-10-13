import test from 'node:test';
import assert from 'node:assert/strict';
import { validateManifest } from '../scripts/pack-check.mjs';
test('package manifest rejects escapes, private-key names, tests, logs and missing runtime',()=>{
  const names=['package/package.json','package/README.md','package/LICENSE','package/bin/scope-guard.mjs','package/src/index.mjs'];
  assert.doesNotThrow(()=>validateManifest(names));
  for(const extra of ['package/../outside','package/test/support.mjs','package/secret-private-key.pem','package/run.jsonl','/absolute'])assert.throws(()=>validateManifest([...names,extra]));
  assert.throws(()=>validateManifest(names.filter(x=>!x.endsWith('/LICENSE'))));
});
