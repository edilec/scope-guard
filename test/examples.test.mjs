import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cli, argsFor, packageRoot } from './support.mjs';
for(const [name,code,decision,rule] of [['pass',0,'allow','target-allowed'],['deny',1,'deny','excluded-domain'],['unknown',2,'unknown','destination-ip-missing']])test('public '+name+' example independently runs offline',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'scope-guard-example-'));const base=join(packageRoot,'examples',name);
  try {
    const out=cli(argsFor({scopePath:join(base,'scope.json'),signaturePath:join(base,'scope.sig'),publicKeyPath:join(base,'public-key.pem'),requestPath:join(base,'request.json'),logPath:join(dir,'log.jsonl')}),{preload:true});
    assert.equal(out.code,code);assert.equal(out.report.decision,decision);assert.equal(out.report.decisions[0].ruleId,rule);if(code===0)assert.deepEqual(out.report.findings,[]);
  }finally{await rm(dir,{recursive:true,force:true});}
});
