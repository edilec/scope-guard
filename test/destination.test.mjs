import test from 'node:test';
import assert from 'node:assert/strict';
import { symlink, link, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { assertWritableDestination } from '../src/destination.mjs';
import { withFixture } from './support.mjs';
test('destination protects every input alias and permits ordinary unconfined paths',()=>withFixture(async({dir,paths})=>{
  const inputs=[paths.scopePath,paths.signaturePath,paths.publicKeyPath,paths.requestPath];
  const out=join(dir,'out');assert.equal(await assertWritableDestination(out,{inputs,root:null}),out);
  for(const [i,input] of inputs.entries()) {
    const before=await readFile(input),alias=join(dir,'hard'+i);await link(input,alias);
    await assert.rejects(()=>assertWritableDestination(alias,{inputs,root:null}));assert.deepEqual(await readFile(input),before);
  }
  const sym=join(dir,'symbolic');await symlink(paths.scopePath,sym);await assert.rejects(()=>assertWritableDestination(sym,{inputs}));
  const missing=join(dir,'missing-input');await symlink(out,missing);await assert.rejects(()=>assertWritableDestination(out,{inputs:[missing]}));
  const root=join(dir,'root'),outside=join(dir,'outside');await mkdir(root);await mkdir(outside);await symlink(outside,join(root,'escape'));
  await assert.rejects(()=>assertWritableDestination(join(root,'escape','out'),{inputs,root}));
  await writeFile(out,'ordinary');assert.equal(await assertWritableDestination(out,{inputs,root:null}),out);
}));
