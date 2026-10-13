import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
export function validateManifest(names) {
  if(new Set(names).size!==names.length)throw new Error('Duplicate package entry.');
  for(const name of names) {
    if(!/^package\/(?:package\.json|README\.md|CHANGELOG\.md|LICENSE|(?:bin|src|docs|examples)\/[A-Za-z0-9._/-]+)$/u.test(name)||name.split('/').some(x=>x==='.'||x==='..')||/private-key|\.jsonl$|\.lock$/u.test(name))throw new Error('Unsafe or unexpected package entry.');
  }
  for(const name of ['package/package.json','package/README.md','package/LICENSE','package/bin/scope-guard.mjs','package/src/index.mjs'])if(!names.includes(name))throw new Error('Required package file missing.');
}
function command(program,args,options={}) {
  const r=spawnSync(program,args,{maxBuffer:2097152,timeout:60000,...options});if(r.error||r.status!==0)throw new Error('Local artifact operation failed.');return r.stdout;
}
export async function checkPackage(tarball) {
  if(typeof tarball!=='string'||!tarball.length)throw new Error('Pass a local npm-produced tarball.');
  const names=command('/usr/bin/tar',['-tf',tarball],{encoding:'utf8'}).trim().split('\n');validateManifest(names);
  const temporary=await mkdtemp(join(tmpdir(),'scope-guard-package-'));
  try {
    // Extract contents to new regular files; tar never receives a filesystem extraction destination.
    for(const name of names) {
      const content=command('/usr/bin/tar',['-xOf',tarball,name]);
      if(content.includes(Buffer.from('-----BEGIN PRIVATE KEY-----'))||content.includes(Buffer.from('-----BEGIN RSA PRIVATE KEY-----')))throw new Error('Private key in package.');
      const target=join(temporary,name);await mkdir(dirname(target),{recursive:true});await writeFile(target,content,{flag:'wx'});
    }
    const root=join(temporary,'package'),manifest=JSON.parse(await readFile(join(root,'package.json'),'utf8'));
    assert.equal(manifest.name,'scope-guard');assert.equal(manifest.type,'module');assert.equal(Object.keys(manifest.dependencies??{}).length,0);assert.equal(Object.keys(manifest.devDependencies??{}).length,0);
    const api=await import(pathToFileURL(join(root,'src/index.mjs')).href);assert.deepEqual(Object.keys(api).sort(),['TOOL_ID','check','verifyLog']);assert.equal(api.TOOL_ID,'scope-guard');
    for(const [example,code,decision] of [['pass',0,'allow'],['deny',1,'deny'],['unknown',2,'unknown']]) {
      const base=join(root,'examples',example),args=['check','--scope',join(base,'scope.json'),'--signature',join(base,'scope.sig'),'--public-key',join(base,'public-key.pem'),'--request',join(base,'request.json'),'--log',join(temporary,example+'.jsonl')];
      const r=spawnSync(process.execPath,['--import',join(dirname(dirname(fileURLToPath(import.meta.url))),'test/offline-preload.mjs'),join(root,'bin/scope-guard.mjs'),...args],{cwd:temporary,encoding:'utf8',timeout:60000});
      if(r.error)throw r.error;assert.equal(r.status,code,r.stderr);assert.equal(JSON.parse(r.stdout).decision,decision);
    }
    return {files:names.length,examples:3};
  }finally{await rm(temporary,{recursive:true,force:true});}
}
if(process.argv[1]&&realpathSync(process.argv[1])===fileURLToPath(import.meta.url))process.stdout.write(JSON.stringify(await checkPackage(process.argv[2]))+'\n');
