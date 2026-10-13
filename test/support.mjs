import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs/promises';
export const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
export const clock = () => 0;
export function validScope() { return {
  schemaVersion:'1', scopeId:'fixture-scope', validFrom:'2026-10-13T09:00:00Z', validUntil:'2026-10-13T17:00:00Z',
  allowedDomains:[{name:'example.invalid',includeSubdomains:true}], allowedCidrs:['192.0.2.0/24','2001:db8::/32'],
  excludedDomains:[{name:'blocked.example.invalid',includeSubdomains:true}], excludedCidrs:['192.0.2.128/25'],
  testWindows:[{start:'2026-10-13T10:00:00Z',end:'2026-10-13T12:00:00Z'}],
  emergencyContacts:[{name:'Fixture Operator',channel:'fixture-only'}]
}; }
export function validRequest() { return {schemaVersion:'1',runId:'c84b1a10-3112-4a81-a0b3-000000000001',decisionTime:'2026-10-13T10:00:00Z',requests:[{target:'api.example.invalid',destinationIp:'192.0.2.20',destinationIpCheckedAt:'2026-10-13T10:00:00Z'}]}; }
export function signedFixture(scope=validScope(), request=validRequest(), bytes=null) {
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const scopeBytes=bytes ?? Buffer.from(JSON.stringify(scope));
  return {scopeBytes,signatureBytes:sign(null,scopeBytes,privateKey),publicKeyBytes:Buffer.from(publicKey.export({type:'spki',format:'pem'})),requestBytes:Buffer.from(JSON.stringify(request))};
}
export async function withFixture(fn, fixture=signedFixture()) {
  const dir=await mkdtemp(join(tmpdir(),'scope-guard-'));
  const paths={scopePath:join(dir,'scope.json'),signaturePath:join(dir,'scope.sig'),publicKeyPath:join(dir,'public-key.pem'),requestPath:join(dir,'request.json'),logPath:join(dir,'decisions.jsonl')};
  try {
    for(const [pathKey,byteKey] of [['scopePath','scopeBytes'],['signaturePath','signatureBytes'],['publicKeyPath','publicKeyBytes'],['requestPath','requestBytes']]) await writeFile(paths[pathKey],fixture[byteKey]);
    return await fn({dir,paths,fixture});
  } finally {await rm(dir,{recursive:true,force:true});}
}
export function argsFor(paths) {return ['check','--scope',paths.scopePath,'--signature',paths.signaturePath,'--public-key',paths.publicKeyPath,'--request',paths.requestPath,'--log',paths.logPath];}
export function cli(args, options={}) {
  const result=spawnSync(process.execPath,[...(options.preload?['--import',join(packageRoot,'test/offline-preload.mjs')]:[]),join(packageRoot,'bin/scope-guard.mjs'),...args],{cwd:packageRoot,encoding:'utf8',timeout:30000,...options.spawn});
  if(result.error) throw result.error;
  return {code:result.status,stdout:result.stdout,stderr:result.stderr,report:result.stdout?JSON.parse(result.stdout):null};
}
export function faultIo(method,behavior) {
  let invoked=false;
  return {...fs,open:async(...args)=>{
    const handle=await fs.open(...args);
    return new Proxy(handle,{get(target,key){
      const value=target[key];if(typeof value!=='function')return value;
      if(key===method&&String(args[0]).endsWith('decisions.jsonl'))return async(...call)=>{
        if(!invoked){invoked=true;return behavior(target,...call);}return value.apply(target,call);
      };
      return value.bind(target);
    }});
  }};
}
