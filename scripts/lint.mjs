import { readdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root=dirname(dirname(fileURLToPath(import.meta.url)));
async function files(dir) {
  let entries; try {entries=await readdir(dir,{withFileTypes:true});}catch(e){if(e.code==='ENOENT')return [];throw e;}
  const out=[];
  for(const e of entries) {const p=join(dir,e.name); if(e.isDirectory())out.push(...await files(p));else if(e.isFile()&&p.endsWith('.mjs'))out.push(p);}
  return out;
}
for(const file of (await Promise.all(['bin','src','test','scripts'].map(d=>files(join(root,d))))).flat().sort()) {
  const r=spawnSync(process.execPath,['--check',file],{stdio:'inherit'});
  if(r.status!==0)process.exit(r.status??1);
}
