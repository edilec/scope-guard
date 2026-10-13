import { readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root=dirname(dirname(fileURLToPath(import.meta.url)));
const tests=(await readdir(join(root,'test'))).filter(x=>x.endsWith('.test.mjs')).sort().map(x=>join(root,'test',x));
if(!tests.length)throw new Error('No tests found.');
for(const args of [[join(root,'scripts/lint.mjs')],['--test',...tests]]) {
  const result=spawnSync(process.execPath,args,{stdio:'inherit',cwd:root});
  if(result.status!==0)process.exit(result.status??1);
}
