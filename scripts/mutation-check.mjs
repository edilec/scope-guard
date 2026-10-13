import { readFile, readdir, writeFile, mkdtemp, cp, rm, mkdir } from 'node:fs/promises';
import { join, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { DENIAL_IDS, refusalFixture } from '../test/refusal-fixtures.mjs';
import { withFixture, argsFor } from '../test/support.mjs';
const root=dirname(dirname(fileURLToPath(import.meta.url))),scratch=await mkdtemp(join(tmpdir(),'scope-guard-mutations-'));
const copy=join(scratch,'package');const receipt={kind:'denial-removal-sweep',results:[],sourceInventory:[]};
const sha=text=>createHash('sha256').update(text).digest('hex');
function run(bin,args) {
  const out=spawnSync(process.execPath,['--import',join(root,'test/offline-preload.mjs'),bin,...args],{encoding:'utf8',timeout:60000,cwd:copy});
  if(out.error||out.signal)throw new Error('Mutation process timed out or failed to execute; not a kill.');
  return {code:out.status,stdout:out.stdout,stderr:out.stderr};
}
try {
  await cp(root,copy,{recursive:true,filter:path=>!['.git','.receipts','node_modules'].some(name=>path===join(root,name)||path.startsWith(join(root,name)+'/'))&&!path.endsWith('.tgz')});
  const sources={};for(const name of (await readdir(join(root,'src'))).filter(n=>n.endsWith('.mjs')).sort()) {
    const text=await readFile(join(root,'src',name),'utf8');sources[name]=text;
    text.split('\n').forEach((line,i)=>{if(/throw|return .*unknown|return .*deny|guard:|\.sync\(|byCodeUnit|>\s*(?:1000|100000|10|LOG_|LINE_|BigInt|milliseconds)/u.test(line))receipt.sourceInventory.push({file:'src/'+name,line:i+1,construct:line.trim(),fileHash:sha(text),classification:line.includes('guard:')?'marked':name==='destination.mjs'?'destination-tests':'behavior-tests; not removal-enumerated'});});
  }
  for(const id of DENIAL_IDS) {
    const name=Object.keys(sources).find(n=>sources[n].includes('guard:'+id+':start'));if(!name)throw new Error('Missing denial marker: '+id);
    const original=sources[name],start=original.indexOf('/* guard:'+id+':start */'),end=original.indexOf('/* guard:'+id+':end */')+('/* guard:'+id+':end */').length;
    await withFixture(async({paths})=>{
      const baseline=run(join(copy,'bin/scope-guard.mjs'),argsFor({...paths,logPath:join(dirname(paths.logPath),'baseline.jsonl')}));
      const before=JSON.parse(baseline.stdout);if(baseline.code!==1||before.decisions[0].ruleId!==id)throw new Error('Refusal fixture is not isolated: '+id);
      await writeFile(join(copy,'src',name),original.slice(0,start)+original.slice(end));
      const mutant=run(join(copy,'bin/scope-guard.mjs'),argsFor(paths));
      const after=JSON.parse(mutant.stdout);if(mutant.code!==0||after.decision!=='allow')throw new Error('Removed denial did not change real CLI verdict: '+id);
      const regression=spawnSync(process.execPath,['--test','--test-name-pattern','^refusal '+id+'$',join(copy,'test/mutation-catalog.test.mjs')],{encoding:'utf8',timeout:60000,cwd:copy});
      if(regression.error||regression.signal||regression.status===0||!regression.stdout.includes('expected: 1'))throw new Error('Regression did not behaviorally reject removal: '+id);
      receipt.results.push({ruleId:id,file:'src/'+name,line:original.slice(0,start).split('\n').length,sourceHash:sha(original),baseline:baseline.code,mutant:mutant.code,regression:regression.status,result:'caught'});
      await writeFile(join(copy,'src',name),original);process.stdout.write(id+': deny changed to allow; regression caught removal\n');
    },refusalFixture(id));
  }
  receipt.unenumerated='The source inventory explicitly lists non-marked validation, incomplete, destination, sync, ordering and limit constructs. Only the eight denial removals are claimed swept by this script; normal tests cover others. Independent review must assess the listed remainder.';
  await mkdir(join(root,'.receipts'),{recursive:true});await writeFile(join(root,'.receipts/mutations.json'),JSON.stringify(receipt,null,2)+'\n');
  process.stdout.write('Denial sweep: '+receipt.results.length+'/8 caught. Non-denial removal coverage is not claimed.\n');
}finally{await rm(scratch,{recursive:true,force:true});}
