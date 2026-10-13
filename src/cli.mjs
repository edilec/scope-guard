import { performance } from 'node:perf_hooks';
import { check, verifyLog } from './index.mjs';
import { UsageError } from './errors.mjs';
import { exitFor } from './report.mjs';
const usage='scope-guard check --scope PATH --signature PATH --public-key PATH --request PATH --log PATH\nscope-guard verify-log --log PATH [--expect-count N --expect-head SHA256]\nLogs are unconfined paths; symbolic parent directories are followed.\nDecision time is explicitly supplied in request.json.\n';
export function parseArgs(argv) {
  if(argv.length===1&&argv[0]==='--help')return {command:'help'};
  const [command,...tail]=argv;
  const flags=command==='check'?['--scope','--signature','--public-key','--request','--log']:command==='verify-log'?['--log','--expect-count','--expect-head']:null;
  if(!flags)throw new UsageError('Unknown or missing command.');
  const values={};
  for(let i=0;i<tail.length;i+=2){const flag=tail[i],value=tail[i+1];if(!flags.includes(flag)||Object.hasOwn(values,flag)||typeof value!=='string'||!value.length||value.startsWith('--'))throw new UsageError('Unknown, duplicate or missing option.');values[flag]=value;}
  if(command==='check'&&flags.some(flag=>!values[flag]))throw new UsageError('All check paths are required.');
  if(!values['--log'])throw new UsageError('Log path is required.');
  const paths={logPath:values['--log']};
  if(command==='check')Object.assign(paths,{scopePath:values['--scope'],signaturePath:values['--signature'],publicKeyPath:values['--public-key'],requestPath:values['--request']});
  let expected=null;
  if(values['--expect-count']||values['--expect-head']){
    const count=values['--expect-count'],head=values['--expect-head'];
    if(!count||!head||!/^[1-9][0-9]*$/u.test(count)||!Number.isSafeInteger(Number(count))||!/^[0-9a-f]{64}$/u.test(head))throw new UsageError('Checkpoint requires a positive count and lowercase SHA256 head.');
    expected={recordCount:Number(count),head};
  }
  return {command,paths,expected};
}
export async function runCli(argv,{stdout,stderr,clock=performance.now.bind(performance)}) {
  let args;try{args=parseArgs(argv);}catch(e){stderr.write((e instanceof UsageError?e.message:'Invalid configuration.')+'\n');return 2;}
  if(args.command==='help'){stderr.write(usage);return 0;}
  const report=await (args.command==='check'?check({...args.paths,clock}):verifyLog({...args.paths,expected:args.expected,clock}));
  stdout.write(JSON.stringify(report)+'\n');stderr.write('Scope Guard: '+report.status+'; checked '+report.summary.checked+'; errors '+report.summary.errors+'.\n');return exitFor(report);
}
