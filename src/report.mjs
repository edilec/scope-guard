import { RULES } from './rules.mjs';
export const byCodeUnit=(a,b)=>a<b?-1:a>b?1:0;
const forbidden=/[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/u;
const roles=new Set(['@scope','@signature','@public-key','@request','@log']);
export function finding(ruleId,pointer='',role=RULES[ruleId]?.role) {
  const rule=RULES[ruleId];
  if(!rule||!roles.has(role)||typeof pointer!=='string'||forbidden.test(pointer))throw new Error('internal-rule');
  return {ruleId,severity:rule.severity,message:rule.message,location:{file:role,pointer}};
}
function envelope(status,rows,findings) {
  const ordered=findings.toSorted((a,b)=>byCodeUnit(a.location.file,b.location.file)||byCodeUnit(a.location.pointer??'',b.location.pointer??'')||byCodeUnit(a.ruleId,b.ruleId));
  return {schemaVersion:'1',tool:'scope-guard',status,summary:{checked:rows.filter(x=>x.decision!=='unknown').length,errors:ordered.filter(x=>x.severity==='error').length,warnings:ordered.filter(x=>x.severity==='warning').length,total:rows.length,allowed:rows.filter(x=>x.decision==='allow').length,denied:rows.filter(x=>x.decision==='deny').length,unknown:rows.filter(x=>x.decision==='unknown').length},findings:ordered};
}
export function makeReport(rows,findings,audit=null) {
  const incomplete=!rows.length||rows.some(x=>x.decision==='unknown')||findings.some(f=>RULES[f.ruleId].disposition==='unknown');
  const status=incomplete?'incomplete':rows.some(x=>x.decision==='deny')?'fail':'pass';
  return {...envelope(status,rows,findings),decision:status==='pass'?'allow':status==='fail'?'deny':'unknown',decisions:rows.map(({targetSourceOrdinal,decision,ruleId})=>({targetSourceOrdinal,decision,ruleId})),...(audit?{audit}:{})};
}
export function makeLogReport(result) {
  const status=!result.complete?'incomplete':result.valid?'pass':'fail';
  const out=envelope(status,[],result.findings);
  out.summary.checked=result.recordCount;
  return {...out,recordCount:result.recordCount,head:result.valid&&result.complete?result.head:null};
}
export const exitFor=report=>report.status==='pass'?0:report.status==='fail'?1:2;
