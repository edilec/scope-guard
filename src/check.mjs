import { resolve } from 'node:path';
import { makeBudget } from './budget.mjs';
import { readBytes, parseUniqueJson } from './documents.mjs';
import { authenticateScope } from './authenticate.mjs';
import { compileScope, compileRequests } from './policy.mjs';
import { evaluateRequests } from './evaluate.mjs';
import { appendDecisions } from './log-store.mjs';
import { verifyLogBytes, LOG_BYTES } from './log-records.mjs';
import { EvidenceError, UsageError } from './errors.mjs';
import { finding, makeReport, makeLogReport } from './report.mjs';
const problem=(e,role)=>e instanceof EvidenceError?e:new EvidenceError('input-unreadable',role);
export async function checkWithIo(options,io) {
  const {scopePath,signaturePath,publicKeyPath,requestPath,logPath,clock}=options;
  if([scopePath,signaturePath,publicKeyPath,requestPath,logPath].some(p=>typeof p!=='string'||!p.length))throw new UsageError('All five explicit paths are required.');
  const budget=makeBudget(clock),registry=new Map(),protectedInputs=[scopePath,signaturePath,publicKeyPath,requestPath].map(p=>resolve(p));
  for(const p of protectedInputs)registry.set(p,{realPath:null,dev:null,ino:null});
  const errors=[],data={};
  for(const [role,path,max] of [['@request',requestPath,1048576],['@scope',scopePath,1048576],['@signature',signaturePath,64],['@public-key',publicKeyPath,16384]]) {
    try{data[role]=await readBytes(path,role,max,registry,budget);}catch(e){const p=problem(e,role);errors.push(p);if(p.ruleId==='evaluation-deadline')break;}
  }
  let requests=null,auth=null,scope=null;
  if(data['@request'])try{requests=compileRequests(parseUniqueJson(data['@request'],'@request',budget),budget);}catch(e){errors.push(problem(e,'@request'));}
  if(data['@scope']&&data['@signature']&&data['@public-key'])try{auth=authenticateScope(data['@scope'],data['@signature'],data['@public-key'],budget);}catch(e){errors.push(problem(e,'@public-key'));}
  if(auth?.authenticated)try{scope=compileScope(parseUniqueJson(data['@scope'],'@scope',budget),budget);}catch(e){errors.push(problem(e,'@scope'));}
  let provisional={decisions:[],findings:errors.map(e=>finding(e.ruleId,e.pointer,e.role))};
  if(requests) {
    if(errors.length||!auth||!auth.authenticated) {
      provisional.decisions=requests.rows.map(row=>{
        if(row.problem){provisional.findings.push(finding(row.problem.ruleId,row.problem.pointer,row.problem.role));return {targetSourceOrdinal:row.targetSourceOrdinal,decision:'unknown',ruleId:row.problem.ruleId};}
        if(errors.length)return {targetSourceOrdinal:row.targetSourceOrdinal,decision:'unknown',ruleId:errors[0].ruleId};
        /* guard:scope-signature-invalid:start */
        if(!auth.authenticated){provisional.findings.push(finding('scope-signature-invalid'));return {targetSourceOrdinal:row.targetSourceOrdinal,decision:'deny',ruleId:'scope-signature-invalid'};}
        /* guard:scope-signature-invalid:end */
        return {targetSourceOrdinal:row.targetSourceOrdinal,decision:'allow',ruleId:'target-allowed'};
      });
    }else {
      try{provisional=evaluateRequests(scope,requests,budget);}catch(e){const p=problem(e,'@request');provisional={decisions:requests.rows.map(r=>({targetSourceOrdinal:r.targetSourceOrdinal,decision:'unknown',ruleId:p.ruleId})),findings:[finding(p.ruleId,p.pointer,p.role)]};}
    }
  }
  if(!requests)return makeReport([],provisional.findings);
  try {
    const audit=await appendDecisions({logPath,protectedInputs,registry,...provisional,context:{checkTime:requests.decisionTime,scopeDigest:auth?.scopeDigest??null,keyFingerprint:auth?.keyFingerprint??null,runId:requests.runId},budget,io});
    budget.checkpoint();return makeReport(provisional.decisions,provisional.findings,audit);
  }catch(e) {
    const p=e instanceof EvidenceError?e:new EvidenceError('log-io-failed');
    const rows=provisional.decisions.map(row=>row.decision==='allow'?{...row,decision:'unknown',ruleId:p.ruleId}:row);
    return makeReport(rows,[...provisional.findings,finding(p.ruleId,p.pointer,p.role)]);
  }
}
export const check=options=>checkWithIo(options,undefined);
export async function verifyLog({logPath,expected=null,clock}) {
  if(typeof logPath!=='string'||!logPath.length)throw new UsageError('An explicit log path is required.');
  if(expected&&(!Number.isSafeInteger(expected.recordCount)||expected.recordCount<1||typeof expected.head!=='string'||!/^[0-9a-f]{64}$/u.test(expected.head)))throw new UsageError('Checkpoint count and head are invalid.');
  const budget=makeBudget(clock);
  try {
    const bytes=await readBytes(logPath,'@log',LOG_BYTES,new Map(),budget);
    const result=verifyLogBytes(bytes,budget,expected);budget.checkpoint();return makeLogReport(result);
  }catch(e){const p=problem(e,'@log');return makeLogReport({valid:false,complete:false,recordCount:0,head:null,findings:[finding(p.ruleId,p.pointer,p.ruleId==='evaluation-deadline'?'@log':p.role)]});}
}
