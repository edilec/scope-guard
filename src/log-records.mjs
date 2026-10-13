import { createHash } from 'node:crypto';
import { RULES } from './rules.mjs';
import { EvidenceError } from './errors.mjs';
import { finding } from './report.mjs';
import { parseUniqueJson } from './documents.mjs';
import { utcSeconds, UUID } from './policy.mjs';
export const LOG_BYTES=16*1024*1024,LOG_RECORDS=100000,LINE_BYTES=4096,ZERO_HEAD='0'.repeat(64);
const bodyKeys=['sequence','checkTime','scopeDigest','keyFingerprint','runId','targetSourceOrdinal','decision','ruleId','previousRecordHash'];
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/u.test(x);
function bodyOf(r){return Object.fromEntries(bodyKeys.map(k=>[k,r[k]]));}
function hashBody(body){return createHash('sha256').update('scope-guard-log-v1\n').update(JSON.stringify(body)).digest('hex');}
function validRecord(r) {
  if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).length!==10||![...bodyKeys,'recordHash'].every(k=>Object.hasOwn(r,k)))return false;
  if(!Number.isSafeInteger(r.sequence)||r.sequence<1||!Number.isSafeInteger(r.targetSourceOrdinal)||r.targetSourceOrdinal<0||r.targetSourceOrdinal>1000||typeof r.runId!=='string'||!UUID.test(r.runId))return false;
  try{utcSeconds(r.checkTime);}catch{return false;}
  if(typeof r.ruleId!=='string'||!Object.hasOwn(RULES,r.ruleId))return false;
  const rule=RULES[r.ruleId];if(rule.disposition!==r.decision||!['allow','deny','unknown'].includes(r.decision))return false;
  if(r.decision!=='unknown'&&r.targetSourceOrdinal===0)return false;
  if(!hex(r.previousRecordHash)||!hex(r.recordHash))return false;
  return [r.scopeDigest,r.keyFingerprint].every(x=>hex(x)||(x===null&&r.decision==='unknown'));
}
export function makeRecord(body) {
  const canonical=bodyOf(body),record={...canonical,recordHash:hashBody(canonical)};
  if(Object.keys(body).length!==9||!validRecord(record))throw new EvidenceError('log-record-invalid');return record;
}
export function serializeRecord(record) {
  const out=Buffer.from(JSON.stringify(record)+'\n');if(out.length>LINE_BYTES)throw new EvidenceError('log-limit');return out;
}
export function verifyLogBytes(bytes,budget,expected=null) {
  let count=0,head=ZERO_HEAD;
  const result=(valid,complete,ruleId=null,pointer='')=>({valid,complete,findings:ruleId?[finding(ruleId,pointer,'@log')]:[],recordCount:count,head});
  if(bytes.length>LOG_BYTES)return result(false,false,'log-limit');
  if(!bytes.length)return result(false,false,'no-log-records');
  let text;try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}catch{return result(false,false,'input-utf8-invalid');}
  if(!text.endsWith('\n'))return result(false,false,'json-invalid');
  const lines=text.slice(0,-1).split('\n');if(lines.length>LOG_RECORDS)return result(false,false,'log-limit');
  for(const line of lines) {
    const pointer='/records/'+(count+1);
    try {
      budget.checkpoint();if(Buffer.byteLength(line)+1>LINE_BYTES)return result(false,false,'log-limit',pointer);
      const record=parseUniqueJson(Buffer.from(line),'@log',budget);
      if(!validRecord(record)||line!==JSON.stringify({...bodyOf(record),recordHash:record.recordHash}))return result(false,true,'log-record-invalid',pointer);
      /* guard:log-sequence-invalid:start */
      if(record.sequence!==count+1)return result(false,true,'log-sequence-invalid',pointer);
      /* guard:log-sequence-invalid:end */
      /* guard:log-chain-invalid:start */
      if(record.previousRecordHash!==head||record.recordHash!==hashBody(bodyOf(record)))return result(false,true,'log-chain-invalid',pointer);
      /* guard:log-chain-invalid:end */
      count++;head=record.recordHash;
    }catch(e){return result(false,false,e instanceof EvidenceError?e.ruleId:'json-invalid',pointer);}
  }
  /* guard:log-checkpoint-mismatch:start */
  if(expected&&(expected.recordCount!==count||expected.head!==head))return result(false,true,'log-checkpoint-mismatch');
  /* guard:log-checkpoint-mismatch:end */
  return result(true,true);
}
