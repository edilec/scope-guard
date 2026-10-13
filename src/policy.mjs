import { EvidenceError } from './errors.mjs';
import { normalizeDomain, parseAddress, parseCidr } from './addresses.mjs';
const scopeKeys=['schemaVersion','scopeId','validFrom','validUntil','allowedDomains','allowedCidrs','excludedDomains','excludedCidrs','testWindows','emergencyContacts'];
export const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const forbidden=/[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}\p{Cs}]/u;
function objectKeys(obj,keys,required=keys) {
  return obj!==null&&typeof obj==='object'&&!Array.isArray(obj)&&Object.keys(obj).every(k=>keys.includes(k))&&required.every(k=>Object.hasOwn(obj,k));
}
function usable(x,max){return typeof x==='string'&&x.trim().length>0&&[...x].length<=max&&!forbidden.test(x);}
export function utcSeconds(text) {
  if(typeof text!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(text))throw new Error('utc');
  const ms=Date.parse(text);if(!Number.isFinite(ms)||new Date(ms).toISOString().replace('.000Z','Z')!==text)throw new Error('utc');return ms;
}
export function compileScope(raw,budget) {
  let pointer='';
  const bad=()=>{throw new EvidenceError('scope-schema-invalid','@scope',pointer);};
  try {
    budget.checkpoint();if(!objectKeys(raw,scopeKeys)||raw.schemaVersion!=='1'||!usable(raw.scopeId,128))bad();
    const validFromMs=utcSeconds(raw.validFrom),validUntilMs=utcSeconds(raw.validUntil);if(validFromMs>validUntilMs)bad();
    const listKeys=['allowedDomains','allowedCidrs','excludedDomains','excludedCidrs'];
    if(listKeys.some(k=>!Array.isArray(raw[k])))bad();
    if(listKeys.reduce((n,k)=>n+raw[k].length,0)>1000)throw new EvidenceError('scope-rule-limit','@scope');
    if(raw.allowedDomains.length+raw.allowedCidrs.length===0)bad();
    const compiled={validFromMs,validUntilMs};
    for(const name of listKeys) {
      const seen=new Set();compiled[name]=raw[name].map((rule,i)=>{
        budget.checkpoint();pointer='/'+name+'/'+i;let normalized,key;
        if(name.endsWith('Domains')) {
          if(!objectKeys(rule,['name','includeSubdomains'])||typeof rule.includeSubdomains!=='boolean')bad();
          normalized={name:normalizeDomain(rule.name),includeSubdomains:rule.includeSubdomains};key=normalized.name;
        }else {normalized=parseCidr(rule);key=normalized.canonicalKey;}
        if(seen.has(key))bad();seen.add(key);return normalized;
      });
    }
    pointer='/testWindows';if(!Array.isArray(raw.testWindows)||!raw.testWindows.length||raw.testWindows.length>1000)bad();
    compiled.windows=raw.testWindows.map((w,i)=>{
      budget.checkpoint();pointer='/testWindows/'+i;if(!objectKeys(w,['start','end']))bad();
      const startMs=utcSeconds(w.start),endMs=utcSeconds(w.end);
      if(startMs>endMs||endMs<validFromMs||startMs>validUntilMs)bad();return {startMs,endMs};
    });
    const sorted=compiled.windows.toSorted((a,b)=>a.startMs-b.startMs);
    for(let i=1;i<sorted.length;i++)if(sorted[i].startMs<=sorted[i-1].endMs)bad();
    pointer='/emergencyContacts';if(!Array.isArray(raw.emergencyContacts)||!raw.emergencyContacts.length||raw.emergencyContacts.length>100)bad();
    for(const [i,c] of raw.emergencyContacts.entries()) {pointer='/emergencyContacts/'+i;if(!objectKeys(c,['name','channel'])||!usable(c.name,256)||!usable(c.channel,256))bad();}
    budget.checkpoint();return compiled;
  }catch(e){if(e instanceof EvidenceError&&['scope-schema-invalid','scope-rule-limit','evaluation-deadline'].includes(e.ruleId))throw e;bad();}
}
export function compileRequests(raw,budget) {
  const bad=()=>{throw new EvidenceError('request-schema-invalid','@request');};
  if(!objectKeys(raw,['schemaVersion','runId','decisionTime','requests'])||raw.schemaVersion!=='1'||typeof raw.runId!=='string'||!UUID.test(raw.runId)||!Array.isArray(raw.requests))bad();
  let decisionMs;try{decisionMs=utcSeconds(raw.decisionTime);}catch{bad();}
  if(!raw.requests.length)throw new EvidenceError('no-requests','@request','/requests');
  if(raw.requests.length>1000)throw new EvidenceError('request-limit','@request','/requests');
  const rows=raw.requests.map((row,i)=>{
    budget.checkpoint();const p='/requests/'+i,targetSourceOrdinal=i+1;
    try {
      if(!objectKeys(row,['target','destinationIp','destinationIpCheckedAt'],['target'])||typeof row.target!=='string')throw new EvidenceError('request-row-invalid','@request',p);
      let address;try{address=parseAddress(row.target);}catch{address=null;}
      if(address) {
        if(Object.keys(row).length!==1)throw new EvidenceError('request-row-invalid','@request',p);
        return {targetSourceOrdinal,parsed:{kind:'ip',address},problem:null};
      }
      if(/^[0-9.]+$/u.test(row.target)||row.target.includes(':'))throw new EvidenceError('request-row-invalid','@request',p+'/target');
      let hostname;try{hostname=normalizeDomain(row.target);}catch{throw new EvidenceError('request-row-invalid','@request',p+'/target');}
      if(!Object.hasOwn(row,'destinationIp')||!Object.hasOwn(row,'destinationIpCheckedAt'))throw new EvidenceError('destination-ip-missing','@request',p+'/destinationIp');
      try{address=parseAddress(row.destinationIp);}catch{throw new EvidenceError('destination-ip-invalid','@request',p+'/destinationIp');}
      try{utcSeconds(row.destinationIpCheckedAt);}catch{throw new EvidenceError('request-row-invalid','@request',p+'/destinationIpCheckedAt');}
      /* guard:destination-ip-stale:start */
      if(row.destinationIpCheckedAt!==raw.decisionTime)throw new EvidenceError('destination-ip-stale','@request',p+'/destinationIpCheckedAt');
      /* guard:destination-ip-stale:end */
      return {targetSourceOrdinal,parsed:{kind:'hostname',hostname,address},problem:null};
    }catch(e){return {targetSourceOrdinal,parsed:null,problem:e instanceof EvidenceError?e:new EvidenceError('request-row-invalid','@request',p)};}
  });
  return {runId:raw.runId,decisionTime:raw.decisionTime,decisionMs,rows};
}
