import { containsAddress, domainMatches } from './addresses.mjs';
import { finding } from './report.mjs';
export function evaluateRequests(scope,requests,budget) {
  const findings=[];
  const decisions=requests.rows.map(row=>{
    budget.checkpoint();const result=(decision,ruleId,pointer)=>{if(decision!=='allow')findings.push(finding(ruleId,pointer));return {targetSourceOrdinal:row.targetSourceOrdinal,decision,ruleId};};
    if(row.problem)return result('unknown',row.problem.ruleId,row.problem.pointer);
    const {hostname,address}=row.parsed,nowMs=requests.decisionMs;
    const targetPointer='/requests/'+(row.targetSourceOrdinal-1)+'/'+(hostname?'destinationIp':'target');
    const deny=(ruleId,pointer=targetPointer)=>result('deny',ruleId,pointer);
    /* guard:scope-not-yet-valid:start */
    if(nowMs<scope.validFromMs)return deny('scope-not-yet-valid','/decisionTime');
    /* guard:scope-not-yet-valid:end */
    /* guard:scope-expired:start */
    if(nowMs>scope.validUntilMs)return deny('scope-expired','/decisionTime');
    /* guard:scope-expired:end */
    /* guard:outside-test-window:start */
    if(!scope.windows.some(w=>w.startMs<=nowMs&&nowMs<=w.endMs))return deny('outside-test-window','/decisionTime');
    /* guard:outside-test-window:end */
    /* guard:excluded-domain:start */
    if(hostname&&scope.excludedDomains.some(r=>domainMatches(r,hostname)))return deny('excluded-domain','/requests/'+(row.targetSourceOrdinal-1)+'/target');
    /* guard:excluded-domain:end */
    /* guard:excluded-ip:start */
    if(scope.excludedCidrs.some(c=>containsAddress(c,address)))return deny('excluded-ip');
    /* guard:excluded-ip:end */
    /* guard:domain-not-allowed:start */
    if(hostname&&!scope.allowedDomains.some(r=>domainMatches(r,hostname)))return deny('domain-not-allowed','/requests/'+(row.targetSourceOrdinal-1)+'/target');
    /* guard:domain-not-allowed:end */
    /* guard:ip-not-allowed:start */
    if((!hostname||scope.allowedCidrs.length+scope.excludedCidrs.length>0)&&!scope.allowedCidrs.some(c=>containsAddress(c,address)))return deny('ip-not-allowed');
    /* guard:ip-not-allowed:end */
    return result('allow','target-allowed');
  });
  return {decisions,findings};
}
