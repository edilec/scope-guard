import { validScope, validRequest, signedFixture } from './support.mjs';
export const DENIAL_IDS=['scope-signature-invalid','scope-not-yet-valid','scope-expired','outside-test-window','excluded-domain','excluded-ip','domain-not-allowed','ip-not-allowed'];
export function refusalFixture(id) {
  const s=validScope(),r=validRequest();
  if(id==='scope-not-yet-valid'||id==='scope-expired') {
    s.testWindows=[{start:'2026-10-13T08:00:00Z',end:'2026-10-13T18:00:00Z'}];
    r.decisionTime=id==='scope-expired'?'2026-10-13T17:00:01Z':'2026-10-13T08:59:59Z';r.requests[0].destinationIpCheckedAt=r.decisionTime;
  }
  if(id==='outside-test-window'){r.decisionTime='2026-10-13T09:59:59Z';r.requests[0].destinationIpCheckedAt=r.decisionTime;}
  if(id==='excluded-domain')r.requests[0].target='blocked.example.invalid';
  if(id==='excluded-ip')r.requests[0].destinationIp='192.0.2.128';
  if(id==='domain-not-allowed')r.requests[0].target='outside.invalid';
  if(id==='ip-not-allowed')r.requests[0].destinationIp='192.0.3.1';
  const fixture=signedFixture(s,r);if(id==='scope-signature-invalid')fixture.publicKeyBytes=signedFixture().publicKeyBytes;
  return fixture;
}
