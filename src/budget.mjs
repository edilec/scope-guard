import { EvidenceError, UsageError } from './errors.mjs';
export function makeBudget(clock,milliseconds=5000) {
  if(typeof clock!=='function'||milliseconds!==5000)throw new UsageError('An explicit monotonic clock and fixed evaluation budget are required.');
  const start=clock();let last=start;
  return {checkpoint() {
    const now=clock();
    if(!Number.isFinite(now)||!Number.isFinite(start)||now<last||now-start>milliseconds)throw new EvidenceError('evaluation-deadline');
    last=now;
  }};
}
