import { RULES } from './rules.mjs';
export class EvidenceError extends Error {
  constructor(ruleId,role=RULES[ruleId]?.role,pointer='') {
    super(RULES[ruleId]?.message??'Internal evidence failure.');
    this.name='EvidenceError';this.ruleId=ruleId;this.role=role;this.pointer=pointer;
  }
}
export class UsageError extends Error {}
