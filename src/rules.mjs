const unknown = {
  'input-unreadable':['@scope','Named input could not be read.'],
  'input-not-regular':['@scope','Named input is not a regular file.'],
  'input-utf8-invalid':['@scope','Input is not valid UTF-8.'],
  'json-invalid':['@scope','Input could not be parsed as JSON.'],
  'json-duplicate-key':['@scope','JSON contains a duplicate object key.'],
  'json-depth-limit':['@scope','JSON depth exceeds 10.'],
  'json-node-limit':['@scope','JSON nodes exceed 100000.'],
  'input-byte-limit':['@scope','Input exceeds its declared byte limit.'],
  'evaluation-deadline':['@request','Evaluation exceeded 5000 milliseconds.'],
  'public-key-invalid':['@public-key','Pinned key must be one Ed25519 SPKI public key.'],
  'signature-format-invalid':['@signature','Signature must be exactly 64 binary bytes.'],
  'scope-schema-invalid':['@scope','Scope does not satisfy the closed version 1 schema.'],
  'scope-rule-limit':['@scope','Scope target rules exceed 1000.'],
  'request-schema-invalid':['@request','Request context does not satisfy the closed version 1 schema.'],
  'request-row-invalid':['@request','Target row is unsupported or malformed.'],
  'request-limit':['@request','Requests exceed 1000.'],
  'no-requests':['@request','No target requests were provided.'],
  'destination-ip-missing':['@request','Hostname requires actual destination IP and observation time.'],
  'destination-ip-invalid':['@request','Actual destination IP is malformed.'],
  'destination-ip-stale':['@request','Destination observation time must equal the decision time.'],
  'destination-unsafe':['@log','Log destination aliases an input, follows a final link, or is unsafe.'],
  'log-busy':['@log','Log lock exists; another writer or retained crash lock prevents append.'],
  'log-io-failed':['@log','Log storage operation failed; no allow can be returned.'],
  'log-durability-failed':['@log','Log durability could not be established; no allow can be returned.'],
  'log-limit':['@log','Log capacity exceeds its declared byte or record limit.'],
  'log-existing-invalid':['@log','Existing log could not be verified; it was not repaired.'],
  'no-log-records':['@log','Log has no records to verify.']
};
const deny={
  'scope-signature-invalid':['@signature','Scope signature does not verify under the pinned key.'],
  'scope-not-yet-valid':['@request','Decision time precedes scope validity.'],
  'scope-expired':['@request','Decision time follows scope validity.'],
  'outside-test-window':['@request','Decision time is outside every signed test window.'],
  'excluded-domain':['@request','Target matches a signed domain exclusion.'],
  'excluded-ip':['@request','Actual address matches a signed IP exclusion.'],
  'domain-not-allowed':['@request','Hostname matches no signed domain allowance.'],
  'ip-not-allowed':['@request','Actual address matches no required signed CIDR allowance.']
};
const fail={
  'log-record-invalid':['@log','Parsed log record violates its canonical schema.'],
  'log-sequence-invalid':['@log','Log record sequence is not consecutive from one.'],
  'log-chain-invalid':['@log','Log hash chain does not match retained records.'],
  'log-checkpoint-mismatch':['@log','Log does not match the independently supplied count and head.']
};
export const RULES=Object.freeze(Object.fromEntries([
  ['target-allowed',Object.freeze({severity:'info',disposition:'allow',role:'@request',message:'Target satisfies the authenticated scope.'})],
  ...Object.entries({unknown,deny,fail}).flatMap(([disposition,table])=>Object.entries(table).map(([id,[role,message]])=>[id,Object.freeze({severity:'error',disposition,role,message})]))
]));
