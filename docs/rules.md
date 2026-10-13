# Stable rule catalog

Finding severities and dispositions are separate: unknown makes a report incomplete, deny makes a complete check fail, and integrity failure makes verify-log fail. An allow rule is recorded without a finding. Errors are located by logical source role and known-field pointer; no raw target/contact/payload is echoed.

| Rule | Severity | Disposition | Default role | Observation |
| --- | --- | --- | --- | --- |
| `target-allowed` | info | allow | `@request` | Target satisfies the authenticated scope. |
| `input-unreadable` | error | unknown | `@scope` | Named input could not be read. |
| `input-not-regular` | error | unknown | `@scope` | Named input is not a regular file. |
| `input-utf8-invalid` | error | unknown | `@scope` | Input is not valid UTF-8. |
| `json-invalid` | error | unknown | `@scope` | Input could not be parsed as JSON. |
| `json-duplicate-key` | error | unknown | `@scope` | JSON contains a duplicate object key. |
| `json-depth-limit` | error | unknown | `@scope` | JSON depth exceeds 10. |
| `json-node-limit` | error | unknown | `@scope` | JSON nodes exceed 100000. |
| `input-byte-limit` | error | unknown | `@scope` | Input exceeds its declared byte limit. |
| `evaluation-deadline` | error | unknown | `@request` | Evaluation exceeded 5000 milliseconds. |
| `public-key-invalid` | error | unknown | `@public-key` | Pinned key must be one Ed25519 SPKI public key. |
| `signature-format-invalid` | error | unknown | `@signature` | Signature must be exactly 64 binary bytes. |
| `scope-schema-invalid` | error | unknown | `@scope` | Scope does not satisfy the closed version 1 schema. |
| `scope-rule-limit` | error | unknown | `@scope` | Scope target rules exceed 1000. |
| `request-schema-invalid` | error | unknown | `@request` | Request context does not satisfy the closed version 1 schema. |
| `request-row-invalid` | error | unknown | `@request` | Target row is unsupported or malformed. |
| `request-limit` | error | unknown | `@request` | Requests exceed 1000. |
| `no-requests` | error | unknown | `@request` | No target requests were provided. |
| `destination-ip-missing` | error | unknown | `@request` | Hostname requires actual destination IP and observation time. |
| `destination-ip-invalid` | error | unknown | `@request` | Actual destination IP is malformed. |
| `destination-ip-stale` | error | unknown | `@request` | Destination observation time must equal the decision time. |
| `destination-unsafe` | error | unknown | `@log` | Log destination aliases an input, follows a final link, or is unsafe. |
| `log-busy` | error | unknown | `@log` | Log lock exists; another writer or retained crash lock prevents append. |
| `log-io-failed` | error | unknown | `@log` | Log storage operation failed; no allow can be returned. |
| `log-durability-failed` | error | unknown | `@log` | Log durability could not be established; no allow can be returned. |
| `log-limit` | error | unknown | `@log` | Log capacity exceeds its declared byte or record limit. |
| `log-existing-invalid` | error | unknown | `@log` | Existing log could not be verified; it was not repaired. |
| `no-log-records` | error | unknown | `@log` | Log has no records to verify. |
| `scope-signature-invalid` | error | deny | `@signature` | Scope signature does not verify under the pinned key. |
| `scope-not-yet-valid` | error | deny | `@request` | Decision time precedes scope validity. |
| `scope-expired` | error | deny | `@request` | Decision time follows scope validity. |
| `outside-test-window` | error | deny | `@request` | Decision time is outside every signed test window. |
| `excluded-domain` | error | deny | `@request` | Target matches a signed domain exclusion. |
| `excluded-ip` | error | deny | `@request` | Actual address matches a signed IP exclusion. |
| `domain-not-allowed` | error | deny | `@request` | Hostname matches no signed domain allowance. |
| `ip-not-allowed` | error | deny | `@request` | Actual address matches no required signed CIDR allowance. |
| `log-record-invalid` | error | fail | `@log` | Parsed log record violates its canonical schema. |
| `log-sequence-invalid` | error | fail | `@log` | Log record sequence is not consecutive from one. |
| `log-chain-invalid` | error | fail | `@log` | Log hash chain does not match retained records. |
| `log-checkpoint-mismatch` | error | fail | `@log` | Log does not match the independently supplied count and head. |

Input findings use the actual fixed source role. Request pointers are zero-based, target/log ordinals one-based. Denial priority: signature, not-yet-valid, expired, window, excluded domain, excluded IP, domain allowance, IP allowance. Unknown evidence and storage failure dominate denial. A malformed existing log in check maps to log-existing-invalid; verify-log retains its precise integrity/incomplete rule.
