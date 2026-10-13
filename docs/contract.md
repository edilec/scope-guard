# Version 1 contract

All JSON is strict UTF-8, duplicate-key checked after decoding escaped keys, with unknown own properties refused. Missing evidence is incomplete, never silently omitted. Literal U+FFFD is permitted in generic JSON; invalid UTF-8 is refused. Object schema values below are exact fields, not an invitation to embed instructions or keys.

## Signed scope

```json
{"schemaVersion":"1","scopeId":"fixture-scope","validFrom":"2026-10-13T09:00:00Z","validUntil":"2026-10-13T17:00:00Z","allowedDomains":[{"name":"example.invalid","includeSubdomains":true}],"allowedCidrs":["192.0.2.0/24","2001:db8::/32"],"excludedDomains":[{"name":"blocked.example.invalid","includeSubdomains":true}],"excludedCidrs":["192.0.2.128/25"],"testWindows":[{"start":"2026-10-13T10:00:00Z","end":"2026-10-13T12:00:00Z"}],"emergencyContacts":[{"name":"Fixture Operator","channel":"fixture-only"}]}
```

Every displayed top-level field is required. `schemaVersion` is the string `1`. `scopeId` is printable, usable text1–128 code points. Contacts contain exactly `name` and `channel`, each usable text1–256 code points; at least one contact is required. Presence does not prove reachability. Text with C0/C1, DEL, line/paragraph separators, Unicode format/bidi controls or lone surrogates is refused. Whitespace-only text is unusable.

Validity requires start<=end. Windows contain exactly `start`,`end`, require start<=end and must intersect scope validity. Windows are not silently discarded or coalesced; duplicate/overlapping windows, including a shared inclusive endpoint, are invalid. Validity and window tests both apply and endpoints are inclusive. Exact UTC second strings must round-trip as real calendar dates; offsets, fractional seconds, leap-second60 and impossible dates are unsupported.

The four rule lists are required arrays totaling at most1000 entries, including exclusions. At least one allowed domain/CIDR is required. Domain entries contain exactly ASCII `name` and boolean `includeSubdomains`; case is normalized and one trailing root dot removed. Labels are1–63 characters, start/end with alphanumeric ASCII and may contain internal hyphens; the normalized name is at most253 bytes. No wildcards/Unicode/URL/port/userinfo/whitespace. Exact matching always applies; subdomain matching additionally requires its flag and a separating dot. ASCII A-label names are supplied by the operator; no IDN conversion or DNS lookup occurs.

CIDRs require a decimal prefix0..32 or0..128. Host bits are masked; normalized duplicates within a list are invalid. Overlaps between same-action rules are unioned; exclusions beat allowances. IPv4 is strict four-octet decimal, without leading zeros or shorthand. IPv6 compression and dotted tails are supported; zone IDs/brackets/ports are unsupported. Mapped IPv6 targets become IPv4 before checks; mapped IPv6 CIDRs are refused. Different address families never match.

Signature input is exactly64 binary bytes. Public key input is one Ed25519 SPKI PEM block with optional ASCII surrounding whitespace, at most16KiB; private/multiple/non-Ed25519 keys are refused. SHA-256 scope digest hashes original bytes; key fingerprint hashes canonical SPKI DER. Verification precedes scope schema use. Wrong well-formed signature => deny; missing/unreadable/malformed evidence => unknown. A self-declared key is unsupported schema and cannot replace the independently configured pin.

## Requests

```json
{"schemaVersion":"1","runId":"c84b1a10-3112-4a81-a0b3-000000000001","decisionTime":"2026-10-13T10:00:00Z","requests":[{"target":"api.example.invalid","destinationIp":"192.0.2.20","destinationIpCheckedAt":"2026-10-13T10:00:00Z"},{"target":"2001:db8::1"}]}
```

Outer fields are exactly these four, with canonical lowercase UUIDv4 `runId`. Do not put personal information in that correlation handle. The common `decisionTime` is explicit; no library or CLI ambient UTC fallback exists. Rows permit only `target`, `destinationIp`, `destinationIpCheckedAt`. A hostname requires actual IP and a strict UTC observation equal to `decisionTime`; older/future observation is unknown. A literal IP forbids redundant destination fields. Request rows with unsupported/malformed evidence remain as unknown rows while valid neighbors evaluate; malformed shared context, empty array or more than1000 rows is an incomplete invocation and writes no fabricated context/partial oversized batch.

A hostname needs an allowed domain. It must never match excluded domains or its actual IP an excluded CIDR. When any CIDR is present, its actual IP must match an allowed CIDR too; exclusions-only CIDRs cannot authorize it. A literal IP always needs an allowed CIDR. A caller can supply false evidence; this program cannot discover that offline. Neither an allowed domain nor an allowed IP overrides a failing check on the other.

## Reports and log

The report envelope is `schemaVersion`, `tool`, `status`, `summary`, `findings` plus aggregate `decision`, source-ordered `decisions`, and successful `audit`. Unknown dominates deny; any storage failure makes aggregate unknown and converts all provisional allow rows to unknown. `summary.checked` counts fully evaluated final rows; `total`,`allowed`,`denied`,`unknown` retain the full row accounting. Findings use stable fixed messages and logical roles plus known-field pointers; no input excerpt is emitted. Sorted findings use `(role,pointer,ruleId)` UTF-16 code units. JSON stdout has no progress text. Exit2 usage has empty stdout; exit2 subject failures have an incomplete report. A successful check has no findings.

Records have exactly `sequence`,`checkTime`,`scopeDigest`,`keyFingerprint`,`runId`,`targetSourceOrdinal`,`decision`,`ruleId`,`previousRecordHash`,`recordHash`, canonically ordered and newline terminated. Sequence begins at1; predecessor for the first record is64 zeroes. Hash domain separator is UTF-8 `scope-guard-log-v1\n`, followed by the canonical JSON body without `recordHash` or LF. All hashes are lowercase64-character SHA-256. Missing digest/fingerprint is represented by null only for unknown records; otherwise digests are required. Ordinals are1..1000 (0 is reserved for document-level unknown provenance); every known row receives a record when shared context and logging are usable. No target/contact/scope ID is stored.

Verify-log reports separate `recordCount`,`head` and the catalog envelope. Parsed structural/canonical/sequence/hash/checkpoint corruption => fail/exit1. Unreadable or unparseable/depth/byte/deadline-limited evidence and empty log => incomplete/exit2. Internal corruption blocks append in check as `log-existing-invalid`. No append repairs retained data. Optional expected count/head must be supplied together and valid; they are operator configuration. An unanchored valid prefix does not prove a tail was retained.

## Bounds

Scope1MiB; requests1MiB; key16KiB; signature64 bytes exactly; total target rules1000; request rows1000; contacts100; windows1000; parsed nodes100000; JSON maximum depth10 with root0; evaluation5000 monotonic injected ms; log16MiB and100000 records; canonical line4096 bytes including LF. Every capacity uses an inclusive legal maximum. Log projected bytes/count are checked before first write. Bound failure is incomplete, never silent truncation. Parsing-layer boundary acceptance does not make an otherwise unsupported schema valid. The100000-record cap is a supplementary ceiling; the byte cap can become decisive first.
