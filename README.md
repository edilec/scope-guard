# Scope Guard

Scope Guard verifies a signed testing scope and evaluates proposed actual destinations offline. An allow is returned only after every decision has been appended to a durable local log. Node >=22; zero runtime and development dependencies.

It never connects to targets, resolves DNS, scans, fetches policy, or signs scopes. A signed file expresses the operator's supplied scope; this program is not a source of legal authority. A scanner is protected only if its own connection path checks the actual destination for **every** connection and honors denial or unknown, including retries and redirects. A caller can lie about its destination and observation time; an offline guard cannot detect that.

## Run

```sh
node bin/scope-guard.mjs --help
node bin/scope-guard.mjs check \
  --scope examples/pass/scope.json \
  --signature examples/pass/scope.sig \
  --public-key examples/pass/public-key.pem \
  --request examples/pass/request.json \
  --log /absolute/operator-controlled-directory/decisions.jsonl
```

The log parent must already exist. The examples are synthetic historical decisions at an explicitly recorded fixture time, with `.invalid` hostnames and documentation-only IP ranges. Replace `pass` with `deny` or `unknown` and use a fresh log to see the other outcomes. No test or example uses a real target. The package bin is `scope-guard`; the commands above work directly in the source checkout without installation.

Stdout contains exactly one version-1 JSON report and a newline. A count summary goes to stderr. `--help` uses stderr and empty stdout. Exit0 means every target was fully evidenced and allowed with durable logging; exit1 means all were evaluated and at least one denied; exit2 means incomplete evidence, storage/execution failure, or invalid configuration. Invalid CLI configuration leaves stdout empty. Unreadable or malformed named inputs produce an incomplete JSON report. Unknown always blocks execution.

The public ESM library exports only `TOOL_ID`, `check`, `verifyLog`:

```js
import { check } from 'scope-guard';
import { performance } from 'node:perf_hooks';
const report = await check({
  scopePath: '/absolute/scope.json', signaturePath: '/absolute/scope.sig',
  publicKeyPath: '/absolute/pinned-key.pem', requestPath: '/absolute/request.json',
  logPath: '/absolute/operator-controlled-directory/decisions.jsonl',
  clock: () => performance.now()
});
if (report.decision !== 'allow') throw new Error('Testing blocked.');
```

This evaluates the explicit decision time in the request. It does not issue a reusable permission token or discover a live destination. The supplied clock is monotonic evaluation timing, separate from the explicit UTC decision time.

## Scope and destination evidence

An independently configured pinned SPKI PEM Ed25519 **public** key verifies a 64-byte binary detached signature over the **exact original scope bytes**. Reformatting semantically equal JSON invalidates the signature. An embedded key is an unsupported field and never replaces the pin. No private key is accepted, stored, or included in fixtures.

The [input contract](docs/contract.md) defines closed version1 schemas. UTC times are exact second-resolution `YYYY-MM-DDTHH:mm:ssZ`; validity and window endpoints are inclusive. Windows can extend validity when they intersect it: both constraints must pass. Exclusions take precedence. Domains use normalized ASCII names and an explicit subdomain flag, with a separating label boundary. Literal IPs require a CIDR allowance. Hostnames require a domain allowance and the supplied actual IP; when any CIDR exists in the scope, an allowed CIDR is also required. An exclusions-only CIDR list cannot authorize a hostname's IP.

Hostname `destinationIpCheckedAt` must **equal** the request `decisionTime`; missing, stale, future or malformed evidence is unknown. This is exact tuple/time binding, not measured DNS freshness. IPv4/IPv6 match parsed address bytes. IPv4-mapped IPv6 targets are normalized to IPv4; mapped IPv6 CIDRs are unsupported and must be expressed in IPv4. There is no wildcard inference, port/URL syntax or zone-ID support.

Reports/logs contain no raw targets, actual IPs, scope IDs or contacts. `@scope`, `@signature`, `@public-key`, `@request`, `@log` are logical source roles for the exact files named at invocation. Known-field JSON pointers locate evidence; target ordinals are one-based and request pointer indices zero-based. Findings sort by UTF-16 code units; row order remains source order. With identical input bytes, explicit clocks and the same starting log state, reports are byte-identical. Appending again changes the log state and audit head/count intentionally.

## Log verification and recovery

```sh
node bin/scope-guard.mjs verify-log --log /absolute/decisions.jsonl
node bin/scope-guard.mjs verify-log --log /absolute/decisions.jsonl \
  --expect-count 42 --expect-head LOWERCASE_64_CHARACTER_SHA256
```

Retain the successful check report's `audit.recordCount` and `audit.head` independently when retention matters. Unanchored verification detects internal modification, reordering and middle deletion. Tail deletion leaves a valid prefix and needs the independent checkpoint to detect it. A local actor who can replace a whole log can forge a new chain; an actor who can replace both log and checkpoint can forge both. This is **not independent tamper-proof evidence**, an external timestamp, or proof that other programs used the guard.

New logs are private mode0600. Writers exclusive-create `<resolved-log-name>.lock`; existing locks fail closed, including crash locks. Appends never truncate or repair a broken tail. Complete writes, file sync, new-file parent-directory sync, descriptor close and owned-lock cleanup precede allow. A failed/late append can leave records or a partial tail while its returned decision is unknown; no transaction rollback is claimed. Preserve a damaged log and the error report, review ownership of any lock, and select a fresh explicit log after operator-approved recovery. The tool never removes a preexisting lock or rotates/deletes evidence.

Destinations are **unconfined**: symbolic parent directories are followed, including macOS `/var` aliases. Final-component symlinks, input aliases/hard links and multi-link existing logs are refused. Use a trusted local parent directory; portable Node path operations are not a defense against an attacker continuously replacing ancestor directories. The local durability path has been tested on macOS/POSIX. Platforms without no-follow/append flags or working directory sync fail closed; Windows durability is not claimed.

## Limits and local checks

Scope bytes1MiB, total target rules1000, requests1000, JSON root-depth0/max-depth10, evaluation deadline5000 injected ms. Exactly-at-limit inputs are accepted; the next value is incomplete. Supplementary limits: request bytes1MiB, key bytes16KiB, signature64 bytes exactly, JSON nodes100000, contacts100, windows1000, retained log16MiB/100000 records, line4096 bytes including LF. Capacity is checked before append. The deadline is cooperative: bounded native operations are checked after completion, and a late result cannot allow. See [rules](docs/rules.md) and [security boundaries](docs/security.md).

```sh
node scripts/check.mjs
node scripts/mutation-check.mjs
npm pack --offline --ignore-scripts --pack-destination /absolute/existing-artifact-directory
node scripts/pack-check.mjs /absolute/scope-guard-0.1.0.tgz
```

All checks are local. The removal sweep proves all eight denial guards change the actual CLI verdict when removed and that their regression tests catch it; its receipt explicitly identifies other constructs that are not removal-swept. Development scripts/tests are not shipped in the runtime package. The artifact verifier exercises the extracted public library/bin from outside the package under a verified network barrier. Runtime, test and package checks do not authorize remote publishing.

MIT ©2026 Edilec Private Limited. [Reuse provenance](docs/provenance.md).
