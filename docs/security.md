# Trust and failure boundaries

| Actor / input | Trusted boundary | Failure consequence and defense |
| --- | --- | --- |
| Untrusted scope author or substituted document | Operator-configured pinned public key | Ed25519 over exact bytes, no embedded-key authority, schema use after verification |
| Caller supplying a hostname/IP/time | Actual connection tuple supplied by caller | Missing/stale evidence unknown; domain/IP checks independent; dishonest caller cannot be detected offline |
| Private or malicious JSON/paths/contacts | Fixed program behavior and diagnostics | Closed schemas, bounded fatal decoding/duplicate scanner, no data-derived instructions/paths/excerpts in reports |
| Competing local writers | Exclusive lock for a resolved pathname and single-link log | Busy is unknown, no stale-lock deletion, hard-link aliases refused, descriptor identity checks |
| Unexpected output alias | All named/resolved inputs and no-follow open | Final symlink and input hard-link refusals before any write; descriptor recheck; never truncate |
| Local log editor | Retained hash chain, optionally independent expected count/head | Internal changes fail; tail loss needs checkpoint; complete replacement can be forged without independent evidence |
| Hostile ancestor-directory replacement | Operator-controlled local parent required | Portable path checks cannot provide openat-style resistance to a continuously hostile parent; no such claim |
| Storage/clock/platform failure | Completed write/sync/close/cleanup within injected budget | Unknown on any failure; no allow exposed, no rollback or retained-tail repair claimed |

This tool grants no legal authorization, signs no policy, performs no active network action and cannot prove another program used its decisions. Its public library exposes durable check, not the provisional evaluator. Callers must honor unknown and deny for every actual connection. Old reports are historical observations, not authorization tokens.

New logs and locks use0600. Existing log state is verified under a lock before append; projected capacity is enforced before writes. Appends never truncate. A partial write or sync failure may leave bytes that need preservation and operator review; future checks refuse a broken log. Retained locks are never automatically removed. Preserve both log and failure report before explicit recovery/rotation.

The POSIX path uses no-follow/append flags, fstat comparisons, file fsync, directory fsync on every append, descriptor close and owned-lock cleanup. A retry cannot assume a previous creation became durable. macOS is locally tested. Missing platform flags or unsupported sync fails closed. Durability depends on the operating system/filesystem honoring sync; these local tests cannot attest hardware or remote-filesystem guarantees.

The test barrier intercepts network entry points before native execution, including positive inert controls. No test starts a target listener or makes a DNS/HTTP call. Mutation results name the exact removals exercised; unenumerated validation/storage paths are disclosed rather than claimed covered. No private fixture key is saved or shipped.
