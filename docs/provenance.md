# Source provenance

Scope Guard is an independent Node ESM package with no third-party runtime or development packages. Cryptography uses Node's Ed25519 verification/SHA-256 built-ins; grammar parsing uses native JSON.parse plus an adapted duplicate/numeric scanner. No cryptographic primitive is invented.

| Local source | Revision observed | File SHA-256 | Selected behavior |
| --- | --- | --- | --- |
| `agent-permission-map/src/write-guard.mjs` | `d7c0c8bfb4194016ece9ded0068469533e6afa16` | `b9213aafdfd002775b260a10cc3f722607475574f5f80c15379b8bb358a8951a` | `assertWritableDestination`, input symlink-chain aliases, rooted parent confinement, device/inode checks; copied independently into destination.mjs |
| `error-budget-calculator/src/json.mjs` | `bd5e62fe418f3b0f4e9b1ef5ce09a4982d036d6b` | `d2f563feb6edb7f959ecc9ac3b1d03c65c5716a2a20efd5713d6b87f4e8cb6c9` | Decoded-key duplicate scanner and canonical decimal precision checks; adapted into documents.mjs with fixed safe errors, depth10, node cap and injected checkpoints |

The corresponding local files/licenses were read. Both sources are MIT ©2026 Edilec Private Limited; the complete copyright/permission notice is retained in the root LICENSE. Source hashes identify the exact bytes observed, without assuming a clean source checkout. Their dependency closure consists solely of Node built-ins; runtime imports never reach sibling tools. The original parser's read wrapper was not copied; Scope Guard uses bounded descriptor reads and identity/size/timestamp checks. The destination helper remains root-capable but this CLI passes null and does not claim output confinement. Its potentially detailed internal exceptions are replaced with fixed report rules at the log-store boundary.

Original scope/evaluation/log/CLI code implements the local approved design. Synthetic public example signatures were created using an ephemeral in-memory test key; only public key/signature/scope/request bytes are retained. No signing capability or private key is part of the product.
