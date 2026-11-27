# missiv expects Ed25519 sign/verify from this package, which 0.2.0 does not export

2026-11-27. missiv's task `one-ciphertext-message-format` (work/tasks/ready/) signs and verifies messages with "Ed25519 through `delegated-identity`'s key module", but delegated-identity 0.2.0 keeps its crypto module (`src/crypto.ts`, with the JS pre-checks) internal: the exports are only the key set, the publication, the envelope and its verifiers. Either missiv re-implements the pre-checks, or a later release exports `ed25519Sign` / `ed25519Verify` (a second consumer would justify it, per AGENTS.md).
