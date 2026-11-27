---
title: The publication names an Ed25519 and an X25519 key, their derivation, and the Ed25519 request envelope with its verifiers
slug: ed25519-keys-in-the-publication
spec: ed25519-keys-in-the-publication
blockedBy: []
covers: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
---

## What to build

The whole of spec `ed25519-keys-in-the-publication` (`work/specs/tasked/`), as one breaking release, 0.2.0:

- **Derivation**: `deriveKeySet(originPrivateKey)` returns `{signing: {publicKey, privateKey}, encryption: {publicKey, privateKey}}`: an Ed25519 and an X25519 key, each HKDF-SHA256 of the origin private key under its own label (e.g. `delegated-identity ed25519 signing key`, `delegated-identity x25519 encryption key`), never one converted from the other; computed with `@noble` (WebCrypto cannot import raw seeds).
- **The publication message**: keeps its shape (the `Origin:` line, the warning, an authorization sentence) and lists both keys on their own lines, algorithm-tagged (`ed25519:0x…`, `x25519:0x…`), with what each is for (signing for the account in this app; receiving encrypted messages). `originPublicKeyPublicationMessage(origin, keySet)` replaces the secp256k1 form; `recoverAccount({appOrigin, keySet, ownershipSignature})` (EIP-191, keccak, `@noble/secp256k1`: the only secp256k1 left).
- **`keySetRef(keySet)`**: SHA-256 of the two tagged keys.
- **The request envelope**: the same fields (purpose line, server origin, route, timestamp, body), the body by its SHA-256, signed with Ed25519 over the raw bytes (no EIP-191). Header value `<timestamp>:<ed25519 public key hex>:<signature hex>`; the key in it is a claim. `signRequest`; a stateful check (the signature against a given key); the stateless `verifyRequest({..request, signature, appOrigin, address, keySet, ownershipSignature})` with today's refusals (`malformed`, `expired`, `not-authorized` when the proofs do not recover `address`). The app origin is passed explicitly, never rebuilt from a domain.
- **One crypto module**: WebCrypto Ed25519 / X25519 / HKDF / SHA-256 when `crypto.subtle` exists, `@noble/curves` / `@noble/hashes` otherwise (older browsers, plain-http origins). Before any Ed25519 verify, JS pre-checks reject a non-canonical `S` (`S >= L`) and small-order `A` or `R`, so WebCrypto's unconfigurable rule and the fallback accept the same signatures.
- **Docs**: `README.md` and `CONTEXT.md` describe the new keys, message and envelope; the frozen-wire rule in `AGENTS.md` and `CONTEXT.md` stays exactly as written (this change is its one exception; the new wire is meant to be final). A new `CHANGELOG.md` with the 0.2.0 entry: the breaking change and the consumers' order (this package; then `@etherplay/connect-core` 0.8.0 / `@etherplay/connect` 0.19.0 and the popup; then missiv, push-notification-server, etherfold's triggers; then the apps). `package.json` version 0.2.0; `@noble/curves` added.

## Acceptance criteria

- [ ] Vectors pin the derivation, the publication message, the envelope and a signature byte for byte, checked once with WebCrypto and once forcing the JS fallback
- [ ] Two derivations from one origin key are identical; the two keys are independent derivations
- [ ] `verifyRequest` refuses another key set, another `address`, another app origin, another server, route or body, an out-of-window timestamp and a malformed header, each with its reason
- [ ] A non-canonical or small-order Ed25519 signature is refused on both paths
- [ ] No secp256k1 publication or envelope remains in the exports
- [ ] README, CONTEXT.md and CHANGELOG.md describe the new wire; the frozen-wire rule text is unchanged
- [ ] Tests cover the new behaviour (mirror the repo's existing test style)

## Blocked by

- None, can start immediately.

## Prompt

Build the spec `work/specs/tasked/ed25519-keys-in-the-publication.md`. The decision and its measurements are in missiv's `docs/adr/0004-messaging-keys-one-ciphertext-server-checked-signatures.md`; who consumes this package is in missiv's `work/notes/findings/shared-identity-across-services.md`. Runtime support for the WebCrypto algorithms was checked on 2026-11-27 against MDN's compatibility data, Cloudflare's Web Crypto docs and Bun's 1.3.13 / 1.4 release notes; re-check rather than trust this line. Do not publish: releasing is the owner's (AGENTS.md).

FIRST, check this task against current reality (it is a launch snapshot and may have drifted): does it still match the code and the specs and plans it names? If a prerequisite landed differently than assumed, route the task to needs-attention with the discrepancy instead of building on a stale premise.

RECORD non-obvious in-scope decisions you make while building (an ADR if it meets the ADR gate in `work/protocol/ADR-FORMAT.md`, otherwise a JSDoc at the choice site or a `## Decisions` block for the done record).

Command cost: bound exploratory shell commands (`timeout 30`, cap output with `head`), never run an unbounded regex over minified, bundled or generated files, and never `grep -r` through `node_modules`, `dist` or `.git`.

Done means: the acceptance criteria hold and `dorfl.json`'s `verify` passes (`pnpm verify`).

---

### Claiming this task

```sh
dorfl claim ed25519-keys-in-the-publication --arbiter <remote>
git fetch <remote> && git switch -c work/ed25519-keys-in-the-publication <remote>/main
# on completion, in the work branch's PR/merge:
git mv work/tasks/ready/ed25519-keys-in-the-publication.md work/tasks/done/ed25519-keys-in-the-publication.md
```
