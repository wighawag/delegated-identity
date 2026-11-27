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

## Decisions

- **The envelope's purpose line is `delegated-identity ed25519 request v1`, not `delegated-identity request v2`.** The frozen-wire convention, kept as written, uses `... request v2` as its example of the next format. Taking that exact line now would make the example point at the current wire. Naming the algorithm matches the tagged keys. The body line is tagged too: `body: sha256:0x…`. Alternative: `request v2`. Touches every verifier (missiv, push-notification-server, the trigger service).
- **The publication text is:** `Origin: …`, the warning, `This authorizes the following keys for your account:`, then `Signing key, to act for your account in this app:` / `ed25519:0x…` and `Encryption key, for others to send you encrypted messages:` / `x25519:0x…`. Keys are lowercased, and a malformed key throws. The spec fixed the shape but not the wording. Touches what wallets and the connect popup show users.
- **The derivation uses an empty HKDF salt**, with the labels `delegated-identity ed25519 signing key` and `delegated-identity x25519 encryption key`. The origin private key must be 32 bytes. `keySetRef` hashes `ed25519:0x…\nx25519:0x…` (UTF-8, lowercase). Touches connect-core's derivation and missiv's `keyRef`.
- **Signing also goes through WebCrypto.** The raw seed is wrapped in its fixed PKCS #8 prefix, and the check at startup confirms the WebCrypto signature equals RFC 8032's. Ed25519 is deterministic, so both backends give the same bytes, which the pinned vector checks on each path. Alternative: always sign in `@noble`, which is about 30 times slower per request according to ADR-0004's measurements.
- **The WebCrypto backend is chosen by an Ed25519 sign-and-verify test on first use, not just by `crypto.subtle` being present.** Older browsers have `crypto.subtle` without Ed25519. X25519 and HKDF are not routed through WebCrypto because this package only uses them in the derivation, which WebCrypto cannot do from a raw seed.
- **`requestMessage` and `keySetRef` are now async**, because SHA-256 goes through the same crypto module. Alternative: always hash synchronously in `@noble`. Touches missiv, which computes `keyRef`.
- **The per-request check is `verifyRequestSignature({...request, signature, publicKey})`.** It refuses with `not-authorized` when the header names another key or the signature fails. `parseRequestSignature(header)` is exported beside it, because missiv's `POST /session` must find the account from the claimed key before checking anything. Alternative: keep a "return the signer" call like the old `recoverRequestSigner`, which would let a caller forget to compare keys.
- **`verifyRequest` returns `malformed` for a malformed key set, and checks the cheap Ed25519 signature before the slower secp256k1 recovery.**
- **Mixed-order points are not pre-checked.** Rejecting them needs a scalar multiplication on every verify, which defeats cheap pre-checks, and only their own signer can produce such a signature. The `@noble` path verifies with `zip215: false`, the strict RFC 8032 decoding.
- **`fromDomainToOrigin` stays exported.** `verifyRequest` takes the app origin explicitly and the README no longer rebuilds it from a domain. Removing the helper is a breaking change the task did not ask for, and push-notification-server uses it today. Alternative: remove it in this breaking release.
