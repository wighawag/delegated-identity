---
title: The publication names an Ed25519 signing key and an X25519 encryption key, and requests are signed with Ed25519
slug: ed25519-keys-in-the-publication
humanOnly: true
---

> Launch snapshot, records intent at creation, NOT maintained. Current truth: the code, `CONTEXT.md`, and the decision record in missiv (`docs/adr/0004-messaging-keys-one-ciphertext-server-checked-signatures.md`).

## Problem Statement

Every service that checks a delegated request (missiv, push-notification-server, etherfold's trigger service) recovers a secp256k1 key from each request signature and checks the wallet's proof for it. secp256k1 recovery is pure JS in every runtime (no WebCrypto has secp256k1): 1.35 ms on Node 24 with `@noble/secp256k1`, against 0.068 ms for an Ed25519 verify through WebCrypto (measured 2026-11-27). missiv, redesigned for throughput, needs a signing key that is cheap to verify and an encryption key for its messages, and the publication message is the one place a wallet authorizes keys for an app. Today it names only the secp256k1 origin key that `@etherplay/connect` derives, which is also an on-chain signer.

## Solution

A breaking change, decided with the human on 2026-11-27 because no production app depends on this package (a past demo exists but is broken). It is the one exception to the "wire is frozen, add a new purpose line beside the old" rule in `AGENTS.md` and `CONTEXT.md`: the rule itself stays, unchanged, and governs every change after this one, so this is the last edit of the wire. The work updates only what those files DESCRIBE (the delegate key, the publication message, the envelope) to the new wire:

- **The publication message names two keys instead of the origin key**: an Ed25519 signing key and an X25519 encryption key, each written with its algorithm tag (`ed25519:0x…`, `x25519:0x…`), for the app origin. The secp256k1 origin key is no longer named; it stays connect's on-chain signer.
- **The derivation lives here**: both keys from the origin private key, each HKDF-SHA256 under its own label (never one converted into the other), deterministic so every device of an account derives the same set. connect-core calls it at sign-in.
- **The request envelope is signed with Ed25519**: the same fields (purpose line, server origin, route, timestamp, body), the body hashed with SHA-256, signed over the raw bytes (no EIP-191: an Ed25519 key never signs transactions). Ed25519 has no key recovery, so the signature value names its signer's public key.
- **The verifiers**: `verifyRequest` for stateless services, keeping today's shape (the request, the claimed `address`, the claimed key set and the ownership signature; `not-authorized` when they do not recover `address`), and the two halves separately for services that keep a directory (verify the ownership proof once at registration, then only the Ed25519 signature per request).
- **One crypto module**: WebCrypto Ed25519 / X25519 / HKDF / SHA-256 where the runtime has them (current Chrome 137+ / 133+, Firefox 129+ / 130+, Safari 17+, Node, Cloudflare Workers, Bun 1.3.13+), `@noble/curves` / `@noble/hashes` otherwise. WebCrypto's Ed25519 rule cannot be configured (OpenSSL, BoringSSL and Safari differ on edge cases), so cheap JS pre-checks run before the native verify (canonical `S < L`, small-order `A` and `R` rejected) and every path accepts the same signatures. WebCrypto cannot import a raw Ed25519 / X25519 private seed, so the derivation runs in `@noble` (once, at sign-in) and WebCrypto serves the hot path. On a plain-http origin (no secure context, so no `crypto.subtle`) everything runs in `@noble`.
- **keccak only where Ethereum requires it**: the wallet's EIP-191 signature over the publication message.

## User Stories

1. As an app, I want to derive my account's Ed25519 and X25519 keys from the origin private key, so that every device derives the same keys without storing them.
2. As connect, I want the new publication message for an origin and a key set, so that the wallet (or the hosted popup, at sign-in) authorizes both keys in one signature.
3. As a wallet user, I want the message to state plainly what each key is for (signing for my account in this app, receiving encrypted messages), so that I know what I authorize.
4. As a service, I want to recover the account from a key set, an app origin and an ownership signature, so that I learn whom the keys speak for.
5. As an app, I want to sign a request (server origin, method, path, body, timestamp) with the Ed25519 key, so that a service knows it is mine without a wallet prompt.
6. As a stateless service, I want one call that checks the request signature and the ownership proof together against the claimed account, so that push-notification-server and the trigger service keep their current shape (a mismatch is `not-authorized`).
7. As a service with a key directory (missiv), I want to check only the Ed25519 request signature against a registered key, so that a request costs one native verify.
8. As a service, I want a request older or newer than the window (60 s) refused as `expired`, a malformed one as `malformed`, and one that does not recover the claimed account as `not-authorized`, as today.
9. As a maintainer, I want test vectors (derivation, publication message, envelope, signatures) pinned byte for byte and checked against both the WebCrypto and the JS path, so that the two never disagree.
10. As every consumer, I want a release numbered 0.2.0 and a changelog entry (a new `CHANGELOG.md`) naming the breaking change and its order (this package, then connect-core and its popup, then missiv, push-notification-server and the trigger service, then the apps), so that I can upgrade in step.

### Autonomy notes

- `humanOnly: true`: a wire change shared by several services and by wallets; its tasking is driven by the human.
- No open questions. Tasked in place (TASKING-PROTOCOL §6) on 2026-11-27, every story into the one task.

## Implementation and testing detail

Tasked in place with the human on 2026-11-27 into `work/tasks/` (`ed25519-keys-in-the-publication`), which carries the detail; the rationale is missiv's ADR-0004.

## Out of Scope

- Post-quantum keys (ML-KEM / ML-DSA): deferred; the algorithm tags are what keeps the message open to them (missiv ADR-0004).
- Accepting the old secp256k1 publication or envelope beside the new ones.
- connect-core's derivation call, popup and re-sign logic: `@etherplay/connect`'s plan `ed25519-keys-in-the-publication`.
- The consumers' changes (missiv's spec `scalable-direct-messaging`; push-notification-server; etherfold's triggers).

## Further Notes

- Who verifies this identity today: missiv's `work/notes/findings/shared-identity-across-services.md`.
- `AGENTS.md` says the wire is "signed by wallets and apps in production": there is no production app (the human, 2026-11-27; a past demo is broken). The frozen-wire rule is kept as written, so the new wire is meant to be final.
