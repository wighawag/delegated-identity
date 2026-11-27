# Changelog

## 0.2.0

**Breaking**: a new publication message and a new request envelope, replacing the secp256k1 ones; neither is accepted beside the other. Every proof and every request signature made with 0.1 stops verifying, so every connected account signs the new publication once (a hosted account by signing in again). This is the one exception to the frozen-wire rule (`AGENTS.md`, `CONTEXT.md`), made because no production app depends on the old wire; the rule governs every change after it. The decision and its measurements are in missiv's `docs/adr/0004-messaging-keys-one-ciphertext-server-checked-signatures.md`.

- **The key set**: `deriveKeySet(originPrivateKey)` returns `{signing, encryption}`, an Ed25519 and an X25519 key pair, each HKDF-SHA256 of the origin private key under its own label. `keySetRef(keySet)` is the SHA-256 of the two tagged keys.
- **The publication message** names the key set instead of the secp256k1 delegate key: `originPublicKeyPublicationMessage(appOrigin, keySet)`, each key on its own line, algorithm-tagged (`ed25519:0x…`, `x25519:0x…`), with what it is for. `recoverAccount({appOrigin, keySet, ownershipSignature})` (still EIP-191: the only secp256k1 and keccak left).
- **The request envelope** is signed with Ed25519 over its raw bytes (no EIP-191): purpose line `delegated-identity ed25519 request v1`, the body by its SHA-256. The `SIGNATURE` header is `<timestamp ms>:<signing key hex>:<signature hex>`.
- **The verifiers**: `verifyRequest` takes `keySet` instead of recovering a key; `verifyRequestSignature` (the request against a registered key) and `parseRequestSignature` (the header's claimed key) replace `recoverRequestSigner`.
- **Removed**: `delegatePublicKey`, `recoverRequestSigner`, the `PublicKey` type.
- **Crypto**: WebCrypto Ed25519 / SHA-256 where available, `@noble/curves` / `@noble/hashes` otherwise, with the same JS pre-checks before every Ed25519 verify. `requestMessage` and `keySetRef` are now async. New dependency: `@noble/curves`.
- **The `delegated-identity/ed25519` subpath** exports that module's `ed25519Sign`, `ed25519Verify` (with the pre-checks), `ed25519PublicKey` and `sha256`, for consumers that sign their own payloads with the signing key (missiv's messages).

Upgrade in this order:

1. This package, `delegated-identity` 0.2.0.
2. `@etherplay/connect-core` 0.8.0 and `@etherplay/connect` 0.19.0, with the wallet-host popup deployed.
3. The services: missiv, push-notification-server, etherfold's trigger service.
4. The apps.

## 0.1.1

- No viem: EIP-191 hashing and recovery on `@noble`.

## 0.1.0

- A wallet-delegated key and its proofs.
