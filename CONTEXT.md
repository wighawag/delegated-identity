# CONTEXT: delegated-identity domain language

## What delegated-identity is

A small library for proving, without a wallet prompt per request, that a request speaks for an Ethereum account in an app. It is shared by every service that checks such requests (missiv, push-notification-server, the trigger service) and by the apps that sign them.

## Core domain terms

- **account**: the wallet's Ethereum address (lowercased), whom a request speaks for.
- **app origin**: the origin of the app the wallet authorized a key for (`https://game.example`, `http://192.168.1.10:5173`); a bare domain names `https://<domain>` (`http://` for localhost) through `fromDomainToOrigin`.
- **origin private key**: the secp256k1 key the app holds for the account in an app origin (with `@etherplay/connect`, the derived "origin key", also its on-chain signer). It is not named in any proof here: the key set is derived from it.
- **key set**: the account's two keys in an app, derived by `deriveKeySet` from the origin private key (each HKDF-SHA256 under its own label, never one converted from the other, so every device derives the same set): the **signing key** (Ed25519), which signs requests for the account, and the **encryption key** (X25519), which others encrypt messages to. Keys are 32 bytes, 0x-prefixed lowercase hex, written algorithm-tagged (`ed25519:0x…`, `x25519:0x…`) in the publication message.
- **key set reference** (`keySetRef`): the SHA-256 of the two tagged keys, naming a key set (missiv's `keyRef`).
- **ownership proof**: the wallet's EIP-191 signature over the publication message naming the key set and the app origin. The only secp256k1 and keccak in the package: Ethereum requires them there.
- **request envelope**: what the signing key signs per request (Ed25519 over the raw bytes, no EIP-191): the purpose line `delegated-identity ed25519 request v1`, the server origin, the route, a timestamp, the body's SHA-256. The SIGNATURE header is `<timestamp ms>:<signing key hex>:<signature hex>`; Ed25519 has no key recovery, so the key in it is a claim the verifiers check.
- **stateless check** (`verifyRequest`): the request signature and the ownership proof together, against a claimed account, key set and app origin. **Stateful check** (`verifyRequestSignature`): the request signature alone, against a key a service registered after checking its ownership proof once.
- **crypto backend**: WebCrypto (Ed25519, SHA-256) where the runtime has it, `@noble` otherwise (older browsers, plain-http origins); the derivation always runs in `@noble`. Every Ed25519 verify first runs the same JS pre-checks (canonical `S < L`, canonical and non-small-order `A` and `R`), so both backends accept the same signatures.
- **server origin**: the origin of the service a request is for; it binds a signature to one service.

## Conventions

- The publication message and the envelope's format are a wire contract: changing either invalidates every signature made over it, so a change is a new purpose line (`... request v2`) accepted beside the old, never an edit.
- Tests open no port and need no network.
