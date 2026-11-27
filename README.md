# delegated-identity

A wallet authorizes a KEY SET for an app's origin once, and the key set's signing key then signs each request. A service checks both proofs and learns which account a request speaks for, with no wallet prompt per request.

- **The key set**: an Ed25519 signing key and an X25519 encryption key, derived from the account's origin private key (`deriveKeySet`; with `@etherplay/connect`, its per-origin "origin key"). Each is HKDF-SHA256 of the origin private key under its own label (`delegated-identity ed25519 signing key`, `delegated-identity x25519 encryption key`), so every device of the account derives the same set and neither key is converted from the other. `keySetRef` names a key set: the SHA-256 of its two tagged keys.
- **The ownership proof**: the wallet's EIP-191 signature over the publication message (`originPublicKeyPublicationMessage(appOrigin, keySet)`), which names the app origin and both keys, algorithm-tagged, with what each is for:

  ```
  Origin: https://game.example

  IMPORTANT: Only sign on trusted websites.

  This authorizes the following keys for your account:

  Signing key, to act for your account in this app:
  ed25519:0x<signing key>

  Encryption key, for others to send you encrypted messages:
  x25519:0x<encryption key>
  ```

- **The request signature**: the signing key's Ed25519 signature over the raw bytes of an envelope (no EIP-191: an Ed25519 key never signs a transaction), sent in the `SIGNATURE` header as `<timestamp ms>:<signing key hex>:<signature hex>`:

  ```
  delegated-identity ed25519 request v1
  origin: <the server's origin>
  route: <METHOD> <path>
  timestamp: <ms>
  body: sha256:0x<SHA-256 of the raw body>
  ```

  Ed25519 has no key recovery, so the header names its key; that key is a claim, which the verifiers check. A signature for one server, route or body verifies for no other, and one more than 60 s from the server's clock is refused. The package keeps no replay store: a server that must refuse a replay within the window keeps the signatures it accepted.

## Use

In the app:

```ts
import {
	deriveKeySet,
	originPublicKeyPublicationMessage,
	signRequest,
	REQUEST_SIGNATURE_HEADER,
} from 'delegated-identity';

const keySet = deriveKeySet(originPrivateKey);

// once per key set and app origin, by the wallet
const ownershipSignature = await wallet.signMessage({
	message: originPublicKeyPublicationMessage(location.origin, keySet),
});

// on every request, by the signing key
const url = new URL('https://push.example/api/register');
const body = JSON.stringify({
	address,
	appOrigin: location.origin,
	keySet: {signing: {publicKey: keySet.signing.publicKey}, encryption: {publicKey: keySet.encryption.publicKey}},
	ownershipSignature,
	// ...
});
await fetch(url, {
	method: 'POST',
	headers: {
		[REQUEST_SIGNATURE_HEADER]: await signRequest(
			{serverOrigin: url.origin, method: 'POST', path: url.pathname, body},
			keySet.signing.privateKey,
		),
	},
	body,
});
```

On a stateless server, both proofs on every request:

```ts
import {verifyRequest} from 'delegated-identity';

const verified = await verifyRequest({
	serverOrigin: 'https://push.example', // this server's public origin
	method,
	path,
	body, // the request as received, the body raw
	signature: headers.SIGNATURE,
	appOrigin: claim.appOrigin, // the origin the wallet signed, passed as it is
	address: claim.address,
	keySet: claim.keySet,
	ownershipSignature: claim.ownershipSignature,
});
// {ok: true, address, publicKey, timestamp} | {ok: false, reason: 'malformed' | 'expired' | 'not-authorized'}
```

On a server that keeps a key directory, the ownership proof once at registration (`recoverAccount({appOrigin, keySet, ownershipSignature})` answers the account it names), then only the request signature: `parseRequestSignature(header)` names the claimed key (to look its account up) and `verifyRequestSignature({...request, signature, publicKey})` checks the request against the registered key, with the same refusals.

## Crypto

Ed25519 and SHA-256 run through WebCrypto where the runtime has them (Chrome 137+, Firefox 129+, Safari 17+, Node, Cloudflare Workers, Bun), and through `@noble/curves` / `@noble/hashes` otherwise (older browsers, and plain-http origins, which have no `crypto.subtle`). The derivation always runs in `@noble`, once at sign-in: WebCrypto cannot import a raw private seed. WebCrypto's Ed25519 rule cannot be configured and implementations differ on edge cases, so every verify first runs the same JS pre-checks (a canonical `S < L`, `A` and `R` canonical and not of small order): both paths accept the same signatures.

A consumer that signs its own payloads with the key set's signing key (missiv's messages) uses the same module through the `delegated-identity/ed25519` subpath, so it accepts exactly the signatures the request verifiers accept:

```ts
import {ed25519PublicKey, ed25519Sign, ed25519Verify, sha256} from 'delegated-identity/ed25519';

const signature = await ed25519Sign(payload, signingPrivateKeyBytes); // 64 bytes
const ok = await ed25519Verify(signature, payload, signingPublicKeyBytes); // pre-checks, then verify
```

## Dependencies

`@noble/curves`, `@noble/hashes` and `@noble/secp256k1` (EIP-191 recovery of the ownership proof, the only secp256k1 and keccak left). An app or a library depending on this package does not pull in viem (its tests use viem as a dev dependency to cross-check the EIP-191 side).

## License

MIT
