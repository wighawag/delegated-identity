# delegated-identity

A wallet authorizes a DELEGATE key for an app's origin once, and the delegate key then signs each request. A service recovers both proofs and learns which account a request speaks for, with no wallet prompt per request.

- **The ownership proof**: the wallet's EIP-191 signature over the publication message naming the delegate key and the app origin (`originPublicKeyPublicationMessage`). Its text is fixed, byte for byte the one `@etherplay/connect-core` pre-signs at sign-in, so existing proofs stay valid.
- **The request signature**: the delegate key's signature over an EIP-191-hashed envelope, sent in the `SIGNATURE` header as `<timestamp ms>:<compact hex>:<recovery bit>`:

  ```
  delegated-identity request v1
  origin: <the server's origin>
  route: <METHOD> <path>
  timestamp: <ms>
  body: 0x<keccak256 of the raw body>
  ```

  A signature for one server, route or body verifies for no other, and one more than 60 s from the server's clock is refused. The package keeps no replay store: a server that must refuse a replay within the window keeps the signatures it accepted.

## Use

In the app:

```ts
import {
	delegatePublicKey,
	fromDomainToOrigin,
	originPublicKeyPublicationMessage,
	signRequest,
	REQUEST_SIGNATURE_HEADER,
} from 'delegated-identity';

// once per delegate key and app origin, by the wallet
const ownershipSignature = await wallet.signMessage({
	message: originPublicKeyPublicationMessage(location.origin, delegatePublicKey(delegatePrivateKey)),
});

// on every request, by the delegate key
const url = new URL('https://push.example/api/register');
const body = JSON.stringify({address, domain: location.host, ownershipSignature /* , ... */});
await fetch(url, {
	method: 'POST',
	headers: {
		[REQUEST_SIGNATURE_HEADER]: await signRequest(
			{serverOrigin: url.origin, method: 'POST', path: url.pathname, body},
			delegatePrivateKey,
		),
	},
	body,
});
```

On the server:

```ts
import {fromDomainToOrigin, verifyRequest} from 'delegated-identity';

const verified = await verifyRequest({
	serverOrigin: 'https://push.example', // this server's public origin
	method,
	path,
	body, // the request as received, the body raw
	signature: headers.SIGNATURE,
	appOrigin: fromDomainToOrigin(claim.domain),
	address: claim.address,
	ownershipSignature: claim.ownershipSignature,
});
// {ok: true, address, publicKey, timestamp} | {ok: false, reason: 'malformed' | 'expired' | 'not-authorized'}
```

`recoverRequestSigner` alone answers the delegate key that signed a request, for a server that looks the key up in its own registry instead of checking an ownership proof each time; `recoverAccount` alone answers the account an ownership proof names.

## Dependencies

Only `@noble/hashes` and `@noble/secp256k1`: EIP-191 hashing and recovery are done here, so an app or a library depending on this package does not pull in viem (its tests use viem as a dev dependency to cross-check both).

## License

MIT
