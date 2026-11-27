// The `delegated-identity/ed25519` subpath: the package's Ed25519 and SHA-256,
// for a consumer that signs and verifies its own payloads with the key set's
// signing key (missiv's messages). Exported so that every consumer accepts the
// same signatures as the request verifiers: WebCrypto where the runtime has
// Ed25519, `@noble` otherwise, and the same JS pre-checks (a canonical `S`, `A`
// and `R` canonical and not of small order) before every verify, on both paths.

import {ed25519PublicKey, ed25519Sign, ed25519Verify, sha256} from './crypto.js';

export {ed25519PublicKey, ed25519Sign, ed25519Verify, sha256};
