// The one crypto module: SHA-256 and Ed25519 sign / verify through WebCrypto
// where the runtime has them (current browsers, Node, Cloudflare Workers, Bun),
// `@noble/curves` / `@noble/hashes` otherwise (older browsers, and plain-http
// origins, which have no `crypto.subtle`). Both paths give the same bytes and
// accept the same signatures: Ed25519 is deterministic, and every verify runs
// the same JS pre-checks first (below).
//
// The derivation (HKDF-SHA256, the Ed25519 and X25519 public keys) always runs
// in `@noble`: WebCrypto cannot import a raw private seed, and it runs once, at
// sign-in. Not exported from the package: tests reach it to force a backend.

import {ed25519, x25519} from '@noble/curves/ed25519';
import {hkdf} from '@noble/hashes/hkdf';
import {sha256 as nobleSha256} from '@noble/hashes/sha2';
import {hexToBytes} from '@noble/hashes/utils';

export type Backend = 'webcrypto' | 'noble';

let forced: Backend | undefined;
let detected: Promise<Backend> | undefined;

/** Force a backend (tests), or `undefined` to detect it again. */
export function setCryptoBackend(backend: Backend | undefined): void {
	forced = backend;
	detected = undefined;
}

/** The backend in use: WebCrypto when it signs and verifies Ed25519 as RFC 8032 says, `@noble` otherwise. */
export function cryptoBackend(): Promise<Backend> {
	if (forced) {
		return Promise.resolve(forced);
	}
	detected ??= detect();
	return detected;
}

function subtle(): SubtleCrypto | undefined {
	return (globalThis as {crypto?: Crypto}).crypto?.subtle;
}

// RFC 8032, section 7.1, test 1 (the empty message).
const PROBE_SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const PROBE_PUBLIC_KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const PROBE_SIGNATURE =
	'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

async function detect(): Promise<Backend> {
	if (!subtle()) {
		return 'noble';
	}
	try {
		const message = new Uint8Array(0);
		const signature = await webCryptoSign(message, hexToBytes(PROBE_SEED));
		const ok = await webCryptoVerify(hexToBytes(PROBE_SIGNATURE), message, hexToBytes(PROBE_PUBLIC_KEY));
		return ok && equalBytes(signature, hexToBytes(PROBE_SIGNATURE)) ? 'webcrypto' : 'noble';
	} catch {
		return 'noble';
	}
}

/** A copy whose buffer is a plain ArrayBuffer, as WebCrypto's types want. */
function buffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
	return new Uint8Array(bytes);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
	return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
	const webCrypto = subtle();
	if (webCrypto && (await cryptoBackend()) === 'webcrypto') {
		return new Uint8Array(await webCrypto.digest('SHA-256', buffer(bytes)));
	}
	return nobleSha256(bytes);
}

/** HKDF-SHA256 with an empty salt. */
export function hkdfSha256(ikm: Uint8Array, info: string, length: number): Uint8Array {
	return hkdf(nobleSha256, ikm, new Uint8Array(0), info, length);
}

export function ed25519PublicKey(seed: Uint8Array): Uint8Array {
	return ed25519.getPublicKey(seed);
}

export function x25519PublicKey(privateKey: Uint8Array): Uint8Array {
	return x25519.getPublicKey(privateKey);
}

// The PKCS #8 wrapping of a raw Ed25519 seed (RFC 8410): WebCrypto imports a
// private key only in this form or as a JWK.
const PKCS8_ED25519_PREFIX = hexToBytes('302e020100300506032b657004220420');

async function webCryptoSign(message: Uint8Array, seed: Uint8Array): Promise<Uint8Array> {
	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
	pkcs8.set(PKCS8_ED25519_PREFIX);
	pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
	const key = await subtle()!.importKey('pkcs8', pkcs8, {name: 'Ed25519'}, false, ['sign']);
	return new Uint8Array(await subtle()!.sign({name: 'Ed25519'}, key, buffer(message)));
}

async function webCryptoVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
	let key: CryptoKey;
	try {
		key = await subtle()!.importKey('raw', buffer(publicKey), {name: 'Ed25519'}, false, ['verify']);
	} catch {
		return false; // not a point on the curve
	}
	return subtle()!.verify({name: 'Ed25519'}, key, buffer(signature), buffer(message));
}

/** An Ed25519 signature (64 bytes) of `message` by the 32-byte `seed`. */
export async function ed25519Sign(message: Uint8Array, seed: Uint8Array): Promise<Uint8Array> {
	if ((await cryptoBackend()) === 'webcrypto') {
		return webCryptoSign(message, seed);
	}
	return ed25519.sign(message, seed);
}

/**
 * Whether `signature` is `publicKey`'s Ed25519 signature of `message`. The
 * pre-checks run first on both paths (WebCrypto's rule cannot be configured,
 * and OpenSSL, BoringSSL and Safari differ on these edge cases), then the
 * `@noble` path verifies under RFC 8032's strict decoding (`zip215: false`).
 */
export async function ed25519Verify(
	signature: Uint8Array,
	message: Uint8Array,
	publicKey: Uint8Array,
): Promise<boolean> {
	if (!passesPreChecks(signature, publicKey)) {
		return false;
	}
	if ((await cryptoBackend()) === 'webcrypto') {
		return webCryptoVerify(signature, message, publicKey);
	}
	try {
		return ed25519.verify(signature, message, publicKey, {zip215: false});
	} catch {
		return false;
	}
}

/** The group order L = 2^252 + 27742317777372353535851937790883648493. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
/** The field prime p = 2^255 - 19. */
const P = 2n ** 255n - 19n;

function littleEndian(bytes: Uint8Array): bigint {
	let n = 0n;
	for (let i = bytes.length - 1; i >= 0; i--) {
		n = (n << 8n) | BigInt(bytes[i]);
	}
	return n;
}

// The y coordinates of the eight small-order points (orders 1, 2, 4 and 8):
// 1, p - 1, 0 and the two order-8 values. A point is named by its y and the
// sign of x, so each y stands for both encodings (an x of 0 with the sign bit
// set is not a valid encoding, and is refused with it).
const SMALL_ORDER_Y = new Set<bigint>([
	0n,
	1n,
	P - 1n,
	littleEndian(hexToBytes('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05')),
	littleEndian(hexToBytes('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a')),
]);

/**
 * A point encoding a verifier may decode the same way everywhere: its y is
 * canonical (below p) and it is not one of the small-order points. A byte
 * comparison, no point decoding: cheap enough to run before every verify.
 */
function isAcceptablePoint(encoding: Uint8Array): boolean {
	const bytes = encoding.slice();
	bytes[31] &= 0x7f; // the sign of x
	const y = littleEndian(bytes);
	return y < P && !SMALL_ORDER_Y.has(y);
}

/**
 * The JS pre-checks every Ed25519 verify runs: a 32-byte key and a 64-byte
 * signature, a canonical `S` (`S < L`, so a signature has one encoding), and
 * `A` and `R` canonical and not of small order (a small-order `A` or `R` lets
 * a signature verify under one equation and not the other). Mixed-order points
 * (a torsion part beside a prime-order part) are not checked: that needs a
 * scalar multiplication, and only their own signer can produce them.
 */
export function passesPreChecks(signature: Uint8Array, publicKey: Uint8Array): boolean {
	if (signature.length !== 64 || publicKey.length !== 32) {
		return false;
	}
	return (
		littleEndian(signature.subarray(32)) < L &&
		isAcceptablePoint(publicKey) &&
		isAcceptablePoint(signature.subarray(0, 32))
	);
}
