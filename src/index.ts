// An account's identity across services. A wallet authorizes a KEY SET for an
// app's origin once (the ownership proof: an EIP-191 signature over the
// publication message naming an Ed25519 signing key and an X25519 encryption
// key), and the signing key then signs each request (the request signature:
// Ed25519 over an envelope naming the server, the route, the time and the
// body). A service checks both and so learns, without a wallet prompt per
// request, which account a request speaks for.
//
// Every service that checks this pair (missiv, push-notification-server, the
// trigger service) uses this one implementation, and every app signs with it.

import {keccak_256} from '@noble/hashes/sha3';
import {bytesToHex, hexToBytes} from '@noble/hashes/utils';
import {Signature} from '@noble/secp256k1';
import {ed25519PublicKey, ed25519Sign, ed25519Verify, hkdfSha256, sha256, x25519PublicKey} from './crypto.js';

export type Address = `0x${string}`;
/** A 32-byte key, as 0x-prefixed lowercase hex. */
export type Key = `0x${string}`;
type PrivateKey = Uint8Array | `0x${string}`;

/** A public key and its private key. */
export type KeyPair = {publicKey: Key; privateKey: Key};

/** An account's keys in an app: an Ed25519 key that signs for it, an X25519 key others encrypt to. */
export type KeySet = {signing: KeyPair; encryption: KeyPair};

/** The public half of a key set, as a publication names it (a `KeySet` is one too). */
export type PublicKeySet = {signing: {publicKey: Key}; encryption: {publicKey: Key}};

/** The HTTP header carrying the request signature: `<timestamp ms>:<Ed25519 public key hex>:<signature hex>`. */
export const REQUEST_SIGNATURE_HEADER = 'SIGNATURE';

/** How far a request's timestamp may be from the server's clock, either way. */
export const DEFAULT_MAX_REQUEST_AGE_MS = 60_000;

/**
 * The origin an app's ownership proofs name, from what an app calls its domain:
 * an origin (`https://...` or `http://...`) is kept as it is; a bare host is
 * `http://` for localhost and `https://` otherwise.
 */
export function fromDomainToOrigin(domain: string): string {
	if (domain.startsWith('https://') || domain.startsWith('http://')) {
		return domain;
	}
	if (domain === 'localhost' || domain.startsWith('localhost:')) {
		return `http://${domain}`;
	}
	return `https://${domain}`;
}

const SIGNING_KEY_LABEL = 'delegated-identity ed25519 signing key';
const ENCRYPTION_KEY_LABEL = 'delegated-identity x25519 encryption key';

function toHex(bytes: Uint8Array): Key {
	return `0x${bytesToHex(bytes)}`;
}

/**
 * The key set of an account in an app, from its origin private key (with
 * `@etherplay/connect`, the origin key it derives per app origin): an Ed25519
 * key and an X25519 key, each HKDF-SHA256 of the origin private key (empty
 * salt) under its own label, never one converted from the other. Deterministic,
 * so every device of the account derives the same set. Throws unless the
 * origin private key is 32 bytes.
 */
export function deriveKeySet(originPrivateKey: PrivateKey): KeySet {
	const ikm = toPrivateKeyBytes(originPrivateKey);
	if (ikm.length !== 32) {
		throw new Error(`an origin private key is 32 bytes, got ${ikm.length}`);
	}
	const signing = hkdfSha256(ikm, SIGNING_KEY_LABEL, 32);
	const encryption = hkdfSha256(ikm, ENCRYPTION_KEY_LABEL, 32);
	return {
		signing: {publicKey: toHex(ed25519PublicKey(signing)), privateKey: toHex(signing)},
		encryption: {publicKey: toHex(x25519PublicKey(encryption)), privateKey: toHex(encryption)},
	};
}

const KEY_PATTERN = /^0x[0-9a-fA-F]{64}$/;

/** The two keys of a publication, algorithm-tagged, lowercase. Throws on a key that is not 32 bytes of hex. */
function taggedKeys(keySet: PublicKeySet): {signing: string; encryption: string} {
	const signing = keySet?.signing?.publicKey;
	const encryption = keySet?.encryption?.publicKey;
	if (typeof signing !== 'string' || !KEY_PATTERN.test(signing)) {
		throw new Error('the signing key is not 32 bytes of 0x-prefixed hex');
	}
	if (typeof encryption !== 'string' || !KEY_PATTERN.test(encryption)) {
		throw new Error('the encryption key is not 32 bytes of 0x-prefixed hex');
	}
	return {signing: `ed25519:${signing.toLowerCase()}`, encryption: `x25519:${encryption.toLowerCase()}`};
}

/**
 * The message a wallet signs to authorize a key set for an app's origin: the
 * origin, a warning, and each key on its own line, algorithm-tagged, with what
 * it is for. A wire contract: wallets sign it and every service checks it.
 * Throws on a malformed key.
 */
export function originPublicKeyPublicationMessage(orig: string, keySet: PublicKeySet): string {
	const keys = taggedKeys(keySet);
	return [
		`Origin: ${orig}`,
		'',
		'IMPORTANT: Only sign on trusted websites.',
		'',
		'This authorizes the following keys for your account:',
		'',
		'Signing key, to act for your account in this app:',
		keys.signing,
		'',
		'Encryption key, for others to send you encrypted messages:',
		keys.encryption,
	].join('\n');
}

const utf8 = new TextEncoder();

/**
 * A key set's reference: SHA-256 of its two tagged keys (`ed25519:0x…`, a
 * newline, `x25519:0x…`), as 0x-prefixed hex. Throws on a malformed key.
 */
export async function keySetRef(keySet: PublicKeySet): Promise<`0x${string}`> {
	const keys = taggedKeys(keySet);
	return toHex(await sha256(utf8.encode(`${keys.signing}\n${keys.encryption}`)));
}

/** EIP-191 (`personal_sign`): keccak256 of "\x19Ethereum Signed Message:\n" + the message's byte length + the message. */
function hashMessage(message: string): Uint8Array {
	const bytes = utf8.encode(message);
	const prefix = utf8.encode(`\x19Ethereum Signed Message:\n${bytes.length}`);
	const prefixed = new Uint8Array(prefix.length + bytes.length);
	prefixed.set(prefix);
	prefixed.set(bytes, prefix.length);
	return keccak_256(prefixed);
}

/**
 * The address (lowercase) that signed `message` with EIP-191, from a 65-byte
 * signature (r, s, v with v 27/28 or 0/1) or a 64-byte EIP-2098 one (the
 * parity in s's top bit). Throws on a malformed signature.
 */
function recoverMessageAddress(message: string, signature: `0x${string}`): Address {
	const bytes = hexToBytes(signature.slice(2));
	let compact: Uint8Array;
	let recovery: number;
	if (bytes.length === 65) {
		const v = bytes[64];
		recovery = v >= 27 ? v - 27 : v;
		compact = bytes.slice(0, 64);
	} else if (bytes.length === 64) {
		recovery = bytes[32] >> 7;
		compact = bytes.slice();
		compact[32] &= 0x7f;
	} else {
		throw new Error(`a signature is 64 or 65 bytes, got ${bytes.length}`);
	}
	if (recovery !== 0 && recovery !== 1) {
		throw new Error(`invalid recovery value`);
	}
	const point = Signature.fromCompact(compact).addRecoveryBit(recovery).recoverPublicKey(hashMessage(message));
	const uncompressed = point.toRawBytes(false);
	return `0x${bytesToHex(keccak_256(uncompressed.slice(1)).slice(12))}`;
}

function toPrivateKeyBytes(privateKey: PrivateKey): Uint8Array {
	return typeof privateKey === 'string' ? hexToBytes(privateKey.slice(2)) : privateKey;
}

/**
 * The account (lowercase) whose wallet signed the ownership proof of this key
 * set for this app origin. A proof for another key set or another origin
 * recovers another account. Throws on a malformed signature or key.
 */
export async function recoverAccount(proof: {
	appOrigin: string;
	keySet: PublicKeySet;
	ownershipSignature: `0x${string}`;
}): Promise<Address> {
	const message = originPublicKeyPublicationMessage(proof.appOrigin, proof.keySet);
	return recoverMessageAddress(message, proof.ownershipSignature);
}

/** What a request signature covers: which server, which route, when, and the body. */
export type RequestToSign = {
	/** the origin of the server the request is for, e.g. `https://push.example` */
	serverOrigin: string;
	/** the HTTP method, e.g. `POST` */
	method: string;
	/** the path and query, e.g. `/api/register` */
	path: string;
	/** the raw body, exactly as sent (`''` for none) */
	body: string;
};

/**
 * The envelope a signing key signs (Ed25519 over its UTF-8 bytes): a purpose
 * line, then the server origin, the route, the timestamp and the body's
 * SHA-256. A signature for one server, route or body verifies for no other.
 */
export async function requestMessage(request: RequestToSign & {timestamp: number}): Promise<string> {
	return [
		'delegated-identity ed25519 request v1',
		`origin: ${request.serverOrigin}`,
		`route: ${request.method.toUpperCase()} ${request.path}`,
		`timestamp: ${request.timestamp}`,
		`body: sha256:${toHex(await sha256(utf8.encode(request.body)))}`,
	].join('\n');
}

/** Sign a request with the account's Ed25519 signing key: the value of the SIGNATURE header. */
export async function signRequest(
	request: RequestToSign & {timestamp?: number},
	signingPrivateKey: PrivateKey,
): Promise<string> {
	const seed = toPrivateKeyBytes(signingPrivateKey);
	if (seed.length !== 32) {
		throw new Error(`an Ed25519 private key is 32 bytes, got ${seed.length}`);
	}
	const timestamp = request.timestamp ?? Date.now();
	const message = utf8.encode(await requestMessage({...request, timestamp}));
	const signature = await ed25519Sign(message, seed);
	return `${timestamp}:${bytesToHex(ed25519PublicKey(seed))}:${bytesToHex(signature)}`;
}

/** A SIGNATURE header's parts. Its key is a claim: nothing is verified yet. */
export type ParsedRequestSignature = {timestamp: number; publicKey: Key; signature: `0x${string}`};

/**
 * The parts of a SIGNATURE header (`<timestamp ms>:<Ed25519 public key hex>:<signature hex>`),
 * or `undefined` when it is malformed. The key it names is only a claim, for a
 * service to look up the account it registered; `verifyRequestSignature` checks it.
 */
export function parseRequestSignature(header: string): ParsedRequestSignature | undefined {
	const parts = typeof header === 'string' ? header.split(':') : [];
	if (
		parts.length !== 3 ||
		!/^[0-9]{1,16}$/.test(parts[0]) ||
		!/^[0-9a-fA-F]{64}$/.test(parts[1]) ||
		!/^[0-9a-fA-F]{128}$/.test(parts[2])
	) {
		return undefined;
	}
	const timestamp = Number(parts[0]);
	if (!Number.isSafeInteger(timestamp)) {
		return undefined;
	}
	return {
		timestamp,
		publicKey: `0x${parts[1].toLowerCase()}`,
		signature: `0x${parts[2].toLowerCase()}`,
	};
}

export type CheckedRequest =
	{ok: true; publicKey: Key; timestamp: number} | {ok: false; reason: 'malformed' | 'expired' | 'not-authorized'};

/**
 * The stateful check, for a service that keeps a key directory: is this
 * request signed by `publicKey` (a key the service registered after checking
 * its ownership proof once)? `malformed` when the header cannot be parsed;
 * `expired` when its timestamp is further than `maxAgeMs` from `now`;
 * `not-authorized` when the header names another key or the signature does not
 * verify for this request (another server, route or body). A server that must
 * refuse a replay within the window keeps the signatures it accepted for that long.
 */
export async function verifyRequestSignature(
	request: RequestToSign & {signature: string; publicKey: Key},
	options?: {now?: number; maxAgeMs?: number},
): Promise<CheckedRequest> {
	const parsed = parseRequestSignature(request.signature);
	if (!parsed) {
		return {ok: false, reason: 'malformed'};
	}
	const now = options?.now ?? Date.now();
	if (Math.abs(now - parsed.timestamp) > (options?.maxAgeMs ?? DEFAULT_MAX_REQUEST_AGE_MS)) {
		return {ok: false, reason: 'expired'};
	}
	if (typeof request.publicKey !== 'string' || parsed.publicKey !== request.publicKey.toLowerCase()) {
		return {ok: false, reason: 'not-authorized'};
	}
	const message = utf8.encode(await requestMessage({...request, timestamp: parsed.timestamp}));
	const valid = await ed25519Verify(
		hexToBytes(parsed.signature.slice(2)),
		message,
		hexToBytes(parsed.publicKey.slice(2)),
	);
	if (!valid) {
		return {ok: false, reason: 'not-authorized'};
	}
	return {ok: true, publicKey: parsed.publicKey, timestamp: parsed.timestamp};
}

export type VerifiedRequest =
	| {ok: true; address: Address; publicKey: Key; timestamp: number}
	| {ok: false; reason: 'malformed' | 'expired' | 'not-authorized'};

/**
 * Both proofs together, for a stateless service: does this request, signed by
 * the key set's signing key, speak for `address` in the app at `appOrigin`
 * (passed as the wallet signed it, never rebuilt here)? `malformed` when the
 * header, the key set or the ownership signature cannot be parsed; `expired`
 * outside the time window; `not-authorized` when they are well formed but do
 * not recover `address` (another account's proof, a proof for another app
 * origin or another key set, a request signed by another key, or for another
 * server, route or body).
 */
export async function verifyRequest(
	request: RequestToSign & {
		signature: string;
		appOrigin: string;
		address: string;
		keySet: PublicKeySet;
		ownershipSignature: `0x${string}`;
	},
	options?: {now?: number; maxAgeMs?: number},
): Promise<VerifiedRequest> {
	let signingKey: Key;
	try {
		signingKey = `0x${taggedKeys(request.keySet).signing.slice('ed25519:0x'.length)}`;
	} catch {
		return {ok: false, reason: 'malformed'};
	}
	const checked = await verifyRequestSignature({...request, publicKey: signingKey}, options);
	if (!checked.ok) {
		return checked;
	}
	let recovered: Address;
	try {
		recovered = await recoverAccount({
			appOrigin: request.appOrigin,
			keySet: request.keySet,
			ownershipSignature: request.ownershipSignature,
		});
	} catch {
		return {ok: false, reason: 'malformed'};
	}
	if (typeof request.address !== 'string' || recovered !== request.address.toLowerCase()) {
		return {ok: false, reason: 'not-authorized'};
	}
	return {ok: true, address: recovered, publicKey: checked.publicKey, timestamp: checked.timestamp};
}
