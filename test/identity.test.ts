import {afterEach, beforeEach, describe, expect, it} from 'vitest';
import {createPrivateKey, createPublicKey, hkdfSync} from 'node:crypto';
import {generatePrivateKey, privateKeyToAccount} from 'viem/accounts';
import {parseSignature, serializeCompactSignature, signatureToCompactSignature} from 'viem';
import {ED25519_TORSION_SUBGROUP, ed25519} from '@noble/curves/ed25519';
import {sha512} from '@noble/hashes/sha2';
import {bytesToHex, hexToBytes} from '@noble/hashes/utils';
import * as api from '../src/index.js';
import {
	deriveKeySet,
	fromDomainToOrigin,
	keySetRef,
	originPublicKeyPublicationMessage,
	parseRequestSignature,
	recoverAccount,
	requestMessage,
	signRequest,
	verifyRequest,
	verifyRequestSignature,
	type KeySet,
} from '../src/index.js';
import {cryptoBackend, ed25519Verify, passesPreChecks, setCryptoBackend, type Backend} from '../src/crypto.js';

const APP = 'https://game.example';
const SERVER = 'https://push.example';
const NOW = 1_800_000_000_000;

// The pinned vectors: an origin private key, and a wallet key for the ownership proof.
const ORIGIN_PRIVATE_KEY = `0x${'42'.repeat(32)}` as const;
const WALLET_PRIVATE_KEY = `0x${'07'.repeat(32)}` as const;
const KEY_SET: KeySet = {
	signing: {
		publicKey: '0x6c93783331e0ce6b5582024814d22c91ebb7af5be6f6accb2707a7fd5c6248ed',
		privateKey: '0x3dcbd1724fbf8452449b3c2b2be8e48c884befd2504fc862031a4c33eac58983',
	},
	encryption: {
		publicKey: '0xeab917b5f1b231978517a7f4558c07d3365b170d8f08daebeb5beb54b437c308',
		privateKey: '0xdeef492330740f17357999f34e7591abb63b56ad26f5234d562bd13773fedf74',
	},
};
const PUBLICATION_MESSAGE =
	'Origin: https://game.example\n\nIMPORTANT: Only sign on trusted websites.\n\nThis authorizes the following keys for your account:\n\nSigning key, to act for your account in this app:\ned25519:0x6c93783331e0ce6b5582024814d22c91ebb7af5be6f6accb2707a7fd5c6248ed\n\nEncryption key, for others to send you encrypted messages:\nx25519:0xeab917b5f1b231978517a7f4558c07d3365b170d8f08daebeb5beb54b437c308';
const KEY_SET_REF = '0xb1af37400b7ab573b20ff2c732b66164b91dc9457c516f08d1a2d0858ec74411';
const OWNERSHIP_SIGNATURE =
	'0xbba007cdf15387ca55cdff07f22205f1b535952436b3a88fe1a3af48def811f804decd033ed55ceb2700f1ea601ce955e9cafdf7d49d27ae7b23c8fa78a9de931c';
const WALLET_ADDRESS = '0x4a62316623ad457f02cdc5d997ded67a383ec569';
const ENVELOPE = [
	'delegated-identity ed25519 request v1',
	'origin: https://push.example',
	'route: POST /api/register',
	'timestamp: 1800000000000',
	'body: sha256:0x230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5',
].join('\n');
const SIGNATURE_HEADER =
	'1800000000000:6c93783331e0ce6b5582024814d22c91ebb7af5be6f6accb2707a7fd5c6248ed:ff5256424f1f568aa776165ab9f63fae67bc325d5378af8a9d4e23eccc1ce3fff031a9ac9e94ec4401b6cddeb10e23062e73b8a63f29014675fe00ab712beb01';

async function createAccount(appOrigin: string) {
	const wallet = privateKeyToAccount(generatePrivateKey());
	const keySet = deriveKeySet(generatePrivateKey());
	const ownershipSignature = await wallet.signMessage({
		message: originPublicKeyPublicationMessage(appOrigin, keySet),
	});
	return {address: wallet.address.toLowerCase() as `0x${string}`, keySet, ownershipSignature};
}

function request(body = '{"hello":"world"}') {
	return {serverOrigin: SERVER, method: 'POST', path: '/api/register', body};
}

const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function littleEndianBytes(n: bigint): Uint8Array {
	const bytes = new Uint8Array(32);
	for (let i = 0; i < 32; i++) {
		bytes[i] = Number((n >> BigInt(8 * i)) & 0xffn);
	}
	return bytes;
}

function littleEndian(bytes: Uint8Array): bigint {
	return BigInt(`0x${bytesToHex(bytes.slice().reverse())}`);
}

describe('the derivation (independent of the backend: it always runs in @noble)', () => {
	it('derives the pinned key set', () => {
		expect(deriveKeySet(ORIGIN_PRIVATE_KEY)).toEqual(KEY_SET);
		expect(deriveKeySet(hexToBytes(ORIGIN_PRIVATE_KEY.slice(2)))).toEqual(KEY_SET);
	});

	it('is the HKDF-SHA256 the spec names, and the keys are those of the derived seeds (cross-checked with node:crypto)', () => {
		const ikm = Buffer.from(ORIGIN_PRIVATE_KEY.slice(2), 'hex');
		const signing = Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), 'delegated-identity ed25519 signing key', 32));
		const encryption = Buffer.from(
			hkdfSync('sha256', ikm, Buffer.alloc(0), 'delegated-identity x25519 encryption key', 32),
		);
		expect(KEY_SET.signing.privateKey).toBe(`0x${signing.toString('hex')}`);
		expect(KEY_SET.encryption.privateKey).toBe(`0x${encryption.toString('hex')}`);
		const rawPublicKey = (prefix: string, seed: Buffer) => {
			const key = createPrivateKey({
				key: Buffer.concat([Buffer.from(prefix, 'hex'), seed]),
				format: 'der',
				type: 'pkcs8',
			});
			const jwk = createPublicKey(key).export({format: 'jwk'});
			return `0x${Buffer.from(jwk.x!, 'base64url').toString('hex')}`;
		};
		expect(KEY_SET.signing.publicKey).toBe(rawPublicKey('302e020100300506032b657004220420', signing));
		expect(KEY_SET.encryption.publicKey).toBe(rawPublicKey('302e020100300506032b656e04220420', encryption));
	});

	it('gives the same key set twice from one origin key, and another from another', () => {
		const originKey = generatePrivateKey();
		expect(deriveKeySet(originKey)).toEqual(deriveKeySet(originKey));
		expect(deriveKeySet(generatePrivateKey()).signing.publicKey).not.toBe(deriveKeySet(originKey).signing.publicKey);
	});

	it('derives the two keys independently: neither private key is the other', () => {
		const keySet = deriveKeySet(generatePrivateKey());
		expect(keySet.signing.privateKey).not.toBe(keySet.encryption.privateKey);
		// not the Ed25519-to-X25519 conversion of the signing key either
		const converted = `0x${bytesToHex(ed25519.utils.toMontgomery(hexToBytes(keySet.signing.publicKey.slice(2))))}`;
		expect(keySet.encryption.publicKey).not.toBe(converted);
	});

	it('refuses an origin private key that is not 32 bytes', () => {
		expect(() => deriveKeySet('0x1234')).toThrow();
	});
});

describe('the publication message', () => {
	it('is the pinned text: the origin, the warning, each key tagged on its own line with what it is for', () => {
		expect(originPublicKeyPublicationMessage(APP, KEY_SET)).toBe(PUBLICATION_MESSAGE);
	});

	it('names the keys in lowercase, from public keys alone', () => {
		const upper: api.PublicKeySet = {
			signing: {publicKey: `0x${KEY_SET.signing.publicKey.slice(2).toUpperCase()}`},
			encryption: {publicKey: KEY_SET.encryption.publicKey},
		};
		expect(originPublicKeyPublicationMessage(APP, upper)).toBe(PUBLICATION_MESSAGE);
	});

	it('refuses a key that is not 32 bytes of hex', () => {
		expect(() => originPublicKeyPublicationMessage(APP, {...KEY_SET, encryption: {publicKey: '0x02ab'}})).toThrow();
	});

	it('names the origin of a domain, and keeps an origin as it is', () => {
		expect(fromDomainToOrigin('game.example')).toBe('https://game.example');
		expect(fromDomainToOrigin('https://game.example')).toBe('https://game.example');
		expect(fromDomainToOrigin('http://192.168.1.10:5173')).toBe('http://192.168.1.10:5173');
		expect(fromDomainToOrigin('localhost')).toBe('http://localhost');
		expect(fromDomainToOrigin('localhost:5173')).toBe('http://localhost:5173');
	});
});

describe('the exports', () => {
	it('keep no secp256k1 publication or envelope', () => {
		expect(Object.keys(api).sort()).toEqual(
			[
				'DEFAULT_MAX_REQUEST_AGE_MS',
				'REQUEST_SIGNATURE_HEADER',
				'deriveKeySet',
				'fromDomainToOrigin',
				'keySetRef',
				'originPublicKeyPublicationMessage',
				'parseRequestSignature',
				'recoverAccount',
				'requestMessage',
				'signRequest',
				'verifyRequest',
				'verifyRequestSignature',
			].sort(),
		);
	});
});

describe('the ownership proof', () => {
	it('recovers the pinned account from the pinned proof', async () => {
		expect(await recoverAccount({appOrigin: APP, keySet: KEY_SET, ownershipSignature: OWNERSHIP_SIGNATURE})).toBe(
			WALLET_ADDRESS,
		);
		const wallet = privateKeyToAccount(WALLET_PRIVATE_KEY);
		expect(await wallet.signMessage({message: PUBLICATION_MESSAGE})).toBe(OWNERSHIP_SIGNATURE);
	});

	it('recovers another account for another origin, even the same host over http, or another key set', async () => {
		const account = await createAccount(APP);
		for (const appOrigin of ['https://other.example', 'http://game.example']) {
			expect(
				await recoverAccount({appOrigin, keySet: account.keySet, ownershipSignature: account.ownershipSignature}),
			).not.toBe(account.address);
		}
		expect(
			await recoverAccount({
				appOrigin: APP,
				keySet: {...account.keySet, encryption: KEY_SET.encryption},
				ownershipSignature: account.ownershipSignature,
			}),
		).not.toBe(account.address);
	});

	// viem is a dev dependency only: it stands for the wallets that sign, and so
	// cross-checks this package's own EIP-191 hashing and recovery.
	it('recovers the account from a proof whose origin is not ASCII (the prefix counts bytes, not characters)', async () => {
		const appOrigin = 'https://jeu-\u00e9t\u00e9.example';
		const account = await createAccount(appOrigin);
		expect(
			await recoverAccount({appOrigin, keySet: account.keySet, ownershipSignature: account.ownershipSignature}),
		).toBe(account.address);
	});

	it('recovers the account from a 64-byte EIP-2098 signature, and a v of 0 or 1', async () => {
		const account = await createAccount(APP);
		const compact = serializeCompactSignature(signatureToCompactSignature(parseSignature(account.ownershipSignature)));
		expect(await recoverAccount({appOrigin: APP, keySet: account.keySet, ownershipSignature: compact})).toBe(
			account.address,
		);
		const v = parseInt(account.ownershipSignature.slice(130), 16);
		const zeroOne = `${account.ownershipSignature.slice(0, 130)}${(v - 27).toString(16).padStart(2, '0')}` as const;
		expect(await recoverAccount({appOrigin: APP, keySet: account.keySet, ownershipSignature: zeroOne})).toBe(
			account.address,
		);
	});
});

describe('the pre-checks', () => {
	it('name exactly the eight small-order points (cross-checked with @noble)', () => {
		const signature = new Uint8Array(64);
		signature.set(hexToBytes(KEY_SET.signing.publicKey.slice(2))); // an R that passes
		for (const torsion of ED25519_TORSION_SUBGROUP) {
			const point = hexToBytes(torsion);
			expect(ed25519.ExtendedPoint.fromHex(point).isSmallOrder()).toBe(true);
			expect(passesPreChecks(signature, point)).toBe(false);
		}
		for (let i = 0; i < 20; i++) {
			const publicKey = deriveKeySet(generatePrivateKey()).signing.publicKey;
			expect(passesPreChecks(signature, hexToBytes(publicKey.slice(2)))).toBe(true);
		}
	});

	it('refuse a non-canonical y (y >= p) for A or R', () => {
		const signature = new Uint8Array(64);
		signature.set(hexToBytes(KEY_SET.signing.publicKey.slice(2)));
		const yIsP = littleEndianBytes(2n ** 255n - 19n + 2n); // p + 2, which is 2 mod p
		expect(passesPreChecks(signature, yIsP)).toBe(false);
		const nonCanonicalR = signature.slice();
		nonCanonicalR.set(yIsP);
		expect(passesPreChecks(nonCanonicalR, hexToBytes(KEY_SET.signing.publicKey.slice(2)))).toBe(false);
	});
});

const BACKENDS: Backend[] = ['webcrypto', 'noble'];

describe.each(BACKENDS)('with the %s backend', (backend) => {
	beforeEach(() => setCryptoBackend(backend));
	afterEach(() => setCryptoBackend(undefined));

	describe('the key set reference', () => {
		it('is the SHA-256 of the two tagged keys', async () => {
			expect(await keySetRef(KEY_SET)).toBe(KEY_SET_REF);
			expect(await keySetRef({signing: KEY_SET.signing, encryption: {publicKey: KEY_SET.signing.publicKey}})).not.toBe(
				KEY_SET_REF,
			);
		});
	});

	describe('the request envelope', () => {
		it('is the pinned text: the purpose, the server, the route, the time and the body by its SHA-256', async () => {
			expect(await requestMessage({...request('body'), method: 'post', timestamp: NOW})).toBe(ENVELOPE);
		});

		it('hashes the body exactly as sent', async () => {
			const a = await requestMessage({...request('{"a":1}'), timestamp: 1});
			const b = await requestMessage({...request('{"a": 1}'), timestamp: 1});
			expect(a).not.toBe(b);
		});
	});

	describe('the request signature', () => {
		it('is the pinned header: the timestamp, the signing key, the Ed25519 signature over the envelope', async () => {
			const header = await signRequest({...request('body'), timestamp: NOW}, KEY_SET.signing.privateKey);
			expect(header).toBe(SIGNATURE_HEADER);
			const [, publicKey, signature] = header.split(':');
			expect(ed25519.verify(signature, new TextEncoder().encode(ENVELOPE), publicKey)).toBe(true);
		});

		it('parses a header, naming its key as a claim', () => {
			expect(parseRequestSignature(SIGNATURE_HEADER.toUpperCase())).toEqual({
				timestamp: NOW,
				publicKey: KEY_SET.signing.publicKey,
				signature: `0x${SIGNATURE_HEADER.split(':')[2]}`,
			});
		});

		it('verifies against the given key, and answers it and the timestamp', async () => {
			const keySet = deriveKeySet(generatePrivateKey());
			const signature = await signRequest({...request(), timestamp: NOW}, keySet.signing.privateKey);
			expect(
				await verifyRequestSignature({...request(), signature, publicKey: keySet.signing.publicKey}, {now: NOW + 1000}),
			).toEqual({ok: true, publicKey: keySet.signing.publicKey, timestamp: NOW});
		});

		it('refuses another key, and another server, route, method or body', async () => {
			const keySet = deriveKeySet(generatePrivateKey());
			const signature = await signRequest({...request(), timestamp: NOW}, keySet.signing.privateKey);
			const other = deriveKeySet(generatePrivateKey()).signing.publicKey;
			expect(await verifyRequestSignature({...request(), signature, publicKey: other}, {now: NOW})).toEqual({
				ok: false,
				reason: 'not-authorized',
			});
			// the header's key swapped for another: the signature no longer verifies
			const swapped = signature.replace(keySet.signing.publicKey.slice(2), other.slice(2));
			expect(await verifyRequestSignature({...request(), signature: swapped, publicKey: other}, {now: NOW})).toEqual({
				ok: false,
				reason: 'not-authorized',
			});
			for (const changed of [
				{...request(), serverOrigin: 'https://missiv.example'},
				{...request(), path: '/api/unregister'},
				{...request(), method: 'PUT'},
				{...request('{"hello":"mallory"}')},
			]) {
				expect(
					await verifyRequestSignature({...changed, signature, publicKey: keySet.signing.publicKey}, {now: NOW}),
				).toEqual({ok: false, reason: 'not-authorized'});
			}
		});

		it('refuses a timestamp outside the window, either way', async () => {
			const publicKey = KEY_SET.signing.publicKey;
			const signed = {...request('body'), signature: SIGNATURE_HEADER, publicKey};
			expect(await verifyRequestSignature(signed, {now: NOW + 60_001})).toEqual({ok: false, reason: 'expired'});
			expect(await verifyRequestSignature(signed, {now: NOW - 60_001})).toEqual({ok: false, reason: 'expired'});
			expect(await verifyRequestSignature(signed, {now: NOW + 5000, maxAgeMs: 1000})).toEqual({
				ok: false,
				reason: 'expired',
			});
			expect(await verifyRequestSignature(signed, {now: NOW + 60_000})).toMatchObject({ok: true});
		});

		it('refuses a malformed header', async () => {
			const [timestamp, publicKey, signature] = SIGNATURE_HEADER.split(':');
			for (const header of [
				'',
				'abc',
				`${timestamp}:${publicKey}`,
				`${timestamp}:${publicKey}:${signature}:0`,
				`x:${publicKey}:${signature}`,
				`${timestamp}:${publicKey.slice(2)}:${signature}`,
				`${timestamp}:${publicKey}:${signature.slice(2)}`,
				`${timestamp}:0x${publicKey}:${signature}`,
				`${timestamp}:${publicKey}:${'z'.repeat(128)}`,
				`${'9'.repeat(17)}:${publicKey}:${signature}`,
			]) {
				expect(
					await verifyRequestSignature(
						{...request('body'), signature: header, publicKey: KEY_SET.signing.publicKey},
						{now: NOW},
					),
				).toEqual({ok: false, reason: 'malformed'});
			}
		});
	});

	describe('edge-case Ed25519 signatures, refused on every path', () => {
		const message = new TextEncoder().encode('a message');
		const seed = hexToBytes(KEY_SET.signing.privateKey.slice(2));
		const publicKey = hexToBytes(KEY_SET.signing.publicKey.slice(2));

		it('accepts the honest signature', async () => {
			expect(await ed25519Verify(ed25519.sign(message, seed), message, publicKey)).toBe(true);
		});

		it('refuses a non-canonical S (S + L, which a lax verifier reduces back to S)', async () => {
			const signature = ed25519.sign(message, seed);
			const s = littleEndian(signature.slice(32));
			const malleated = signature.slice();
			malleated.set(littleEndianBytes(s + L), 32);
			expect(await ed25519Verify(malleated, message, publicKey)).toBe(false);
		});

		it('refuses a small-order A with a small-order R (the signature that verifies for any message, cofactored)', async () => {
			const identity = littleEndianBytes(1n); // the neutral point, y = 1
			const signature = new Uint8Array(64);
			signature.set(identity);
			// @noble's permissive mode accepts it: the pre-checks are what refuse it
			expect(ed25519.verify(signature, message, identity, {zip215: true})).toBe(true);
			expect(await ed25519Verify(signature, message, identity)).toBe(false);
		});

		it('refuses a small-order R with the real key (verifies cofactored, not cofactorless)', async () => {
			const {scalar} = ed25519.utils.getExtendedPublicKey(seed);
			const R = hexToBytes(ED25519_TORSION_SUBGROUP[1]); // of order 8
			const k = littleEndian(sha512(new Uint8Array([...R, ...publicKey, ...message]))) % L;
			const S = (k * scalar) % L;
			const signature = new Uint8Array([...R, ...littleEndianBytes(S)]);
			// RFC 8032 strict decoding in @noble still accepts it (it checks A, not R): the pre-checks refuse it
			expect(ed25519.verify(signature, message, publicKey, {zip215: false})).toBe(true);
			expect(await ed25519Verify(signature, message, publicKey)).toBe(false);
		});
	});

	describe('verifyRequest: both proofs together', () => {
		async function signedBy(account: Awaited<ReturnType<typeof createAccount>>, body = 'body') {
			return {
				...request(body),
				signature: await signRequest({...request(body), timestamp: NOW}, account.keySet.signing.privateKey),
			};
		}

		it('verifies the pinned vectors', async () => {
			expect(
				await verifyRequest(
					{
						...request('body'),
						signature: SIGNATURE_HEADER,
						appOrigin: APP,
						address: WALLET_ADDRESS,
						keySet: KEY_SET,
						ownershipSignature: OWNERSHIP_SIGNATURE,
					},
					{now: NOW},
				),
			).toEqual({ok: true, address: WALLET_ADDRESS, publicKey: KEY_SET.signing.publicKey, timestamp: NOW});
		});

		it('answers the account, the signing key and the timestamp, from public keys alone', async () => {
			const account = await createAccount(APP);
			const result = await verifyRequest(
				{
					...(await signedBy(account)),
					appOrigin: APP,
					address: account.address.toUpperCase().replace('0X', '0x'),
					keySet: {
						signing: {publicKey: account.keySet.signing.publicKey},
						encryption: {publicKey: account.keySet.encryption.publicKey},
					},
					ownershipSignature: account.ownershipSignature,
				},
				{now: NOW},
			);
			expect(result).toEqual({
				ok: true,
				address: account.address,
				publicKey: account.keySet.signing.publicKey,
				timestamp: NOW,
			});
		});

		it('verifies an app on a LAN address over http, the origin the wallet signed', async () => {
			const lan = 'http://192.168.1.10:5173';
			const account = await createAccount(lan);
			const result = await verifyRequest(
				{...(await signedBy(account)), appOrigin: lan, address: account.address, ...account},
				{now: NOW},
			);
			expect(result.ok).toBe(true);
		});

		it('refuses an address the proofs do not recover', async () => {
			const account = await createAccount(APP);
			const other = await createAccount(APP);
			expect(
				await verifyRequest(
					{...(await signedBy(account)), appOrigin: APP, ...account, address: other.address},
					{now: NOW},
				),
			).toEqual({ok: false, reason: 'not-authorized'});
		});

		it('refuses a proof made for another app origin', async () => {
			const account = await createAccount('https://other.example');
			expect(await verifyRequest({...(await signedBy(account)), appOrigin: APP, ...account}, {now: NOW})).toEqual({
				ok: false,
				reason: 'not-authorized',
			});
		});

		it('refuses another key set: one the wallet did not authorize, signing the request (a public proof replayed)', async () => {
			const account = await createAccount(APP);
			const mallory = await createAccount(APP);
			// mallory's request with account's proof and key set: the signing key is not the header's
			expect(await verifyRequest({...(await signedBy(mallory)), appOrigin: APP, ...account}, {now: NOW})).toEqual({
				ok: false,
				reason: 'not-authorized',
			});
			// mallory's request and key set with account's proof: the proof recovers another account
			expect(
				await verifyRequest(
					{
						...(await signedBy(mallory)),
						appOrigin: APP,
						address: account.address,
						keySet: mallory.keySet,
						ownershipSignature: account.ownershipSignature,
					},
					{now: NOW},
				),
			).toEqual({ok: false, reason: 'not-authorized'});
			// account's signing key with another encryption key: the proof names another set
			expect(
				await verifyRequest(
					{
						...(await signedBy(account)),
						appOrigin: APP,
						...account,
						keySet: {...account.keySet, encryption: mallory.keySet.encryption},
					},
					{now: NOW},
				),
			).toEqual({ok: false, reason: 'not-authorized'});
		});

		it('refuses another server, route or body', async () => {
			const account = await createAccount(APP);
			const signed = await signedBy(account);
			for (const changed of [
				{serverOrigin: 'https://missiv.example'},
				{path: '/api/unregister'},
				{body: 'other body'},
			]) {
				expect(await verifyRequest({...signed, ...changed, appOrigin: APP, ...account}, {now: NOW})).toEqual({
					ok: false,
					reason: 'not-authorized',
				});
			}
		});

		it('refuses an expired request, and a malformed header, key set or ownership proof', async () => {
			const account = await createAccount(APP);
			const signed = await signedBy(account);
			expect(await verifyRequest({...signed, appOrigin: APP, ...account}, {now: NOW + 120_000})).toEqual({
				ok: false,
				reason: 'expired',
			});
			expect(await verifyRequest({...signed, appOrigin: APP, ...account, signature: 'abc'}, {now: NOW})).toEqual({
				ok: false,
				reason: 'malformed',
			});
			expect(
				await verifyRequest(
					{...signed, appOrigin: APP, ...account, keySet: {...account.keySet, encryption: {publicKey: '0x02ab'}}},
					{now: NOW},
				),
			).toEqual({ok: false, reason: 'malformed'});
			expect(
				await verifyRequest({...signed, appOrigin: APP, ...account, ownershipSignature: '0x1234'}, {now: NOW}),
			).toEqual({ok: false, reason: 'malformed'});
		});
	});
});

describe('the backend', () => {
	afterEach(() => setCryptoBackend(undefined));

	it('is WebCrypto where the runtime has Ed25519 (Node), @noble without crypto.subtle (a plain-http origin)', async () => {
		setCryptoBackend(undefined);
		expect(await cryptoBackend()).toBe('webcrypto');
		const crypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
		Object.defineProperty(globalThis, 'crypto', {value: undefined, configurable: true});
		try {
			setCryptoBackend(undefined);
			expect(await cryptoBackend()).toBe('noble');
			expect(await signRequest({...request('body'), timestamp: NOW}, KEY_SET.signing.privateKey)).toBe(
				SIGNATURE_HEADER,
			);
			expect(await keySetRef(KEY_SET)).toBe(KEY_SET_REF);
		} finally {
			Object.defineProperty(globalThis, 'crypto', crypto);
		}
	});
});
