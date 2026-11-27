import {afterEach, beforeEach, describe, expect, it} from 'vitest';
import {bytesToHex, hexToBytes} from '@noble/hashes/utils';
import * as subpath from '../src/ed25519.js';
import {ed25519PublicKey, ed25519Sign, ed25519Verify, sha256} from '../src/ed25519.js';
import {setCryptoBackend, type Backend} from '../src/crypto.js';

// RFC 8032, section 7.1, test 2 (a one-byte message).
const SEED = hexToBytes('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
const PUBLIC_KEY = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
const MESSAGE = hexToBytes('72');
const SIGNATURE =
	'92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00';

// L, the group order: S + L is the same S to a lax verifier.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

describe('the ed25519 subpath', () => {
	it('exports Ed25519 sign, verify, its public key, and SHA-256, nothing else', () => {
		expect(Object.keys(subpath).sort()).toEqual(['ed25519PublicKey', 'ed25519Sign', 'ed25519Verify', 'sha256']);
	});

	it('names the public key of a seed as RFC 8032 does', () => {
		expect(bytesToHex(ed25519PublicKey(SEED))).toBe(PUBLIC_KEY);
	});
});

describe.each<Backend>(['webcrypto', 'noble'])('the ed25519 subpath with the %s backend', (backend) => {
	beforeEach(() => setCryptoBackend(backend));
	afterEach(() => setCryptoBackend(undefined));

	it('signs RFC 8032 test 2 byte for byte', async () => {
		expect(bytesToHex(await ed25519Sign(MESSAGE, SEED))).toBe(SIGNATURE);
	});

	it('verifies the honest signature and refuses another message or key', async () => {
		const signature = hexToBytes(SIGNATURE);
		expect(await ed25519Verify(signature, MESSAGE, hexToBytes(PUBLIC_KEY))).toBe(true);
		expect(await ed25519Verify(signature, hexToBytes('73'), hexToBytes(PUBLIC_KEY))).toBe(false);
		expect(await ed25519Verify(signature, MESSAGE, ed25519PublicKey(new Uint8Array(32).fill(1)))).toBe(false);
	});

	it('runs the pre-checks: a non-canonical S is refused', async () => {
		const signature = hexToBytes(SIGNATURE);
		let s = 0n;
		for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(signature[i]);
		let t = s + L;
		for (let i = 32; i < 64; i++) {
			signature[i] = Number(t & 0xffn);
			t >>= 8n;
		}
		expect(await ed25519Verify(signature, MESSAGE, hexToBytes(PUBLIC_KEY))).toBe(false);
	});

	it('hashes with SHA-256', async () => {
		expect(bytesToHex(await sha256(new TextEncoder().encode('abc')))).toBe(
			'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
		);
	});
});
