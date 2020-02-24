/**
 * Original work Copyright (c) 2003-2005 Tom Wu <tjw@cs.Stanford.EDU>
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

// Depends on jsbn.js and rng.js

import { BigInteger } from "./jsbn.js"
import { SecureRandom } from "./rng.js"
import { hex2b64, b64tohex } from "./base64.js"

// Version 1.1: support utf-8 encoding in pkcs1pad2

/**
 * convert a (hex) string to a bignum object
 * @param {string} str 
 * @param {number | SecureRandom} r 
 * @returns {BigInteger}
 */
export function parseBigInt(str, r) {
	return new BigInteger(str, r);
}

/**
 * @param {string} s 
 * @param {number} n 
 * @returns {string}
 */
export function linebrk(s, n) {
	let ret = "";
	let i = 0;
	while (i + n < s.length) {
		ret += s.substring(i, i + n) + "\n";
		i += n;
	}
	return ret + s.substring(i, s.length);
}

/**
 * @param {number} b 
 * @returns {string}
 */
export function byte2Hex(b) {
	if (b < 0x10)
		return "0" + b.toString(16);
	else
		return b.toString(16);
}

/**
 * PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
 * @param {string} s 
 * @param {number} n 
 * @returns {BigInteger}
 */
export function pkcs1pad2(s, n) {
	if (n < s.length + 11) { // TODO: fix for utf-8
		throw "Message too long for RSA";
	}
	/** @type {Array<number>} */ let ba = new Array();
	let i = s.length - 1;
	while (i >= 0 && n > 0) {
		let c = s.charCodeAt(i--);
		if (c < 128) { // encode using utf-8
			ba[--n] = c;
		}
		else if ((c > 127) && (c < 2048)) {
			ba[--n] = (c & 63) | 128;
			ba[--n] = (c >> 6) | 192;
		}
		else {
			ba[--n] = (c & 63) | 128;
			ba[--n] = ((c >> 6) & 63) | 128;
			ba[--n] = (c >> 12) | 224;
		}
	}
	ba[--n] = 0;
	let rng = new SecureRandom();
	let x = new Array();
	while (n > 2) { // random non-zero pad
		x[0] = 0;
		while (x[0] == 0) rng.nextBytes(x);
		ba[--n] = x[0];
	}
	ba[--n] = 2;
	ba[--n] = 0;
	return new BigInteger(ba);
}

/**
 * @param {BigInteger} d 
 * @param {number} n 
 * @returns {string | null} Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
 */
export function pkcs1unpad2(d, n) {
	let b = d.toByteArray();
	let i = 0;
	while (i < b.length && b[i] == 0)++i;
	if (b.length - i != n - 1 || b[i] != 2)
		return null;
	++i;
	while (b[i] != 0)
		if (++i >= b.length) return null;
	let ret = "";
	while (++i < b.length) {
		let c = b[i] & 255;
		if (c < 128) { // utf-8 decode
			ret += String.fromCharCode(c);
		}
		else if ((c > 191) && (c < 224)) {
			ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
			++i;
		}
		else {
			ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
			i += 2;
		}
	}
	return ret;
}

// "empty" RSA key constructor
export class RSAKey {
	constructor() {
		/** @type {BigInteger | null} */ this.n = null;
		this.e = 0;
		/** @type {BigInteger | null} */ this.d = null;
		/** @type {BigInteger | null} */ this.p = null;
		/** @type {BigInteger | null} */ this.q = null;
		/** @type {BigInteger | null} */ this.dmp1 = null;
		/** @type {BigInteger | null} */ this.dmq1 = null;
		/** @type {BigInteger | null} */ this.coeff = null;
	}

	/**
	 * Set the public key fields N and e from hex strings
	 * @param {string} N 
	 * @param {string} E 
	 */
	setPublic(N, E) {
		if (N != null && E != null && N.length > 0 && E.length > 0) {
			this.n = parseBigInt(N, 16);
			this.e = parseInt(E, 16);
		}
		else
			throw "Invalid RSA public key";
	}

	/**
	 * Perform raw public operation on "x": return x^e (mod n)
	 * @param {BigInteger} x
	 * @returns {BigInteger}
	 */
	doPublic(x) {
		return x.modPowInt(this.e, this.n);
	}

	/**
	 * @param {string} text 
	 * @returns {string | null} the PKCS#1 RSA encryption of "text" as an even-length hex string
	 */
	encrypt(text) {
		let m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
		if (m == null) return null;
		let c = this.doPublic(m);
		if (c == null) return null;
		let h = c.toString(16);
		if ((h.length & 1) == 0) return h; else return "0" + h;
	}

	/**
	 * @param {string} text 
	 * @returns {string | null} the PKCS#1 RSA encryption of "text" as a Base64-encoded string
	 */
	encrypt_b64(text) {
		let h = this.encrypt(text);
		if (h) return hex2b64(h); else return null;
	}

	/**
	 * Set the private key fields N, e, and d from hex strings
	 * @param {string | null} N 
	 * @param {string | null} E 
	 * @param {string} D 
	 */
	setPrivate(N, E, D) {
		if (N != null && E != null && N.length > 0 && E.length > 0) {
			this.n = parseBigInt(N, 16);
			this.e = parseInt(E, 16);
			this.d = parseBigInt(D, 16);
		}
		else
			throw "Invalid RSA private key";
	}

	/**
	 * Set the private key fields N, e, d and CRT params from hex strings
	 * @param {string} N 
	 * @param {string} E 
	 * @param {string} D 
	 * @param {string} P 
	 * @param {string} Q 
	 * @param {string} DP 
	 * @param {string} DQ 
	 * @param {string} C 
	 */
	setPrivateEx(N, E, D, P, Q, DP, DQ, C) {
		if (N != null && E != null && N.length > 0 && E.length > 0) {
			this.n = parseBigInt(N, 16);
			this.e = parseInt(E, 16);
			this.d = parseBigInt(D, 16);
			this.p = parseBigInt(P, 16);
			this.q = parseBigInt(Q, 16);
			this.dmp1 = parseBigInt(DP, 16);
			this.dmq1 = parseBigInt(DQ, 16);
			this.coeff = parseBigInt(C, 16);
		}
		else
			throw "Invalid RSA private key";
	}

	/**
	 * Generate a new random private key B bits long, using public expt E
	 * @param {number} B 
	 * @param {string} E 
	 */
	generate(B, E) {
		let rng = new SecureRandom();
		let qs = B >> 1;
		this.e = parseInt(E, 16);
		let ee = new BigInteger(E, 16);
		for (; ;) {
			for (; ;) {
				this.p = new BigInteger(B - qs, 1, rng);
				if (this.p.subtract(BigInteger.ONE()).gcd(ee).compareTo(BigInteger.ONE()) == 0 && this.p.isProbablePrime(10)) break;
			}
			for (; ;) {
				this.q = new BigInteger(qs, 1, rng);
				if (this.q.subtract(BigInteger.ONE()).gcd(ee).compareTo(BigInteger.ONE()) == 0 && this.q.isProbablePrime(10)) break;
			}
			if (this.p.compareTo(this.q) <= 0) {
				let t = this.p;
				this.p = this.q;
				this.q = t;
			}
			let p1 = this.p.subtract(BigInteger.ONE());
			let q1 = this.q.subtract(BigInteger.ONE());
			let phi = p1.multiply(q1);
			if (phi.gcd(ee).compareTo(BigInteger.ONE()) == 0) {
				this.n = this.p.multiply(this.q);
				this.d = ee.modInverse(phi);
				this.dmp1 = this.d.mod(p1);
				this.dmq1 = this.d.mod(q1);
				this.coeff = this.q.modInverse(this.p);
				break;
			}
		}
	}

	/**
	 * @protected
	 * @param {BigInteger} x
	 * @returns {BigInteger} Perform raw private operation on "x": return x^d (mod n)
	 */
	doPrivate(x) {
		if (this.p == null || this.q == null)
			return x.modPow(this.d, this.n);

		// TODO: re-calculate any missing CRT params
		let xp = x.mod(this.p).modPow(this.dmp1, this.p);
		let xq = x.mod(this.q).modPow(this.dmq1, this.q);

		while (xp.compareTo(xq) < 0)
			xp = xp.add(this.p);
		return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
	}

	/**
	 * Return the PKCS#1 RSA decryption of "ctext".
	 * "ctext" is an even-length hex string and the output is a plain string.
	 * @param {string} ctext 
	 * @returns {string | null}
	 */
	decrypt(ctext) {
		let c = parseBigInt(ctext, 16);
		let m = this.doPrivate(c);
		if (m == null) return null;
		return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
	}

	/**
	 * Return the PKCS#1 RSA decryption of "ctext".
	 * "ctext" is a Base64-encoded string and the output is a plain string.
	 * @param {string} ctext 
	 * @returns {string | null}
	 */
	decrypt_b64(ctext) {
		let h = b64tohex(ctext);
		if (h) return this.decrypt(h); else return null;
	}
}
