/**
 * Original work Copyright (c) 2003-2005 Tom Wu <tjw@cs.Stanford.EDU>
 * Modified work Copyright (c) Stefan Thomas | https://github.com/bitcoinjs/bitcoinjs-lib
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// Only Fp curves implemented for now

// Requires jsbn.js and jsbn2.js

import { BigInteger, Barrett, nbv } from "./jsbn.js"

// ----------------
// ECFieldElementFp

export class ECFieldElementFp {
	/**
	 * @param {BigInteger} q 
	 * @param {BigInteger} x 
	 */
	constructor(q,x) {
		/** @type {BigInteger} */ this.x = x;
		// TODO if(x.compareTo(q) >= 0) error
		/** @type {BigInteger} */ this.q = q;
	}

	/**
	 * @param {ECFieldElementFp} other 
	 * @returns {boolean}
	 */
	equals(other) {
		if(other == this) return true;
		return (this.q.equals(other.q) && this.x.equals(other.x));
	}

	/**
	 * @returns {BigInteger}
	 */
	toBigInteger() {
		return this.x;
	}

	/**
	 * @returns {ECFieldElementFp}
	 */
	negate() {
		return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
	}

	/**
	 * @param {ECFieldElementFp} b 
	 * @returns {ECFieldElementFp}
	 */
	add(b) {
		return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
	}

	/**
	 * @param {ECFieldElementFp} b 
	 * @returns {ECFieldElementFp}
	 */
	subtract(b) {
		return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
	}

	/**
	 * @param {ECFieldElementFp} b 
	 * @returns {ECFieldElementFp}
	 */
	multiply(b) {
		return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
	}

	/**
	 * @returns {ECFieldElementFp}
	 */
	square() {
		return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
	}

	/**
	 * @param {ECFieldElementFp} b 
	 * @returns {ECFieldElementFp}
	 */
	divide(b) {
		return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
	}

	/**
	 * @returns {number}
	 */
	getByteLength() {
		return Math.floor((this.toBigInteger().bitLength() + 7) / 8);
	}
}

// ----------------
// ECPointFp

/**
 * @param {BigInteger} i 
 * @param {number} len 
 * @returns {Array<number>}
 */
function integerToBytes(i, len) {
	let bytes = i.toByteArray();
	
	// FIX: undefined toByteArrayUnsigned()
	let l = len < bytes.length ? len : bytes.length;
	for (let i = l - 1; i >= 0; i--) {
		bytes[i] &= 0xFF;
	}

	if (len < bytes.length) {
		bytes = bytes.slice(bytes.length - len);
	} else while (len > bytes.length) {
		bytes.unshift(0);
	}

	return bytes;
}

export class ECPointFp {
	/**
	 * @param {ECCurveFp} curve 
	 * @param {ECFieldElementFp | null} x 
	 * @param {ECFieldElementFp | null} y 
	 * @param {(BigInteger | null)=} z 
	 */
	constructor(curve,x,y,z) {
		this.curve = curve;
		this.x = x;
		this.y = y;
		// Projective coordinates: either zinv == null or z * zinv == 1
		// z and zinv are just BigIntegers, not fieldElements
		if(z == null) {
			this.z = BigInteger.ONE();
		}
		else {
			this.z = z;
		}
		/** @type {BigInteger | null} */ this.zinv = null;
		//TODO: compression flag
	}

	/**
	 * @returns {ECFieldElementFp}
	 */
	getX() {
		if(this.zinv == null) {
			this.zinv = this.z.modInverse(this.curve.q);
		}
		let r = this.x.toBigInteger().multiply(this.zinv);
		this.curve.reduce(r);
		return this.curve.fromBigInteger(r);
	}

	/**
	 * @returns {ECFieldElementFp}
	 */
	getY() {
		if(this.zinv == null) {
			this.zinv = this.z.modInverse(this.curve.q);
		}
		let r = this.y.toBigInteger().multiply(this.zinv);
		this.curve.reduce(r);
		return this.curve.fromBigInteger(r);
	}

	/**
	 * @param {ECPointFp} other 
	 * @returns {boolean}
	 */
	equals(other) {
		if(other == this) return true;
		if(this.isInfinity()) return other.isInfinity();
		if(other.isInfinity()) return this.isInfinity();
		// u = Y2 * Z1 - Y1 * Z2
		let u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
		if(!u.equals(BigInteger.ZERO())) return false;
		// v = X2 * Z1 - X1 * Z2
		let v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
		return v.equals(BigInteger.ZERO());
	}

	/**
	 * @returns {boolean}
	 */
	isInfinity() {
		if((this.x == null) && (this.y == null)) return true;
		return this.z.equals(BigInteger.ZERO()) && !this.y.toBigInteger().equals(BigInteger.ZERO());
	}

	/**
	 * @returns {ECPointFp}
	 */
	negate() {
		return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
	}

	/**
	 * @param {ECPointFp} b 
	 * @returns {ECPointFp}
	 */
	add(b) {
		if(this.isInfinity()) return b;
		if(b.isInfinity()) return this;

		// u = Y2 * Z1 - Y1 * Z2
		let u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
		// v = X2 * Z1 - X1 * Z2
		let v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

		if(BigInteger.ZERO().equals(v)) {
			if(BigInteger.ZERO().equals(u)) {
				return this.twice(); // this == b, so double
			}
			return this.curve.getInfinity(); // this = -b, so infinity
		}

		let THREE = new BigInteger("3");
		let x1 = this.x.toBigInteger();
		let y1 = this.y.toBigInteger();
		let x2 = b.x.toBigInteger();
		let y2 = b.y.toBigInteger();

		let v2 = v.square();
		let v3 = v2.multiply(v);
		let x1v2 = x1.multiply(v2);
		let zu2 = u.square().multiply(this.z);

		// x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
		let x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
		// y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
		let y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
		// z3 = v^3 * z1 * z2
		let z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

		return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
	}

	/**
	 * @returns {ECPointFp}
	 */
	twice() {
		if(this.isInfinity()) return this;
		if(this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

		// TODO: optimized handling of constants
		let THREE = new BigInteger("3");
		let x1 = this.x.toBigInteger();
		let y1 = this.y.toBigInteger();

		let y1z1 = y1.multiply(this.z);
		let y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
		let a = this.curve.a.toBigInteger();

		// w = 3 * x1^2 + a * z1^2
		let w = x1.square().multiply(THREE);
		if(!BigInteger.ZERO().equals(a)) {
		w = w.add(this.z.square().multiply(a));
		}
		w = w.mod(this.curve.q);
		//this.curve.reduce(w);
		// x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
		let x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
		// y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
		let y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
		// z3 = 8 * (y1 * z1)^3
		let z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

		return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
	}

	/**
	 * Simple NAF (Non-Adjacent Form) multiplication algorithm
	 * TODO: modularize the multiplication algorithm
	 * @param {BigInteger} k 
	 * @returns {ECPointFp}
	 */
	multiply(k) {
		if(this.isInfinity()) return this;
		if(k.signum() == 0) return this.curve.getInfinity();

		let e = k;
		let h = e.multiply(new BigInteger("3"));

		let neg = this.negate();
		let R = this;

		let i;
		for(i = h.bitLength() - 2; i > 0; --i) {
			R = R.twice();

			let hBit = h.testBit(i);
			let eBit = e.testBit(i);

			if (hBit != eBit) {
				R = R.add(hBit ? this : neg);
			}
		}

		return R;
	}

	/**
	 * Compute this*j + x*k (simultaneous multiplication)
	 * @param {BigInteger} j 
	 * @param {ECPointFp} x 
	 * @param {BigInteger} k 
	 * @returns {ECPointFp}
	 */
	multiplyTwo(j,x,k) {
		/** @type {number} */ let i;
		if(j.bitLength() > k.bitLength())
			i = j.bitLength() - 1;
		else
			i = k.bitLength() - 1;

		let R = this.curve.getInfinity();
		let both = this.add(x);
		while(i >= 0) {
			R = R.twice();
			if(j.testBit(i)) {
			if(k.testBit(i)) {
				R = R.add(both);
			}
			else {
				R = R.add(this);
			}
			}
			else {
			if(k.testBit(i)) {
				R = R.add(x);
			}
			}
			--i;
		}

		return R;
	}

	/**
	 * @param {boolean} compressed 
	 * @returns {Array<number>}
	 */
	getEncoded(compressed) {
		let x = this.getX().toBigInteger();
		let y = this.getY().toBigInteger();

		// Get value as a 32-byte Buffer
		// Fixed length based on a patch by bitaddress.org and Casascius
		let enc = integerToBytes(x, 32);

		if (compressed) {
			if (y.isEven()) {
				// Compressed even pubkey
				// M = 02 || X
				enc.unshift(0x02);
			} else {
				// Compressed uneven pubkey
				// M = 03 || X
				enc.unshift(0x03);
			}
		} else {
			// Uncompressed pubkey
			// M = 04 || X || Y
			enc.unshift(0x04);
			enc = enc.concat(integerToBytes(y, 32));
		}
		return enc;
	}

	/**
	 * 
	 * @param {ECCurveFp} curve 
	 * @param {Array<number>} enc 
	 */
	static decodeFrom(curve, enc) {
		//let type = enc[0];
		let dataLen = enc.length - 1;

		// Extract x and y as byte arrays
		let xBa = enc.slice(1, 1 + dataLen / 2);
		let yBa = enc.slice(1 + dataLen / 2, 1 + dataLen);

		// Prepend zero byte to prevent interpretation as negative integer
		xBa.unshift(0);
		yBa.unshift(0);

		// Convert to BigIntegers
		let x = new BigInteger(xBa);
		let y = new BigInteger(yBa);

		// Return point
		return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
	}

	/**
	 * @param {ECCurveFp} curve 
	 * @param {string} encHex 
	 */
	static decodeFromHex(curve, encHex) {
		//let type = encHex.substr(0, 2); // shall be "04"
		let dataLen = encHex.length - 2;

		// Extract x and y as byte arrays
		let xHex = encHex.substr(2, dataLen / 2);
		let yHex = encHex.substr(2 + dataLen / 2, dataLen / 2);

		// Convert to BigIntegers
		let x = new BigInteger(xHex, 16);
		let y = new BigInteger(yHex, 16);

		// Return point
		return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
	}

	/**
	 * @param {ECPointFp} b 
	 * @returns {ECPointFp}
	 */
	add2D(b) {
		if (this.isInfinity()) return b;
		if (b.isInfinity()) return this;

		if (this.x.equals(b.x)) {
			if (this.y.equals(b.y)) {
				// this = b, i.e. this must be doubled
				return this.twice();
			}
			// this = -b, i.e. the result is the point at infinity
			return this.curve.getInfinity();
		}

		let x_x = b.x.subtract(this.x);
		let y_y = b.y.subtract(this.y);
		let gamma = y_y.divide(x_x);

		let x3 = gamma.square().subtract(this.x).subtract(b.x);
		let y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

		return new ECPointFp(this.curve, x3, y3);
	}

	/**
	 * @returns {ECPointFp}
	 */
	twice2D() {
		if (this.isInfinity()) return this;
		if (this.y.toBigInteger().signum() == 0) {
			// if y1 == 0, then (x1, y1) == (x1, -y1)
			// and hence this = -this and thus 2(x1, y1) == infinity
			return this.curve.getInfinity();
		}

		let TWO = this.curve.fromBigInteger(nbv(2));
		let THREE = this.curve.fromBigInteger(nbv(3));
		let gamma = this.x.square().multiply(THREE).add(this.curve.a).divide(this.y.multiply(TWO));

		let x3 = gamma.square().subtract(this.x.multiply(TWO));
		let y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

		return new ECPointFp(this.curve, x3, y3);
	}

	/**
	 * @param {BigInteger} k 
	 * @returns {ECPointFp}
	 */
	multiply2D(k) {
		if (this.isInfinity()) return this;
		if (k.signum() == 0) return this.curve.getInfinity();

		let e = k;
		let h = e.multiply(new BigInteger("3"));

		let neg = this.negate();
		let R = this;

		/** @type {number} */ let i;
		for (i = h.bitLength() - 2; i > 0; --i) {
			R = R.twice();

			let hBit = h.testBit(i);
			let eBit = e.testBit(i);

			if (hBit != eBit) {
				R = R.add2D(hBit ? this : neg);
			}
		}

		return R;
	}

	/**
	 * @returns {boolean}
	 */
	isOnCurve() {
		let x = this.getX().toBigInteger();
		let y = this.getY().toBigInteger();
		let a = this.curve.getA().toBigInteger();
		let b = this.curve.getB().toBigInteger();
		let n = this.curve.getQ();
		let lhs = y.multiply(y).mod(n);
		let rhs = x.multiply(x).multiply(x)
			.add(a.multiply(x)).add(b).mod(n);
		return lhs.equals(rhs);
	}

	/**
	 * @returns {string}
	 */
	toString() {
		return '(' + this.getX().toBigInteger().toString() + ',' +
			this.getY().toBigInteger().toString() + ')';
	}

	/**
	 * Validate an elliptic curve point.
	 *
	 * See SEC 1, section 3.2.2.1: Elliptic Curve Public Key Validation Primitive
	 * 
	 * @returns {boolean}
	 */
	validate() {
		let n = this.curve.getQ();

		// Check Q != O
		if (this.isInfinity()) {
			throw new Error("Point is at infinity.");
		}

		// Check coordinate bounds
		let x = this.getX().toBigInteger();
		let y = this.getY().toBigInteger();
		if (x.compareTo(BigInteger.ONE()) < 0 ||
			x.compareTo(n.subtract(BigInteger.ONE())) > 0) {
			throw new Error('x coordinate out of bounds');
		}
		if (y.compareTo(BigInteger.ONE()) < 0 ||
			y.compareTo(n.subtract(BigInteger.ONE())) > 0) {
			throw new Error('y coordinate out of bounds');
		}

		// Check y^2 = x^3 + ax + b (mod n)
		if (!this.isOnCurve()) {
			throw new Error("Point is not on the curve.");
		}

		// Check nQ = 0 (Q is a scalar multiple of G)
		if (this.multiply(n).isInfinity()) {
			// TODO: This check doesn't work - fix.
			throw new Error("Point is not a scalar multiple of G.");
		}

		return true;
	}
}

// ----------------
// ECCurveFp

export class ECCurveFp {
	/**
	 * @param {BigInteger} q 
	 * @param {BigInteger} a 
	 * @param {BigInteger} b 
	 */
	constructor(q,a,b) {
		this.q = q;
		this.a = this.fromBigInteger(a);
		this.b = this.fromBigInteger(b);
		this.infinity = new ECPointFp(this, null, null);
		this.reducer = new Barrett(this.q);
	}

	/**
	 * @returns {BigInteger}
	 */
	getQ() {
		return this.q;
	}

	/**
	 * @returns {ECFieldElementFp}
	 */
	getA() {
		return this.a;
	}

	/**
	 * @returns {ECFieldElementFp}
	 */
	getB() {
		return this.b;
	}

	/**
	 * @param {ECCurveFp} other 
	 * @returns {boolean}
	 */
	equals(other) {
		if(other == this) return true;
		return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
	}

	/**
	 * @returns {ECPointFp}
	 */
	getInfinity() {
		return this.infinity;
	}

	/**
	 * @param {BigInteger} x 
	 * @returns {ECFieldElementFp}
	 */
	fromBigInteger(x) {
		return new ECFieldElementFp(this.q, x);
	}

	/**
	 * @param {BigInteger} x 
	 */
	reduce(x) {
		this.reducer.reduce(x);
	}

	/**
	 * for now, work with hex strings because they're easier in JS
	 * @param {string} s 
	 * @returns {ECPointFp | null}
	 */
	decodePointHex(s) {
		switch(parseInt(s.substr(0,2), 16)) { // first byte
			case 0:
				return this.infinity;
			case 2:
			case 3:
				// point compression not supported yet
				return null;
			case 4:
			case 6:
			case 7:
				let len = (s.length - 2) / 2;
				let xHex = s.substr(2, len);
				let yHex = s.substr(len+2, len);

				return new ECPointFp(this,
					this.fromBigInteger(new BigInteger(xHex, 16)),
					this.fromBigInteger(new BigInteger(yHex, 16)));

			default: // unsupported
				return null;
		}
	}

	/**
	 * @param {ECPointFp} p 
	 * @returns {string}
	 */
	encodePointHex(p) {
		if (p.isInfinity()) return "00";
		let xHex = p.getX().toBigInteger().toString(16);
		let yHex = p.getY().toBigInteger().toString(16);
		let oLen = this.getQ().toString(16).length;
		if ((oLen % 2) != 0) oLen++;
		while (xHex.length < oLen) {
			xHex = "0" + xHex;
		}
		while (yHex.length < oLen) {
			yHex = "0" + yHex;
		}
		return "04" + xHex + yHex;
	}
}
