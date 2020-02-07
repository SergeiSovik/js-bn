/**
 * Original work Copyright (c) 2003-2005 Tom Wu <tjw@cs.Stanford.EDU>
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

// prng4.js - uses Arcfour as a PRNG

"use strict";

export class Arcfour {
	constructor() {
		this.i = 0;
		this.j = 0;
		/** @type {Array<number>} */ this.S = new Array();
	}

	/**
	 * Initialize arcfour context from key, an array of ints, each from [0..255] 
	 * @param {string | Array<number>} key 
	 */
	init(key) {
		/** @type {number} */ let i;
		/** @type {number} */ let j;
		/** @type {number} */ let t;
		for(i = 0; i < 256; ++i)
			this.S[i] = i;
		j = 0;
		for(i = 0; i < 256; ++i) {
			j = (j + this.S[i] + key[i % key.length]) & 255;
			t = this.S[i];
			this.S[i] = this.S[j];
			this.S[j] = t;
		}
		this.i = 0;
		this.j = 0;
	}

	/**
	 * @returns {number}
	 */
	next() {
		/** @type {number} */ let t;
		this.i = (this.i + 1) & 255;
		this.j = (this.j + this.S[this.i]) & 255;
		t = this.S[this.i];
		this.S[this.i] = this.S[this.j];
		this.S[this.j] = t;
		return this.S[(t + this.S[this.i]) & 255];
	}
}

/**
 * Plug in your RNG constructor here
 * @returns {Arcfour}
 */
export function prng_newstate() {
	return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
export const rng_psize = 256;
