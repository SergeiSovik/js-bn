/**
 * Original work Copyright (c) 2003-2005 Tom Wu <tjw@cs.Stanford.EDU>
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

// Random number generator - requires a PRNG backend, e.g. prng4.js

"use strict";

import { Arcfour, rng_psize, prng_newstate } from "./prng4.js"

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

/** @type {Arcfour | null} */ let rng_state = null;
/** @type {Array<number> | null} */ let rng_pool = null;
/** @type {number} */ let rng_pptr = 0;

/**
 * Mix in a 32-bit integer into the pool
 * @param {number} x 
 */
export function rng_seed_int(x) {
	if (rng_pool === null) rng_seed_init();
	rng_pool[rng_pptr++] ^= x & 255;
	rng_pool[rng_pptr++] ^= (x >> 8) & 255;
	rng_pool[rng_pptr++] ^= (x >> 16) & 255;
	rng_pool[rng_pptr++] ^= (x >> 24) & 255;
	if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

/**
 * Mix in the current time (w/milliseconds) into the pool 
 */
export function rng_seed_time() {
	rng_seed_int(new Date().getTime());
}

// Initialize the pool with junk if needed.
function rng_seed_init() {
//if(rng_pool == null) {
//	rng_pool = new Array();
//	rng_pptr = 0;
	/** @type {number} */ let t;
	if(platform.crypto && platform.crypto.getRandomValues) {
		// Use webcrypto if available
		let ua = new Uint8Array(32);
		platform.crypto.getRandomValues(ua);
		for(t = 0; t < 32; ++t)
			rng_pool[rng_pptr++] = ua[t];
	}
	if(navigator.appName == "Netscape" && navigator.appVersion < "5" && platform.crypto) {
		// Extract entropy (256 bits) from NS4 RNG if available
		let z = /** @type {*} */ ( platform.crypto ).random(32);
		for(t = 0; t < z.length; ++t)
			rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
	}	
	while(rng_pptr < rng_psize) {	// extract some randomness from Math.random()
		t = Math.floor(65536 * Math.random());
		rng_pool[rng_pptr++] = t >>> 8;
		rng_pool[rng_pptr++] = t & 255;
	}
	rng_pptr = 0;
	rng_seed_time();
	//rng_seed_int(window.screenX);
	//rng_seed_int(window.screenY);
//}
}

/**
 * @returns {number}
 */
export function rng_get_byte() {
	if(rng_state == null) {
		rng_seed_time();
		rng_state = prng_newstate();
		rng_state.init(rng_pool);
		for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
			rng_pool[rng_pptr] = 0;
		rng_pptr = 0;
		//rng_pool = null;
	}
	// TODO: allow reseeding after first request
	return rng_state.next();
}

/**
 * @param {Array<number>} ba
 */
export function rng_get_bytes(ba) {
	let i;
	for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

export class SecureRandom {
	/**
	 * @param {Array<number>} ba
	 */
	nextBytes(ba) {
		return rng_get_bytes(ba);
	}
}
