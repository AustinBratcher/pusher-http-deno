// import * as crypto from "https://deno.land/std@0.164.0/node/crypto.ts";
import { hmac } from "https://deno.land/x/hmac@v2.0.1/mod.ts";
// import * as Buffer from 'https://deno.land/std@0.164.0/node/internal/buffer.d.ts';
import * as util from './utils.js';
import { Buffer } from "https://deno.land/std/io/buffer.ts";

import { encode } from "https://deno.land/std/encoding/base64.ts"


/** Verifies and signs data against the key and secret.
 *
 * @constructor
 * @param {String} key app key
 * @param {String} secret app secret
 */
function Token(key, secret) {
  this.key = key
  this.secret = secret
}

/** Signs the string using the secret.
 *
 * @param {String} string
 * @returns {String}
 */
Token.prototype.sign = function (string) {
  // const message = string
  //
  // const encoder = new TextEncoder()
  // const keyBuf = encoder.encode(this.secret);
  // const key = await crypto.subtle.importKey(
  //   "raw",
  //   keyBuf,
  //   {name: "HMAC", hash: "SHA-256"},
  //   true,
  //   ["sign", "verify"],
  // )
  //
  // const data = encoder.encode(message);
  //
  // const result = crypto.subtle.sign("HMAC", key , data.buffer);
  // const r2 = await crypto.subtle.digest('HMAC', result);

  const result = hmac("sha256", this.secret, string, 'utf8', 'hex');
  console.log(result);
  return result; //new TextDecoder().decode(result.buffer);
}

/** Checks if the string has correct signature.
 *
 * @param {String} string
 * @param {String} signature
 * @returns {Boolean}
 */
Token.prototype.verify = function (string, signature) {
  return util.secureCompare(this.sign(string), signature)
}

export default Token;
