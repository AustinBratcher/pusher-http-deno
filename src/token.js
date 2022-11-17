import { hmac } from "https://deno.land/x/hmac@v2.0.1/mod.ts";
import * as util from './utils.js';


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
  return hmac("sha256", this.secret, string, 'utf8', 'hex');
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
