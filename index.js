"use strict";

let util = require('util');
let crypto = require('crypto');
let fs = require('fs');

let base64url = require('base64-url');
let uuid = require('node-uuid');
let ecdsa = require('ecdsa-sig-formatter');
var ms = require('ms');

/**
 */
function logd() {
  // console.log.apply(this, arguments);
}

class JWTError extends Error {
  constructor(message) {
    super(message);
    this.message = message;
    this.name = 'JWTError';
  }
}

/**
*/
function bufferOrStreamToString(cert) {
  if (Buffer.isBuffer(cert) || typeof cert === 'string') {
    return Promise.resolve(cert);
  }
  return new Promise( (resolve, reject) => {
    let key = '';
    cert.on('data', chunk => key += chunk.toString('ascii'));
    cert.on('end', () => resolve(key));
    cert.on('error', err => reject(err));
  });
}

/**
*/
function verify(payload, sig, pubkey, algo) {
  logd('algo', algo);

  let translate = function(val) { return val; };
  let bits = algo.substring(2);
  let rsa = 'RSA-SHA' + bits;

  logd('-------------- verifying -----------------');
  logd('algo:', rsa);
  logd('payload:', payload);

  switch(algo) {
    case 'HS256':
    case 'HS384':
    case 'HS512': {
      let hmac = crypto.createHmac(rsa, pubkey);
      hmac.update(payload);
      return hmac.digest('base64') === sig;
    }

    case 'ES256':
    case 'ES384':
    case 'ES512':
      sig = ecdsa.joseToDer(sig, 'ES' + bits).toString('base64');
      // ↓↓↓↓↓↓↓↓↓↓↓

    case 'RS256':
    case 'RS384':
    case 'RS512': {
      let verify = crypto.createVerify(rsa);
      verify.update(payload);
      return verify.verify(pubkey, sig, 'base64');
    }

    case 'none':
      assert(!sig, `algorithm was set to 'none', but a signature was provided.`);
      assert(!pubkey, `algorithm was set to 'none', but a public key was provided.`);
      break;

    default:
      assert(false, `unsupported algorithm: ${algo}`);
      break;
  }
}

/**
*/
function sign(payload, seckey, algo) {
  logd('algo', algo);

  let bits = algo.substring(2);
  let rsa = 'RSA-SHA' + bits;
  logd('-------------- signing -----------------');
  logd('algo:', rsa);
  logd('payload:', payload);

  function rsaSign(rsa, payload, seckey) {
    let sign = crypto.createSign(rsa);
    sign.update(payload);
    return sign.sign(seckey, 'base64');
  }

  switch(algo) {
    case 'HS256':
    case 'HS384':
    case 'HS512': {
      let hmac = crypto.createHmac(rsa, seckey);
      hmac.update(payload);
      return hmac.digest('base64');
    }

    case 'ES256':
    case 'ES384':
    case 'ES512': {
      let s = rsaSign(rsa, payload, seckey);
      return ecdsa.derToJose(s, 'ES' + bits);
    }

    case 'RS256':
    case 'RS384':
    case 'RS512':
      return rsaSign(rsa, payload, seckey);

    case 'none':
      return '';

    default:
      assert(false, `unsupported algorithm: ${algo}`);
      break;
  }
}

/**
*/
function assert(b, fmt) {
  if (!b) {
    let errMsg = '';
    if (fmt) {
      const args = [].slice.call(arguments, 2);
      errMsg = util.format.bind(util, fmt).apply(null, args);
    }
    throw new JWTError(errMsg);
  }
}

/// convert from milliseconds to seconds
function ms2s(ms) { return (ms*1e-3)|0; }

/// convert from seconds to millisecons
function s2ms(s) { return (s*1e3)|0; }

/**
  Create a timestamp from a relative timestamp using human readable relative
  time differences. All timestamps are in seconds since Jan. 1st 1970.

  for example:
  let time = relativeTime(now, '60m');
*/
function relativeTime(ref, time) {

  switch (typeof time) {
    case 'string': {
      let millis = ms(time);
      assert(typeof millis !== 'undefined', `invalid type for time: ${time}`);
      return ref + ms2s(millis);
    }

    case 'number': {
      return ref + ms2s(time);
    }

    default:
      assert(false, `invalid type for time: ${time}`);
  }
}

/**
  Javascript Web Token for creating a signed token used in web authentication.
*/
class JwtSign {
  constructor() {
    this.iat = ms2s(Date.now());
  }

  expiration(exp) { this.exp = relativeTime(this.iat, exp); return this; }
  notBefore(nbf) { this.nbf = relativeTime(this.iat, nbf); return this; }
  issuedAt(at) { this.iat = at||Date.now(); return this; }
  issuer(issuer) { this.iss = issuer; return this; }
  audience(audience) { this.aud = audience; return this; }
  subject(subject) { this.sub = subject; return this; }
  principal(principal) { this.prn = principal; return this; }
  jwtid(jwtid) { this.jti = jwtid || uuid.v4(); return this; }
  type(type) { this.typ = type; return this; }
  toString() { return JSON.stringify(this); }

  /**
    Convert this object into a signed jwt token using the given algorithm and
    seckey.

    @param alg the algorithm for signing
    @param certOrKey a signing certificate or secret key (depending on the alg).
  */
  tokenize(alg, certOrKey) {
    let header = {
      typ: 'JWT',
      alg: alg
    };

    let h = JSON.stringify(header);
    let b = JSON.stringify(this);

    let content = `${base64url.encode(h)}.${base64url.encode(b)}`;
    let b64 = sign(content, certOrKey, alg);
    return `${content}.${base64url.escape(b64)}`;
  }

  /**
    Set an arbitrary key/value pair as part of the token.
  */
  set(key, val) {
    if (val === undefined || val === null) {
      delete this[key];
    } else {
      this[key] = val;
    }
    return this;
  }
}

/**
*/
class JwtVerify {

  constructor(token) {
    assert(token, 'no token provided');

    // <header>.<body>.<signature>
    let tokens = token.split('.');
    assert(tokens.length === 3, `invalid token: ${token}`);

    let header = JSON.parse(base64url.decode(tokens[0]));
    let body = JSON.parse(base64url.decode(tokens[1]));
    let sig = tokens[2];

    logd('header', header);
    logd('body', body);

    assert(header.typ === 'JWT', `token type must be JWT, found: '${header.typ}'`);
    this.token = token;
    this.header = header;
    this.body = body;
    this.sig = sig;
    Object.freeze(this);
  }

  verify(pubkey) {
    assert(pubkey, 'missing signing key');

    // <header>.<body>.<signature>
    let idx = this.token.lastIndexOf('.');
    assert(idx >= 0, 'invalid token');

    let body = this.token.substring(0, idx);
    assert(body, 'token missing body');

    let algo = this.header.alg;
    assert(algo, `invalid algo: ${algo}`);

    let sig = base64url.unescape(this.sig);
    assert(sig, `token signature is missing: ${sig}`);

    let suc = verify(body, sig, pubkey, algo);
    assert(suc, 'signature verification failed');
    return this;
  }

  expiration(tolerance) {
    let exp = this.body.exp;
    if (exp !== undefined) {
      let now = ms2s(Date.now());
      let off = tolerance ? ms(tolerance) : 0;
      assert(now < exp+off, 'token has expired');
    }
    return this;
  }

  notBefore(tolerance) {
    let nbf = this.body.nbf;
    if (nbf !== undefined) {
      let now = ms2s(Date.now());
      let off = tolerance ? ms(tolerance) : 0;
      assert(now+off > nbf, 'token is not yet active');
    }
    return this;
  }

  issuer(issuer) {
    assert(this.body.iss === issuer, 'issuer does not match');
    return this;
  }

  audience(audience) {
    assert(this.body.aud === audience, 'audience does not match');
    return this;
  }

  subject(subject) {
    assert(this.body.sub === subject, 'subject does not match');
    return this;
  }

  principal(principal) {
    assert(this.body.prn === principal, 'principal does not match');
    return this;
  }

  jwtid(jwtid) {
    assert(this.body.jti === jwtid, 'jwtid does not match');
    return this;
  }

  type(type) {
    assert(this.body.typ === type, 'type does not match');
    return this;
  }
}

/**
*/
module.exports = {
  ALGORITHMS: [
    'HS256', 'HS384', 'HS512',
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512'
  ],

  bufferOrStreamToString: bufferOrStreamToString,
  create: function() { return new JwtSign(); },
  verify: function(token) { return new JwtVerify(token); }
};
