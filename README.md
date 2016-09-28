# IMS Json Web Token
An implementation of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519). Syntax was inspired by unirest.

# Install
```bash
$ npm install ims-json
```

# Usage

## Creating a token

You create a new token by calling the create function. The `iat` property will be automatically assigned to the current time. You can override this by setting `iat` directly or by calling `tok.set('iat', time)`.

You can assign any public claim by calling the appropriate method. Custom / private claims can be assigned by calling the `set` method.

* `issuedAt` sets the time this token was issued. Defaults to now if no argument is supplied.
* `expiration` sets the expiration date relative to the `issuedAt` time. Can either be the number of seconds, or a string describing a time span [rauchg/ms](https://github.com/rauchg/ms.js). i.e.: `'60s'`, `'8h'`, `'1 days'`
* `notBefore` sets the notBefore time relative to the `issuedAt` time. Can either be the number of seconds, or a string describing a time span [rauchg/ms](https://github.com/rauchg/ms.js). i.e.: `'60s'`, `'8h'`, `'1 days'`
* `jwtid` defaults to a v4 uuid if no argument is supplied.
* `audience`
* `issuer`
* `subject`
* `principal`
* `type`
* `audience`

```js
let jwt = require('ims-jwt');
let seckey = fs.readFileSync('private.key');  // get private key

let token = jwt.create()
.expires('30m') // valid for 30 mins
.issuer('http://auth.mysite.com')
.audience('http://api.mysite.com')
.set('cus', { id: 123, key: 'custom' })
.jwtid() // defaults to v4 uuid
.subject('myid1234')
.tokenize('RS256', seckey);

```

### `myjwt.tokenize(algo, secretOrPrivateKey)`
Generates a signed token

`algo` The signing algorithm

`secretOrPrivateKey` is a string or buffer containing either the secret key (for HMAC), or the PEM encoded private key for RSA and ECDSA.

## Verifying a token
Verifying a token is straightforward process:
1. Parse the token.
2. Compare any claims against an expected value.
3. Verify the signature against a key.

If any of the claim comparisons fail, or the signature verification match fails an exception is thrown.

```js
let jwt = require('ims-jwt');
let pubkey = fs.readFileSync('public.pem');  // get private key

try {
    jwt.verify(token)
    .expires('2s')
    .issuer('http://auth.mysite.com')
    .audience('http://api.mysite.com')
    .verify(pubkey);    
} catch (err) {
    // failed
}
```

### `myjwt.verify(secretOrPublicKey)`
Verifies a signed token

`secretOrPrivateKey` is a string or buffer containing either the secret key (for HMAC), or the PEM encoded public key for RSA and ECDSA.

### Reading the claims from a token
You can read the claims from a parsed token by accessing the properties directly
```js
let jwt = require('ims-jwt');

let data = jwt.verify(token);

let issuer = data.iss;
let subject = data.sub;
//...
let custom = data.cus;
```

## Algorithms supported

Supported algorithm values:

alg Parameter Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA using SHA-256 hash algorithm
RS384 | RSASSA using SHA-384 hash algorithm
RS512 | RSASSA using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm
none | No digital signature

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
