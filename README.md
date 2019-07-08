# node-webtokens

Simple, opinionated implementation of [JWS](https://tools.ietf.org/html/rfc7515) and [JWE](https://tools.ietf.org/html/rfc7516) compact serialization.

### Simple

All functions exposed through a single set of straightforward APIs.

```javascript
const jwt = require('node-webtokens');

// JWS EXAMPLE
token = jwt.generate(alg, payload, key);
parsedToken = jwt.parse(token).verify(key);

// JWE EXAMPLE
token = jwt.generate(alg, enc, payload, key);
parsedToken = jwt.parse(token).verify(key);
```

Token parsing and token verification/decryption supported through chainable methods. When necessary, this enables the user to inspect the token header before proceeding with the verification/decryption. Here is an example:

```javascript
parsedToken = jwt.parse(token);

if (parsedToken.error) {
  // error handling logic
} else {
  // inspect parsedToken.header

  // proceed with verification
  parsedToken.verify(key);
}
```

Token verification can be fine-tuned through additional chainable methods. Example:

```javascript
parsedToken = jwt.parse(token)
                 .setTokenLifetime(120000)
                 .setAlgorithmList(['RS256', 'RS384'])
                 .setIssuer(['auth.mydomain.com'])
                 .setAudience(['A1B2C3D4E5.com.mydomain.myservice'])
                 .verify(key);
```

Keys can be automatically managed out of keystores (JavaScript objects holding multiple keys). Example:

```javascript
keystore = {
  'e5739df2261c8a0ed41715e7f62cc295': 'SATKcp7AMnCg0YdEBPIcgknBplYttePtQoRddpJjyVak9F5vEp/7pL0Q1236MkVQd7nIXGoaPt4w1dlrpEmY4A==',
  'f0fd89c4abe83811ee9afa92d0d687f7': '6Bzisgmhj9LGJDNjx/WBNRUsnZA8pXRpVxB7Pf8ar29XI158V4+t1GEqkCl5MYZhcOMTi5fa3yYr0Vcya6vUkA==',
  '20e009a52cd91dc7dc7a8d7da525fed5': '+PC/htwSB6pz4VRTcGL1iN74xlqoX6Q2oilsraVvSVefL+lr0tW1+/pOGQpdZpXtN20DjfbC0s4rHYZD2z924Q=='
};

token = jwt.generate(alg, payload, keystore, kid);
parsedToken = jwt.parse(token).verify(keystore);
```

### Opinionated

There are various [npm](https://www.npmjs.com/) packages that cover the [IETF JOSE](https://datatracker.ietf.org/wg/jose/documents/) scope striving for generality and flexibility. This specific package is shaped after the following strong assumptions, which somehow restrict its usability:

- No effort to ensure compatibility with older [Node.js](https://nodejs.org) versions. Most stringent requirement comes from the use of `crypto.timingSafeEqual()`, which is not available in [Node.js](https://nodejs.org) versions prior to v6.6.0;
- The [JWS](https://tools.ietf.org/html/rfc7515)/[JWE](https://tools.ietf.org/html/rfc7516) payload must be a JavaScript object (a.k.a. hash or dictionary);
- The `iat` claim is automatically added to the payload at token generation time, and comes in the form of a Unix timestamp (number of seconds);
- The [JWS](https://tools.ietf.org/html/rfc7515)/[JWE](https://tools.ietf.org/html/rfc7516) header is automatically generated at token generation time, with limited control by the user.

### Installation

```
npm install node-webtokens --save
```

### Supported JWS algorithms

| Algorithm | Minimum key requirements                                                 |
|:----------|:-------------------------------------------------------------------------|
| `HS256` | 32-octet key, passed either as base64 string or as buffer; same key for token generation and token verification |
| `HS384` | 48-octet key, passed either as base64 string or as buffer; same key for token generation and token verification |
| `HS512` | 64-octet key, passed either as base64 string or as buffer; same key for token generation and token verification |
| `RS256` | 2048-bit RSA key in PEM format, passed either as UTF-8 string or as buffer; private key for token generation, public key or certificate for token verification |
| `RS384` | 2048-bit RSA key in PEM format, passed either as UTF-8 string or as buffer; private key for token generation, public key or certificate for token verification |
| `RS512` | 2048-bit RSA key in PEM format, passed either as UTF-8 string or as buffer; private key for token generation, public key or certificate for token verification |
| `ES256` | P-256 EC key in PEM format, passed either as UTF-8 string or as buffer; private key for token generation, public key or certificate for token verification; P-256 keys are identified as `prime256v1` in OpenSSL |
| `ES384` | P-384 EC key in PEM format, passed either as UTF-8 string or as buffer; private key for token generation, public key or certificate for token verification; P-384 keys are identified as `secp384r1` in OpenSSL |
| `ES512` | P-521 EC key in PEM format, passed either as UTF-8 string or as buffer; private key for token generation, public key or certificate for token verification; P-521 keys are identified as `secp521r1` in OpenSSL |

*Table 1 - List of JWS algorithms*

### Supported JWE key management algorithms

| Algorithm            | Minimum key requirements                                                   |
|:---------------------|:---------------------------------------------------------------------------|
| `RSA-OAEP`           | 2048-bit RSA key in PEM format, passed either as UTF-8 string or as buffer; public key or certificate for token generation, private key for token decryption |
| `A128KW`             | 16-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |
| `A192KW`             | 24-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |
| `A256KW`             | 32-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |
| `dir`                | n/a                                                                        |
| `PBES2-HS256+A128KW` | Password, passed either as UTF-8 string or as buffer; same password for token generation and token decryption; a 16-octet key is derived from the password through [PBKDF2](https://tools.ietf.org/html/rfc8018) |
| `PBES2-HS384+A192KW` | Password, passed either as UTF-8 string or as buffer; same password for token generation and token decryption; a 24-octet key is derived from the password through [PBKDF2](https://tools.ietf.org/html/rfc8018) |
| `PBES2-HS512+A256KW` | Password, passed either as UTF-8 string or as buffer; same password for token generation and token decryption; a 32-octet key is derived from the password through [PBKDF2](https://tools.ietf.org/html/rfc8018) |

*Table 2 - List of JWE key management algorithms*

### Supported JWE content encryption algorithms

| Algorithm       | Minimum key requirements (*)                                 |
|:----------------|:-------------------------------------------------------------|
| `A128CBC-HS256` | 32-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |
| `A192CBC-HS384` | 48-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |
| `A256CBC-HS512` | 64-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |
| `A128GCM`       | 16-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |
| `A192GCM`       | 24-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |
| `A256GCM`       | 32-octet key, passed either as base64 string or as buffer; same key for token generation and token decryption |

*Table 3 - List of JWE content encryption algorithms*

(*) These requirements are relevant only when direct content encryption is used (key management algorithm equal to `dir`). In all the other cases, the [JWE](https://tools.ietf.org/html/rfc7516) generation API takes care of generating a single-use content encryption key of appropriate length.

### Synchronous vs. asynchronous

The token generation API and token verification API can both be used in either synchronous or asynchronous mode. Example:

```javascript
// SYNCHRONOUS API MODE
token = jwt.generate('HS256', payload, key);
parsedToken = jwt.parse(token).verify(key);

// ASYNCHRONOUS API MODE
jwt.generate('PBES2-HS512+A256KW', 'A256GCM', payload, pwd, (error, token) => {
  jwt.parse(token).verify(pwd, (error, parsedToken) => {
    // other statements
  });
});
```

All the [Node.js](https://nodejs.org) crypto functions used in this package are synchronous, with the exception of [PBKDF2](https://tools.ietf.org/html/rfc8018), which can be invoked either synchronously as `crypto.pbkdf2Sync()` or asynchronously as `crypto.pbkdf2()`. This implies that the use of the asynchronous API mode makes a real difference in terms of execution only when one of the algorithms based on [PBKDF2](https://tools.ietf.org/html/rfc8018) is selected, namely  `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW` or `PBES2-HS512+A256KW`.   

> Use of the token generation and token verification APIs in asynchronous mode is recommended for [JWE](https://tools.ietf.org/html/rfc7516) when the selected key management algorithm is `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW` or `PBES2-HS512+A256KW`. Conversely, use of the synchronous mode is preferable for [JWS](https://tools.ietf.org/html/rfc7515) and for all other [JWE](https://tools.ietf.org/html/rfc7516) cases.

### Token generation

Single API, supporting two slightly different usage patterns, each with synchronous and asynchronous mode:

**jwt.generate(alg, [enc,] payload, key[, callback])**   
**jwt.generate(alg, [enc,] payload, keystore, kid[, callback])**

- `alg` - String corresponding to one of the algorithms listed in *Table 1* for [JWS](https://tools.ietf.org/html/rfc7515) or in *Table 2* for [JWE](https://tools.ietf.org/html/rfc7516) (case sensitive spelling);
- `enc` - Present only for [JWE](https://tools.ietf.org/html/rfc7516); string corresponding to one of the algorithms listed in *Table 3* (case sensitive spelling);
- `payload` - JavaScript object (a.k.a. hash or dictionary); if already present, the `iat` claim is overridden at token generation time;
- `key` - Key subject to the requirements specified in *Table 1*, *Table 2* or *Table 3*, depending on the selected `alg` value;
- `keystore` - JavaScript object holding multiple keys;
- `kid` - Key identifier; string; must exist in `keystore`.

When the `keystore` / `kid` pattern is used, the `kid` claim is automatically added to the token header.

When used in synchronous mode, the token generation API returns the token as string. When used in asynchronous mode, the `callback` function is invoked with parameters `(error, token)`.

### Token parsing and verification/decryption

Token parsing and token verification/decryption are supported through chainable methods.

**jwt.parse(token)**

The token parsing API is invoked with the token (string) as input and returns a `ParsedToken` object with the following properties:
- `error` - Error condition as JavaScript object; present if parsing could not be completed (e.g., invalid token, non parsable header);
- `parts` - Array of strings, with each string corresponding to one of the token parts (three parts for [JWS](https://tools.ietf.org/html/rfc7515), five parts for [JWE](https://tools.ietf.org/html/rfc7516));
- `type` - Either `JWS` or `JWE` or not present, with the latter relevant in case the token type could not be recognized (invalid token error);
- `header` - Token header as JavaScript object; not present if the token header could not be parsed;
- `payload` - Token payload as JavaScript object; present only for [JWS](https://tools.ietf.org/html/rfc7515) tokens and in absence of errors; for [JWE](https://tools.ietf.org/html/rfc7516) tokens the payload gets added to the `ParsedToken` object after decryption, which is performed when the token verification API is invoked.

Token parsing never throws errors. Any error condition encountered during parsing is reported in the `error` object.

**parsedToken.setTokenLifetime(lifetime)**

The `setTokenLifetime` method can be used to configure the token lifetime to be considered when assessing the token validity. The parameter `lifetime` constraints the maximum number of seconds elapsed since the generation of the token (indicated by the `iat` claim in the token payload).  

If the `setTokenLifetime` method is not used, then token verification does not encompass expiration based on the `iat` claim. However, if the token payload contains the `exp` claim, then the token is still subject to expiration based on the `exp` claim.

The `setTokenLifetime` method does not throw errors. The specified `lifetime` value is simply ignored if it is not an integer number greater than zero.

> Token verification does not enforce the presence of the `exp` claim in the token payload. However, if present, the `exp` claim is processed.

**parsedToken.setAlgorithmList(algList[, encList])**

The `setAlgorithmList` method can be used to configure the list of algorithms that are considered acceptable:
- `algList` - String or array of strings corresponding to one or multiple of the algorithms listed in *Table 1* for [JWS](https://tools.ietf.org/html/rfc7515) or in *Table 2* for [JWE](https://tools.ietf.org/html/rfc7516) (case-sensitive spelling);  
- `encList` - Only relevant for [JWE](https://tools.ietf.org/html/rfc7516); string or array of strings corresponding to one or multiple of the algorithms listed in *Table 3* (case-sensitive spelling);

Integrity check/decryption is not attempted during verification if the token under verification does not comply with the configured algorithm list. In that case, the token is simply reported as invalid because of the unwanted algorithm.

The `setAlgorithmList` method does not throw errors. If the algorithm list contains only invalid or non-existent algorithms, then all the tokens are reported as invalid.

**parsedToken.setAudience(audList)**

The `setAudience` method can be used to configure the acceptable values of the `aud` claim. Input parameter `audList` can be a string or an array of strings.

The `setAudience` method does not throw errors. If `audList` is not a string or an array of strings, then the action is simply ignored.

> Token verification enforces the presence of the `aud` claim in the token payload only if the `setAudience` method is invoked before proceeding with the verification.

**parsedToken.setIssuer(issList)**

The `setIssuer` method can be used to configure the acceptable values of the `iss` claim. Input parameter `issList` can be a string or an array of strings.

The `setIssuer` method does not throw errors. If `issList` is not a string or an array of strings, then the action is simply ignored.

> Token verification enforces the presence of the `iss` claim in the token payload only if the `setIssuer` method is invoked before proceeding with the verification.

**parsedToken.verify(key[, callback])**   
**parsedToken.verify(keystore[, callback])**

- `key` - Key subject to the requirements specified in *Table 1*, *Table 2* or *Table 3*, depending on the `alg` claim found in the token header;
- `keystore` - JavaScript object holding multiple keys; the key used for verification is determined on the basis of the `kid` claim found in the token header.

When used in synchronous mode, the `verify` method returns the `ParsedToken` object enriched with additional properties. When used in asynchronous mode, the `callback` function is invoked with parameters `(error, parsedToken)`.

After the verification, the `ParsedToken` object exposes the following properties:
- `valid` - Present and equal to `true` (boolean) if the token is valid and  not expired; absent in all other cases;
- `expired` - Present and equal to the token expiration time (Unix timestamp, seconds) if the token is valid but expired; absent in all other cases;
- `error` - Error condition as JavaScript object; present if token verification could not be completed or the token was found invalid; absent in all other cases; when present, the `error` object always includes the `message` property that specifies the reason why token verification failed;
- `parts` - Array of strings, with each string corresponding to one of the token parts (three parts for [JWS](https://tools.ietf.org/html/rfc7515), five parts for [JWE](https://tools.ietf.org/html/rfc7516));
- `type` - Either `JWS` or `JWE`; always present for valid or expired tokens; may not be present otherwise;
- `header` - Token header as JavaScript object; always present for valid or expired tokens; may not be present otherwise;
- `payload` - Token payload as JavaScript object; always present for valid or expired tokens; may not be present otherwise.

The following example illustrates a plausible handling of the final `ParsedToken` object:

```javascript
if (parsedToken.error) {
  // error handling; parsedToken.error.message provides details

} else if (parsedToken.expired) {
  // token has expired; the parsedToken.expired value indicates when

} else {
  // token is valid; parsedToken.payload is ready for use

}
```

### Examples

Token generated/verified with individual key:

```javascript
const jwt = require('node-webtokens');

var key = getKeyFromSomewhere();

var payload = {
  iss: 'auth.mydomain.com',
  aud: 'A1B2C3D4E5.com.mydomain.myservice',
  sub: 'jack.sparrow@example.com',
  info: 'Hello World!',
  list: [1, 2, 3]
};

var token = jwt.generate('HS512', payload, key);
console.log(token);
// eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJhdXRoLm15ZG9tYWluLmNvbSIsImF1ZCI6IkExQjJDM0Q0RTUuY29tLm15ZG9tYWluLm15c2VydmljZSIsInN1YiI6ImphY2suc3BhcnJvd0BleGFtcGxlLmNvbSIsImluZm8iOiJIZWxsbyBXb3JsZCEiLCJsaXN0IjpbMSwyLDNdLCJpYXQiOjE0OTQ0NTEwMDR9.Rzb8KJ6du4QKnd9goevhswj56Y3polY_IwF6_onDKxa9IbEtBCUBfmgdZDZdE5meLBUFw9PaMqbj3fo3L3JEQA

var parsed = jwt.parse(token).verify(key);
console.log(parsed.valid);
// true
console.log(parsed.header);
// { alg: 'HS512' }
console.log(parsed.payload);
/* { iss: 'auth.mydomain.com',
     aud: 'A1B2C3D4E5.com.mydomain.myservice',
     sub: 'jack.sparrow@example.com',
     info: 'Hello World!',
     list: [ 1, 2, 3 ],
     iat: 1494451004 } */
```

Token generated/verified with keystore:

```javascript
var keystore = {
  'e5739df2261c8a0ed41715e7f62cc295': 'SATKcp7AMnCg0YdEBPIcgknBplYttePtQoRddpJjyVak9F5vEp/7pL0Q1236MkVQd7nIXGoaPt4w1dlrpEmY4A==',
  'f0fd89c4abe83811ee9afa92d0d687f7': '6Bzisgmhj9LGJDNjx/WBNRUsnZA8pXRpVxB7Pf8ar29XI158V4+t1GEqkCl5MYZhcOMTi5fa3yYr0Vcya6vUkA==',
  '20e009a52cd91dc7dc7a8d7da525fed5': '+PC/htwSB6pz4VRTcGL1iN74xlqoX6Q2oilsraVvSVefL+lr0tW1+/pOGQpdZpXtN20DjfbC0s4rHYZD2z924Q=='
};

token = jwt.generate('HS512', payload, keystore, 'f0fd89c4abe83811ee9afa92d0d687f7');
console.log(token);
// eyJhbGciOiJIUzUxMiIsImtpZCI6ImYwZmQ4OWM0YWJlODM4MTFlZTlhZmE5MmQwZDY4N2Y3In0.eyJpc3MiOiJhdXRoLm15ZG9tYWluLmNvbSIsImF1ZCI6IkExQjJDM0Q0RTUuY29tLm15ZG9tYWluLm15c2VydmljZSIsInN1YiI6ImphY2suc3BhcnJvd0BleGFtcGxlLmNvbSIsImluZm8iOiJIZWxsbyBXb3JsZCEiLCJsaXN0IjpbMSwyLDNdLCJpYXQiOjE0OTQ0NTEwMDR9.z9mawWuGjE0eIQV08YtWTrlD7OAnmxGaLWFiBlXMn9MwzYHE-Sa9KhPLeeWuSx1c8at62F2IegK8O61gDGUA_g

parsed = jwt.parse(token).verify(keystore);
console.log(parsed.valid);
// true
console.log(parsed.header);
// { alg: 'HS512', kid: 'f0fd89c4abe83811ee9afa92d0d687f7' }
```

> Note the `kid` claim automatically added to the token header.

Verification key not found in keystore:

```javascript
token = jwt.generate('HS512', payload, keystore, 'f0fd89c4abe83811ee9afa92d0d687f7');

delete keystore['f0fd89c4abe83811ee9afa92d0d687f7'];

parsed = jwt.parse(token).verify(keystore);
console.log(parsed.error);
/* { message: 'Key with id not found',
     kid: 'f0fd89c4abe83811ee9afa92d0d687f7' } */
```

> The offending key identifier is exposed in the `error` object.

Expired token:

```javascript
token = jwt.generate('HS512', payload, key);

setTimeout(() => {
  parsed = jwt.parse(token).setTokenLifetime(3).verify(key);
  console.log(parsed.expired);
  // 1494451007

}, 5000);
```

> In the above example, expiration is determined on the basis of the `iat` claim and of the configured token lifetime (3 seconds). However, in case the token payload contains the `exp` claim, that is considered as well.

Token using unwanted algorithm:

```javascript
token = jwt.generate('HS256', payload, key);

parsed = jwt.parse(token)
            .setAlgorithmList(['HS384', 'HS512'])
            .verify(key);

console.log(parsed.error);
// { message: 'Unwanted algorithm HS256' }
```

Parsing and verification as separate steps. [JWS](https://tools.ietf.org/html/rfc7515) example:

```javascript
token = jwt.generate('HS512', payload, key);

parsed = jwt.parse(token);
console.log(parsed.header);
// { alg: 'HS512' }
console.log(parsed.payload);
/* { iss: 'auth.mydomain.com',
     aud: 'A1B2C3D4E5.com.mydomain.myservice',
     sub: 'jack.sparrow@example.com',
     info: 'Hello World!',
     list: [ 1, 2, 3 ],
     iat: 1494451807 } */

parsed.setTokenLifetime(600).verify(key);
console.log(parsed.valid);
// true
```

Parsing and verification as separate steps. [JWE](https://tools.ietf.org/html/rfc7516) example:

```javascript
token = jwt.generate('A256KW', 'A256GCM', payload, key);

parsed = jwt.parse(token);
console.log(parsed.header);
// { alg: 'A256KW', enc: 'A256GCM' }
console.log(parsed.payload);
// undefined

parsed.setTokenLifetime(600).verify(key);
console.log(parsed.valid);
// true
console.log(parsed.payload);
/* { iss: 'auth.mydomain.com',
     aud: 'A1B2C3D4E5.com.mydomain.myservice',
     sub: 'jack.sparrow@example.com',
     info: 'Hello World!',
     list: [ 1, 2, 3 ],
     iat: 1494451807 } */
```

Token generation with asynchronous API:

```javascript
jwt.generate('PBES2-HS512+A256KW', 'A256GCM', payload, key, (error, token) => {
  console.log(token);
  // eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoxMDAwLCJwMnMiOiJVRUpGVXpJdFNGTTFNVElyUVRJMU5rdFhBRGN0N2dnMk1qWGsifQ.IeIzzbZBtb65xF9z1I_L39up0V7FBtSlTJKMNft4_DD6pdQEiIMXAw.kihjXwJhu2ZC3ckd.CTbf_iRZrYho2Y-iw-1IHVh-POCYzBX0QhZ3j3onycb3hjMU6iWKokiKKeyzyG8UGLKO8uT5pyndGUNmyGAc-sJSMwZN5chHovet2JRsxjDC4PWiaMoE423eMqI3cc3iK4k9c71aKOOQOsEXbBohKwOy-nnlwU62ombiRejptb5p22V-FL7OwqK14-EcKSJxnvU8XRq4pX9HWU9G.jMnFV6OK2yBVUnw-W7YJKA
});
```

> With [PBES2](https://tools.ietf.org/html/rfc7518#section-4.8), key derivation at token generation time performs 1024 [PBKDF2](https://tools.ietf.org/html/rfc8018) iterations. Hence the recommendation to use the asynchronous mode.

Token verification with asynchronous API:

```javascript
jwt.parse(token).setTokenLifetime(600).verify(key, (error, parsed) => {
    console.log(parsed.valid);
    // true
    console.log(parsed.header);
    /* { alg: 'PBES2-HS512+A256KW',
         enc: 'A256GCM',
         p2c: 1024,
         p2s: 'UEJFUzItSFM1MTIrQTI1NktXADct7gg2MjXk' } */
    console.log(parsed.payload);
    /* { iss: 'auth.mydomain.com',
         aud: 'A1B2C3D4E5.com.mydomain.myservice',
         sub: 'jack.sparrow@example.com',
         info: 'Hello World!',
         list: [ 1, 2, 3 ],
         iat: 1494451023 } */
  });
```

> With [PBES2](https://tools.ietf.org/html/rfc7518#section-4.8), key derivation at token verification time performs the number of [PBKDF2](https://tools.ietf.org/html/rfc8018) iterations indicated by the `p2c` claim in the [JWE](https://tools.ietf.org/html/rfc7516) header. For protection against bogus tokens, the token verification API rejects `p2c` values larger than 1024 when used in synchronous mode or 16384 when used in asynchronous mode.

### Credits

The JavaScript code used for ECDSA signature conversion from DER to concatenated and vice-versa is directly derived from the [ecdsa-sig-formatter](https://github.com/Brightspace/node-ecdsa-sig-formatter) module.
