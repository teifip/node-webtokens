const fs = require('fs');
const crypto = require('crypto');
const jwt = require('../index.js');

const KEYS_DIR = __dirname + '/pem_keys/';

const simKey = crypto.randomBytes(64);
const pwd = 'My very secret password';
const priRsa = fs.readFileSync(KEYS_DIR + 'priRsa.key');
const pubRsa = fs.readFileSync(KEYS_DIR + 'pubRsa.key');
const priEc256 = fs.readFileSync(KEYS_DIR + 'priEc256.key');
const pubEc256 = fs.readFileSync(KEYS_DIR + 'pubEc256.key');
const priEc384 = fs.readFileSync(KEYS_DIR + 'priEc384.key');
const pubEc384 = fs.readFileSync(KEYS_DIR + 'pubEc384.key');
const priEc521 = fs.readFileSync(KEYS_DIR + 'priEc521.key');
const pubEc521 = fs.readFileSync(KEYS_DIR + 'pubEc521.key');

const payload = {
  iss: 'auth.mydomain.com',
  aud: 'A1B2C3D4E5.com.mydomain.myservice',
  sub: 'jack.sparrow@example.com',
  info: 'Hello World!',
  list: [1, 2, 3, 4]
};

const tests = [
  {
    alg: 'dir',
    enc: 'A128CBC-HS256',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A192CBC-HS384',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A256CBC-HS512',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A128GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A192GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A256GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A128CBC-HS256',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'dir',
    enc: 'A192CBC-HS384',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'dir',
    enc: 'A256CBC-HS512',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'dir',
    enc: 'A128GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'dir',
    enc: 'A192GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'dir',
    enc: 'A256GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'dir',
    enc: 'A128CBC-HS256',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'dir',
    enc: 'A192CBC-HS384',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'dir',
    enc: 'A256CBC-HS512',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'dir',
    enc: 'A128GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'dir',
    enc: 'A192GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'dir',
    enc: 'A256GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'dir',
    enc: 'A128CBC-HS256',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A192CBC-HS384',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A256CBC-HS512',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A128GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A192GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'dir',
    enc: 'A256GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A128CBC-HS256',
    eKey: pubRsa,
    vKey: priRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A192CBC-HS384',
    eKey: pubRsa,
    vKey: priRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A256CBC-HS512',
    eKey: pubRsa,
    vKey: priRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A128GCM',
    eKey: pubRsa,
    vKey: priRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A192GCM',
    eKey: pubRsa,
    vKey: priRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A256GCM',
    eKey: pubRsa,
    vKey: priRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A128CBC-HS256',
    eKey: pubRsa,
    vKey: priRsa.toString(),
    label: 'public key as buffer, private key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A192CBC-HS384',
    eKey: pubRsa,
    vKey: priRsa.toString(),
    label: 'public key as buffer, private key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A256CBC-HS512',
    eKey: pubRsa,
    vKey: priRsa.toString(),
    label: 'public key as buffer, private key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A128GCM',
    eKey: pubRsa,
    vKey: priRsa.toString(),
    label: 'public key as buffer, private key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A192GCM',
    eKey: pubRsa,
    vKey: priRsa.toString(),
    label: 'public key as buffer, private key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A256GCM',
    eKey: pubRsa,
    vKey: priRsa.toString(),
    label: 'public key as buffer, private key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A128CBC-HS256',
    eKey: pubRsa.toString(),
    vKey: priRsa,
    label: 'public key as UTF-8 string, private key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A192CBC-HS384',
    eKey: pubRsa.toString(),
    vKey: priRsa,
    label: 'public key as UTF-8 string, private key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A256CBC-HS512',
    eKey: pubRsa.toString(),
    vKey: priRsa,
    label: 'public key as UTF-8 string, private key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A128GCM',
    eKey: pubRsa.toString(),
    vKey: priRsa,
    label: 'public key as UTF-8 string, private key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A192GCM',
    eKey: pubRsa.toString(),
    vKey: priRsa,
    label: 'public key as UTF-8 string, private key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A256GCM',
    eKey: pubRsa.toString(),
    vKey: priRsa,
    label: 'public key as UTF-8 string, private key as buffer'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A128CBC-HS256',
    eKey: pubRsa.toString(),
    vKey: priRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A192CBC-HS384',
    eKey: pubRsa.toString(),
    vKey: priRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A256CBC-HS512',
    eKey: pubRsa.toString(),
    vKey: priRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A128GCM',
    eKey: pubRsa.toString(),
    vKey: priRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A192GCM',
    eKey: pubRsa.toString(),
    vKey: priRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'RSA-OAEP',
    enc: 'A256GCM',
    eKey: pubRsa.toString(),
    vKey: priRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'A128KW',
    enc: 'A128CBC-HS256',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A192CBC-HS384',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A256CBC-HS512',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A128GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A192GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A256GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A128CBC-HS256',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A192CBC-HS384',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A256CBC-HS512',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A128GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A192GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A256GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A128CBC-HS256',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A192CBC-HS384',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A256CBC-HS512',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A128GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A192GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A256GCM',
    eKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A128CBC-HS256',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A192CBC-HS384',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A256CBC-HS512',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A128GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A192GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A256GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A128CBC-HS256',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A192CBC-HS384',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A256CBC-HS512',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A128GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A192GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A256GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A128CBC-HS256',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A192CBC-HS384',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A256CBC-HS512',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A128GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A192GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A256GCM',
    eKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at encryption, as base64 string at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A128CBC-HS256',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A192CBC-HS384',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A256CBC-HS512',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A128GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A192GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A256GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A128CBC-HS256',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A192CBC-HS384',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A256CBC-HS512',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A128GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A192GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A256GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A128CBC-HS256',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A192CBC-HS384',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A256CBC-HS512',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A128GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A192GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A256GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at encryption, as buffer at decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A128CBC-HS256',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A192CBC-HS384',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A256CBC-HS512',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A128GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A192GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A128KW',
    enc: 'A256GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A128CBC-HS256',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A192CBC-HS384',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A256CBC-HS512',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A128GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A192GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A192KW',
    enc: 'A256GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A128CBC-HS256',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A192CBC-HS384',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A256CBC-HS512',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A128GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A192GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'A256KW',
    enc: 'A256GCM',
    eKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A128CBC-HS256',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A192CBC-HS384',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A256CBC-HS512',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A128GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A192GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A256GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A128CBC-HS256',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A192CBC-HS384',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A256CBC-HS512',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A128GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A192GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A256GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A128CBC-HS256',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A192CBC-HS384',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256CBC-HS512',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A128GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A192GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256GCM',
    eKey: pwd,
    vKey: pwd,
    label: 'password as UTF-8 string at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A128CBC-HS256',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A192CBC-HS384',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A256CBC-HS512',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A128GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A192GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A256GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A128CBC-HS256',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A192CBC-HS384',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A256CBC-HS512',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A128GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A192GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A256GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A128CBC-HS256',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A192CBC-HS384',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256CBC-HS512',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A128GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A192GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256GCM',
    eKey: pwd,
    vKey: Buffer.from(pwd),
    label: 'password as UTF-8 string at encryption, as buffer at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A128CBC-HS256',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A192CBC-HS384',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A256CBC-HS512',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A128GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'ppassword as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A192GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A256GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A128CBC-HS256',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A192CBC-HS384',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A256CBC-HS512',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A128GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A192GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A256GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A128CBC-HS256',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A192CBC-HS384',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256CBC-HS512',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A128GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A192GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256GCM',
    eKey: Buffer.from(pwd),
    vKey: pwd,
    label: 'password as buffer at encryption, as UTF-8 string at decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A128CBC-HS256',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A192CBC-HS384',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A256CBC-HS512',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryptionn'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A128GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A192GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS256+A128KW',
    enc: 'A256GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A128CBC-HS256',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A192CBC-HS384',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A256CBC-HS512',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A128GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A192GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS384+A192KW',
    enc: 'A256GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A128CBC-HS256',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A192CBC-HS384',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256CBC-HS512',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A128GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A192GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  },
  {
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256GCM',
    eKey: Buffer.from(pwd),
    vKey: Buffer.from(pwd),
    label: 'password as buffer at both encryption and decryption'
  }
];

console.log('\nBASIC TEST CASES - SYNCHRONOUS MODE\n');
let token;
let result;
for (let test of tests) {
  token = jwt.generate(test.alg, test.enc, payload, test.eKey);
  result = jwt.parse(token)
              .setTokenLifetime(60000)
              .verify(test.vKey);
  if (result.error) {
    console.log(`[NOK] ${test.alg}, ${test.enc}, ${test.label}`);
    console.log(result);
    process.exit();
  }
  console.log(`[OK] ${test.alg}, ${test.enc}, ${test.label}`);
}

console.log('\nBASIC TEST CASES - ASYNCHRONOUS MODE\n');
executeCaseAsync(0);

function executeCaseAsync(idx) {
  if (idx === tests.length) process.exit();
  let test = tests[idx];
  jwt.generate(test.alg, test.enc, payload, test.eKey, (error, token) => {
    if (error) throw error;
    jwt.parse(token)
       .setTokenLifetime(60000)
       .verify(test.vKey, (error, result) => {
      if (error) throw error;
      if (result.error) {
        console.log(`[NOK] ${test.alg}, ${test.enc}, ${test.label}`);
        console.log(result);
        process.exit();
      }
      console.log(`[OK] ${test.alg}, ${test.enc}, ${test.label}`);
      executeCaseAsync(++idx);
    });
  });
}
