const fs = require('fs');
const crypto = require('crypto');
const jwt = require('../index.js');

const KEYS_DIR = __dirname + '/pem_keys/';

var simKey = crypto.randomBytes(64);
var priRsa = fs.readFileSync(KEYS_DIR + 'priRsa.key');
var pubRsa = fs.readFileSync(KEYS_DIR + 'pubRsa.key');
var priEc256 = fs.readFileSync(KEYS_DIR + 'priEc256.key');
var pubEc256 = fs.readFileSync(KEYS_DIR + 'pubEc256.key');
var priEc384 = fs.readFileSync(KEYS_DIR + 'priEc384.key');
var pubEc384 = fs.readFileSync(KEYS_DIR + 'pubEc384.key');
var priEc521 = fs.readFileSync(KEYS_DIR + 'priEc521.key');
var pubEc521 = fs.readFileSync(KEYS_DIR + 'pubEc521.key');

var payload = {
  iss: 'auth.mydomain.com',
  aud: 'A1B2C3D4E5.com.mydomain.myservice',
  sub: 'jack.sparrow@example.com',
  info: 'Hello World!',
  list: [1, 2, 3]
}

var cases = [
  {
    alg: 'HS256',
    sKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both generation and verification'
  },
  {
    alg: 'HS384',
    sKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both generation and verification'
  },
  {
    alg: 'HS512',
    sKey: simKey,
    vKey: simKey,
    label: 'key as buffer at both generation and verification'
  },
  {
    alg: 'HS256',
    sKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at generation, as base64 string at verification'
  },
  {
    alg: 'HS384',
    sKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at generation, as base64 string at verification'
  },
  {
    alg: 'HS512',
    sKey: simKey,
    vKey: simKey.toString('base64'),
    label: 'key as buffer at generation, as base64 string at verification'
  },
  {
    alg: 'HS256',
    sKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at generation, as buffer at verification'
  },
  {
    alg: 'HS384',
    sKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at generation, as buffer at verification'
  },
  {
    alg: 'HS512',
    sKey: simKey.toString('base64'),
    vKey: simKey,
    label: 'key as base64 string at generation, as buffer at verification'
  },
  {
    alg: 'HS256',
    sKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both generation and verification'
  },
  {
    alg: 'HS384',
    sKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both generation and verification'
  },
  {
    alg: 'HS512',
    sKey: simKey.toString('base64'),
    vKey: simKey.toString('base64'),
    label: 'key as base64 string at both generation and verification'
  },
  {
    alg: 'RS256',
    sKey: priRsa,
    vKey: pubRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RS384',
    sKey: priRsa,
    vKey: pubRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RS512',
    sKey: priRsa,
    vKey: pubRsa,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'RS256',
    sKey: priRsa,
    vKey: pubRsa.toString(),
    label: 'private key as buffer, public key as UTF-8 string'
  },
  {
    alg: 'RS384',
    sKey: priRsa,
    vKey: pubRsa.toString(),
    label: 'private key as buffer, public key as UTF-8 string'
  },
  {
    alg: 'RS512',
    sKey: priRsa,
    vKey: pubRsa.toString(),
    label: 'private key as buffer, public key as UTF-8 string'
  },
  {
    alg: 'RS256',
    sKey: priRsa.toString(),
    vKey: pubRsa,
    label: 'private key as UTF-8 string, public key as buffer'
  },
  {
    alg: 'RS384',
    sKey: priRsa.toString(),
    vKey: pubRsa,
    label: 'private key as UTF-8 string, public key as buffer'
  },
  {
    alg: 'RS512',
    sKey: priRsa.toString(),
    vKey: pubRsa,
    label: 'private key as UTF-8 string, public key as buffer'
  },
  {
    alg: 'RS256',
    sKey: priRsa.toString(),
    vKey: pubRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'RS384',
    sKey: priRsa.toString(),
    vKey: pubRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'RS512',
    sKey: priRsa.toString(),
    vKey: pubRsa.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'ES256',
    sKey: priEc256,
    vKey: pubEc256,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'ES384',
    sKey: priEc384,
    vKey: pubEc384,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'ES512',
    sKey: priEc521,
    vKey: pubEc521,
    label: 'both private and public key as buffer'
  },
  {
    alg: 'ES256',
    sKey: priEc256,
    vKey: pubEc256.toString(),
    label: 'private key as buffer, public key as UTF-8 string'
  },
  {
    alg: 'ES384',
    sKey: priEc384,
    vKey: pubEc384.toString(),
    label: 'private key as buffer, public key as UTF-8 string'
  },
  {
    alg: 'ES512',
    sKey: priEc521,
    vKey: pubEc521.toString(),
    label: 'private key as buffer, public key as UTF-8 string'
  },
  {
    alg: 'ES256',
    sKey: priEc256.toString(),
    vKey: pubEc256,
    label: 'private key as UTF-8 string, public key as buffer'
  },
  {
    alg: 'ES384',
    sKey: priEc384.toString(),
    vKey: pubEc384,
    label: 'private key as UTF-8 string, public key as buffer'
  },
  {
    alg: 'ES512',
    sKey: priEc521.toString(),
    vKey: pubEc521,
    label: 'private key as UTF-8 string, public key as buffer'
  },
  {
    alg: 'ES256',
    sKey: priEc256.toString(),
    vKey: pubEc256.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'ES384',
    sKey: priEc384.toString(),
    vKey: pubEc384.toString(),
    label: 'both private and public key as UTF-8 string'
  },
  {
    alg: 'ES512',
    sKey: priEc521.toString(),
    vKey: pubEc521.toString(),
    label: 'both private and public key as UTF-8 string'
  }
];

console.log('\nBASIC TEST CASES - SYNCHRONOUS MODE\n');
var token;
var result;
for (let i in cases) {
  token = jwt.generate(cases[i].alg, payload, cases[i].sKey);
  result = jwt.parse(token)
              .setTokenLifetime(60000)
              .verify(cases[i].vKey);
  if (result.error) {
    console.log(`[NOK] ${cases[i].alg}, ${cases[i].label}`);
    console.log(result);
    process.exit();
  }
  console.log(`[OK] ${cases[i].alg}, ${cases[i].label}`);
}

console.log('\nBASIC TEST CASES - ASYNCHRONOUS MODE\n');
executeCaseAsync(0);

function executeCaseAsync(i) {
  if (i === cases.length) {
    process.exit();
  }
  jwt.generate(cases[i].alg, payload, cases[i].sKey, (error, token) => {
    if (error) throw error;
    jwt.parse(token)
       .setTokenLifetime(60000)
       .verify(cases[i].vKey, (error, result) => {
      if (error) throw error;
      if (result.error) {
        console.log(`[NOK] ${cases[i].alg}, ${cases[i].label}`);
        console.log(result);
        process.exit();
      }
      console.log(`[OK] ${cases[i].alg}, ${cases[i].label}`);
      executeCaseAsync(++i);
    });
  });
}
