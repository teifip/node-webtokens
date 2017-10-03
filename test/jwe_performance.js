const fs = require('fs');
const crypto = require('crypto');
const jwt = require('../index.js');

const ITER = 1000;
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
  list: [1, 2, 3]
}

const cases = [
  {alg: 'dir', enc: 'A128CBC-HS256', eKey: simKey, vKey: simKey},
  {alg: 'dir', enc: 'A192CBC-HS384', eKey: simKey, vKey: simKey},
  {alg: 'dir', enc: 'A256CBC-HS512', eKey: simKey, vKey: simKey},
  {alg: 'dir', enc: 'A128GCM', eKey: simKey, vKey: simKey},
  {alg: 'dir', enc: 'A192GCM', eKey: simKey, vKey: simKey},
  {alg: 'dir', enc: 'A256GCM', eKey: simKey, vKey: simKey},
  {alg: 'RSA-OAEP', enc: 'A128CBC-HS256', eKey: pubRsa, vKey: priRsa},
  {alg: 'RSA-OAEP', enc: 'A192CBC-HS384', eKey: pubRsa, vKey: priRsa},
  {alg: 'RSA-OAEP', enc: 'A256CBC-HS512', eKey: pubRsa, vKey: priRsa},
  {alg: 'RSA-OAEP', enc: 'A128GCM', eKey: pubRsa, vKey: priRsa},
  {alg: 'RSA-OAEP', enc: 'A192GCM', eKey: pubRsa, vKey: priRsa},
  {alg: 'RSA-OAEP', enc: 'A256GCM', eKey: pubRsa, vKey: priRsa},
  {alg: 'A128KW', enc: 'A128CBC-HS256', eKey: simKey, vKey: simKey},
  {alg: 'A128KW', enc: 'A192CBC-HS384', eKey: simKey, vKey: simKey},
  {alg: 'A128KW', enc: 'A256CBC-HS512', eKey: simKey, vKey: simKey},
  {alg: 'A128KW', enc: 'A128GCM', eKey: simKey, vKey: simKey},
  {alg: 'A128KW', enc: 'A192GCM', eKey: simKey, vKey: simKey},
  {alg: 'A128KW', enc: 'A256GCM', eKey: simKey, vKey: simKey},
  {alg: 'A192KW', enc: 'A128CBC-HS256', eKey: simKey, vKey: simKey},
  {alg: 'A192KW', enc: 'A192CBC-HS384', eKey: simKey, vKey: simKey},
  {alg: 'A192KW', enc: 'A256CBC-HS512', eKey: simKey, vKey: simKey},
  {alg: 'A192KW', enc: 'A128GCM', eKey: simKey, vKey: simKey},
  {alg: 'A192KW', enc: 'A192GCM', eKey: simKey, vKey: simKey},
  {alg: 'A192KW', enc: 'A256GCM', eKey: simKey, vKey: simKey},
  {alg: 'A256KW', enc: 'A128CBC-HS256', eKey: simKey, vKey: simKey},
  {alg: 'A256KW', enc: 'A192CBC-HS384', eKey: simKey, vKey: simKey},
  {alg: 'A256KW', enc: 'A256CBC-HS512', eKey: simKey, vKey: simKey},
  {alg: 'A256KW', enc: 'A128GCM', eKey: simKey, vKey: simKey},
  {alg: 'A256KW', enc: 'A192GCM', eKey: simKey, vKey: simKey},
  {alg: 'A256KW', enc: 'A256GCM', eKey: simKey, vKey: simKey},
  {alg: 'PBES2-HS256+A128KW', enc: 'A128CBC-HS256', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS256+A128KW', enc: 'A192CBC-HS384', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS256+A128KW', enc: 'A256CBC-HS512', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS256+A128KW', enc: 'A128GCM', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS256+A128KW', enc: 'A192GCM', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS256+A128KW', enc: 'A256GCM', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS384+A192KW', enc: 'A128CBC-HS256', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS384+A192KW', enc: 'A192CBC-HS384', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS384+A192KW', enc: 'A256CBC-HS512', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS384+A192KW', enc: 'A128GCM', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS384+A192KW', enc: 'A192GCM', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS384+A192KW', enc: 'A256GCM', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS512+A256KW', enc: 'A128CBC-HS256', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS512+A256KW', enc: 'A192CBC-HS384', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS512+A256KW', enc: 'A256CBC-HS512', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS512+A256KW', enc: 'A128GCM', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS512+A256KW', enc: 'A192GCM', eKey: pwd, vKey: pwd},
  {alg: 'PBES2-HS512+A256KW', enc: 'A256GCM', eKey: pwd, vKey: pwd}
];

let start;
let delta;
let token;
let result;

console.log(`\nGENERATION OF ${ITER} TOKENS\n`);
for (let i in cases) {
  start = process.hrtime();
  for (let j = 0; j < ITER; j++) {
    token = jwt.generate(cases[i].alg, cases[i].enc, payload, cases[i].eKey);
  }
  delta = process.hrtime(start);
  console.log(`${cases[i].alg} / ${cases[i].enc} in ${formatResult(delta)}`);
}

console.log(`\nVERIFICATION OF ${ITER} TOKENS\n`);
for (let i in cases) {
  token = jwt.generate(cases[i].alg, cases[i].enc, payload, cases[i].eKey);
  start = process.hrtime();
  for (let j = 0; j < ITER; j++) {
    result = jwt.parse(token).setTokenLifetime(60000).verify(cases[i].vKey);
  }
  delta = process.hrtime(start);
  console.log(`${cases[i].alg} / ${cases[i].enc} in ${formatResult(delta)}`);
}

function formatResult(delta) {
  let ms = delta[0] * 1e3 + delta[1] * 1e-6;
  if (ms < 1000) {
    return `${ms.toFixed(1)} ms`;
  } else {
    return `${(ms / 1000).toFixed(3)} s`;
  }
}
