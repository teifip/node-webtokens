const fs = require('fs');
const crypto = require('crypto');
const jwt = require('../index.js');

const ITER = 1000;
const KEYS_DIR = __dirname + '/pem_keys/';

const simKey = crypto.randomBytes(64);
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
  {alg: 'HS256', sKey: simKey, vKey: simKey},
  {alg: 'HS384', sKey: simKey, vKey: simKey},
  {alg: 'HS512', sKey: simKey, vKey: simKey},
  {alg: 'RS256', sKey: priRsa, vKey: pubRsa},
  {alg: 'RS384', sKey: priRsa, vKey: pubRsa},
  {alg: 'RS512', sKey: priRsa, vKey: pubRsa},
  {alg: 'ES256', sKey: priEc256, vKey: pubEc256},
  {alg: 'ES384', sKey: priEc384, vKey: pubEc384},
  {alg: 'ES512', sKey: priEc521, vKey: pubEc521}
];

let start;
let delta;
let token;
let result;

console.log(`\nGENERATION OF ${ITER} TOKENS\n`);
for (let test of tests) {
  start = process.hrtime();
  for (let j = 0; j < ITER; j++) {
    token = jwt.generate(test.alg, payload, test.sKey);
  }
  delta = process.hrtime(start);
  console.log(`${test.alg} in ${formatResult(delta)}`);
}

console.log(`\nVERIFICATION OF ${ITER} TOKENS\n`);
for (let test of tests) {
  token = jwt.generate(test.alg, payload, test.sKey);
  start = process.hrtime();
  for (let j = 0; j < ITER; j++) {
    result = jwt.parse(token).setTokenLifetime(60).verify(test.vKey);
  }
  delta = process.hrtime(start);
  console.log(`${test.alg} in ${formatResult(delta)}`);
}

function formatResult(delta) {
  let ms = delta[0] * 1e3 + delta[1] * 1e-6;
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(3)} s`;
}
