const fs = require('fs');
const crypto = require('crypto');
const jwt = require('../index.js');

const ITER = 1000;
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

var start;
var delta;
var token;
var result;

console.log(`\nGENERATION OF ${ITER} TOKENS\n`);
for (let i in cases) {
  start = process.hrtime();
  for (let j = 0; j < ITER; j++) {
    token = jwt.generate(cases[i].alg, payload, cases[i].sKey);
  }
  delta = process.hrtime(start);
  console.log(`${cases[i].alg} in ${formatResult(delta)}`);
}

console.log(`\nVERIFICATION OF ${ITER} TOKENS\n`);
for (let i in cases) {
  token = jwt.generate(cases[i].alg, payload, cases[i].sKey);
  start = process.hrtime();
  for (let j = 0; j < ITER; j++) {
    result = jwt.parse(token).setTokenLifetime(60000).verify(cases[i].vKey);
  }
  delta = process.hrtime(start);
  console.log(`${cases[i].alg} in ${formatResult(delta)}`);
}

function formatResult(delta) {
  var ms = delta[0] * 1e3 + delta[1] * 1e-6;
  if (ms < 1000) {
    return `${ms.toFixed(1)} ms`;
  } else {
    return `${(ms / 1000).toFixed(3)} s`;
  }
}
