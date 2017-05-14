const fs = require('fs');
const crypto = require('crypto');
const jwt = require('../index.js');

const KEYS_DIR = __dirname + '/pem_keys/';

try {
  var jws = require('jws');
} catch (error) {
  console.log('\nThis test requires installation of the jws package');
  console.log('\n$ npm install jws\n');
  process.exit();
}

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

var token;
var parsed;
var result;

console.log('\nGENERATION WITH node-webtokens / VERIFICATION WITH jws\n');
for (let i in cases) {
  token = jwt.generate(cases[i].alg, payload, cases[i].sKey);
  parsed = jws.decode(token);
  if(jws.verify(token, parsed.header.alg, cases[i].vKey)) {
    console.log(`[OK] ${cases[i].alg}`);
  } else {
    console.log(`[NOK] ${cases[i].alg}`);
    process.exit();
  }
}

console.log('\nGENERATION WITH jws / VERIFICATION WITH node-webtokens\n');
for (let i in cases) {
  payload.iat = Date.now();
  token = jws.sign({
    header: {alg: cases[i].alg},
    payload: payload,
    secret: cases[i].sKey
  });
  result = jwt.parse(token).verify(cases[i].vKey);
  if (result.error) {
    console.log(`[NOK] ${cases[i].alg}`);
    process.exit();
  } else {
    console.log(`[OK] ${cases[i].alg}`);
  }
}