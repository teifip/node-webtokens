const fs = require('fs');
const crypto = require('crypto');
const jwt = require('../index.js');
const buf2b64url = require('../lib/common.js').buf2b64url;

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

let token;
let validToken;
let parsed;
let key;

for (let test of tests) {
  console.log(`\n${test.alg}, ${test.enc}`);
  validToken = jwt.generate(test.alg, test.enc, payload, test.eKey);

  // no alg in header
  token = removeAlgFromHeader(validToken);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Missing or invalid alg claim in header')) {
    console.log(`[OK] missing alg claim`);
  } else {
    console.log(`[NOK] missing alg claim`);
    console.log(parsed);
    process.exit();
  }

  // unrecognized alg in header
  token = messupAlgInHeader(validToken);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Unrecognized key management algorithm')) {
    console.log(`[OK] unrecognized alg claim`);
  } else {
    console.log(`[NOK] unrecognized alg claim`);
    console.log(parsed);
    process.exit();
  }

  // unwanted alg in header
  parsed = jwt.parse(validToken)
              .setAlgorithmList(['dummy1', 'dummy2'], test.enc)
              .verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Unwanted key management algorithm')) {
    console.log(`[OK] unwanted alg claim`);
  } else {
    console.log(`[NOK] unwanted alg claim`);
    console.log(parsed);
    process.exit();
  }

  // no enc in header
  token = removeEncFromHeader(validToken);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Missing or invalid enc claim in header')) {
    console.log(`[OK] missing enc claim`);
  } else {
    console.log(`[NOK] missing enc claim`);
    console.log(parsed);
    process.exit();
  }

  // unrecognized enc in header
  token = messupEncInHeader(validToken);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Unrecognized content encryption algorithm')) {
    console.log(`[OK] unrecognized enc claim`);
  } else {
    console.log(`[NOK] unrecognized enc claim`);
    console.log(parsed);
    process.exit();
  }

  // unwanted enc in header
  parsed = jwt.parse(validToken)
              .setAlgorithmList(test.alg, ['dummy1', 'dummy2'])
              .verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Unwanted content encryption algorithm')) {
    console.log(`[OK] unwanted enc claim`);
  } else {
    console.log(`[NOK] unwanted enc claim`);
    console.log(parsed);
    process.exit();
  }

  // tampered header
  token = tamperHeader(validToken);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Could not decrypt token')) {
    console.log(`[OK] tampered header`);
  } else {
    console.log(`[NOK] tampered header`);
    console.log(parsed);
    process.exit();
  }

  // tampered payload
  token = tamperPayload(validToken);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Could not decrypt token')) {
    console.log(`[OK] tampered payload`);
  } else {
    console.log(`[NOK] tampered payload`);
    console.log(parsed);
    process.exit();
  }

  // tampered initialization vector
  token = tamperIv(validToken);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Could not decrypt token')) {
    console.log(`[OK] tampered initialization vector`);
  } else {
    console.log(`[NOK] tampered initialization vector`);
    console.log(parsed);
    process.exit();
  }

  // tampered authentication tag
  token = tamperTag(validToken);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Could not decrypt token')) {
    console.log(`[OK] tampered authentication tag`);
  } else {
    console.log(`[NOK] tampered authentication tag`);
    console.log(parsed);
    process.exit();
  }

  // check with wrong key
  key = messupVerificationKey(test.vKey);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Could not decrypt token')) {
    console.log(`[OK] wrong key`);
  } else {
    console.log(`[NOK] wrong key`);
    console.log(parsed);
    process.exit();
  }

  // check with invalid key type
  key = messupVerificationKeyType(test.vKey);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Could not decrypt token')) {
    console.log(`[OK] wrong key type`);
  } else {
    console.log(`[NOK] wrong key type`);
    console.log(parsed);
    process.exit();
  }

  // check with invalid key length
  key = messupVerificationKeyLength(test.vKey);
  parsed = jwt.parse(token).verify(test.vKey);
  if (parsed.error &&
      parsed.error.message.includes('Could not decrypt token')) {
    console.log(`[OK] wrong key length`);
  } else {
    console.log(`[NOK] wrong key length`);
    console.log(parsed);
    process.exit();
  }
}


function removeAlgFromHeader(token) {
  let parts = token.split('.');
  let header = JSON.parse(Buffer.from(parts[0], 'base64'));
  delete header.alg;
  let newHeader = Buffer.from(JSON.stringify(header)).toString('base64');
  parts[0] = buf2b64url(newHeader);
  return parts.join('.');
}

function messupAlgInHeader(token) {
  let parts = token.split('.');
  let header = JSON.parse(Buffer.from(parts[0], 'base64'));
  header.alg = 'dummy';
  let newHeader = Buffer.from(JSON.stringify(header)).toString('base64');
  parts[0] = buf2b64url(newHeader);
  return parts.join('.');
}

function removeEncFromHeader(token) {
  let parts = token.split('.');
  let header = JSON.parse(Buffer.from(parts[0], 'base64'));
  delete header.enc;
  let newHeader = Buffer.from(JSON.stringify(header)).toString('base64');
  parts[0] = buf2b64url(newHeader);
  return parts.join('.');
}

function messupEncInHeader(token) {
  let parts = token.split('.');
  let header = JSON.parse(Buffer.from(parts[0], 'base64'));
  header.enc = 'dummy';
  let newHeader = Buffer.from(JSON.stringify(header)).toString('base64');
  parts[0] = buf2b64url(newHeader);
  return parts.join('.');
}

function tamperHeader(token) {
  let parts = token.split('.');
  let header = JSON.parse(Buffer.from(parts[0], 'base64'));
  header.extra = 'dummy';
  let newHeader = Buffer.from(JSON.stringify(header)).toString('base64');
  parts[0] = buf2b64url(newHeader);
  return parts.join('.');
}

function tamperPayload(token) {
  let parts = token.split('.');
  parts[3] = parts[3].slice(0, -1);
  return parts.join('.');
}

function tamperIv(token) {
  let parts = token.split('.');
  parts[2] = parts[2].slice(0, -1);
  return parts.join('.');
}

function tamperTag(token) {
  let parts = token.split('.');
  parts[4] = parts[4].slice(1);
  return parts.join('.');
}

function messupVerificationKey(key) {
  let wrongKey = Buffer.from(key);
  wrongKey[0] ^= 1;
  return wrongKey;
}

function messupVerificationKeyType(key) {
  return Buffer.from(key).toString('hex');
}

function messupVerificationKeyLength(key) {
  let len = key.length;
  return key.slice(0, len / 2);
}
