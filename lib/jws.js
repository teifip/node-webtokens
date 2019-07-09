const crypto = require('crypto');
const ecdsa = require('./ecdsa.js');
const { responder, buf2b64url, payloadVerifications } = require('./common.js');

const ALG_RE = /^(HS|RS|ES)(256|384|512)$/;

// ===== JWS GENERATION =======================================================

exports.generate = (alg, payload, ...rest) => {
  // alg, payload, key[, cb] or alg, payload, keystore, kid[, cb]
  let key;
  let cb;
  let header = { alg: alg };
  if (rest[0].constructor !== Object) {
    key = rest[0];
    cb = typeof rest[1] === 'function' ? rest[1] : undefined;
  } else {
    header.kid = rest[1];
    key = rest[0][rest[1]];
    cb = typeof rest[2] === 'function' ? rest[2] : undefined;
    if (!key) {
      return responder(new TypeError('Invalid key identifier'), null, cb);
    }
  }
  let match = typeof alg === 'string' ? alg.match(ALG_RE) : null;
  if (!match) {
    return responder(new TypeError('Unrecognized algorithm'), null, cb);
  }
  let generateJws;
  if (match[1] === 'HS') {
    generateJws = generateHsJws;
  } else if (match[1] === 'RS') {
    generateJws = generateRsJws;
  } else {
    generateJws = generateEsJws;
  }
  payload.iat = Math.floor(Date.now() / 1000);
  let h = buf2b64url(Buffer.from(JSON.stringify(header)));
  let p = buf2b64url(Buffer.from(JSON.stringify(payload)));
  let token;
  try {
    token = generateJws(`${h}.${p}`, +match[2], key);
  } catch (error) {
    return responder(error, null, cb);
  }
  return responder(null, token, cb);
}

// ===== JWS VERIFICATION =====================================================

exports.verify = (parsed, key, cb) => {
  if (parsed.error) return responder(null, parsed, cb);
  if (typeof parsed.header.alg !== 'string') {
    parsed.error = { message: 'Missing or invalid alg claim in header' };
    return responder(null, parsed, cb);
  }
  let match = parsed.header.alg.match(ALG_RE);
  if (!match) {
    parsed.error = { message: `Unrecognized algorithm ${parsed.header.alg}` };
    return responder(null, parsed, cb);
  }
  if (parsed.algList && !parsed.algList.includes(parsed.header.alg)) {
    parsed.error = { message: `Unwanted algorithm ${parsed.header.alg}` };
    return responder(null, parsed, cb);
  }
  let protect = `${parsed.parts[0]}.${parsed.parts[1]}`;
  let verifyJws;
  if (match[1] === 'HS') {
    verifyJws = verifyHsJws;
  } else if (match[1] === 'RS') {
    verifyJws = verifyRsJws;
  } else {
    verifyJws = verifyEsJws;
  }
  let integrity;
  try {
    integrity = verifyJws(protect, parsed.parts[2], +match[2], key);
  } catch (error) {
    parsed.error = { message: `Could not verify integrity. ${error.message}` };
    return responder(null, parsed, cb);
  }
  if (!integrity) {
    parsed.error = { message: 'Integrity check failed' };
    return responder(null, parsed, cb);
  }
  return payloadVerifications(parsed, cb);
}

// ===== HS256, HS384, HS512 ==================================================

function generateHsJws(protect, bits, key) {
  if (typeof key === 'string') {
    key = Buffer.from(key, 'base64');
  } else if (!(key instanceof Buffer)) {
    throw new TypeError('Key must be a buffer or a base64 string');
  }
  let bytes = bits >> 3;
  if (key.length < bytes) {
    throw new TypeError(`Key length must be at least ${bytes} bytes`);
  }
  let hmac = crypto.createHmac(`SHA${bits}`, key);
  let mac = buf2b64url(hmac.update(protect).digest());
  return `${protect}.${mac}`;
}

function verifyHsJws(protect, mac, bits, key) {
  if (typeof key === 'string') {
    key = Buffer.from(key, 'base64');
  } else if (!(key instanceof Buffer)) {
    throw new TypeError('Key must be a buffer or a base64 string');
  }
  let bytes = bits >> 3;
  if (key.length < bytes) {
    throw new TypeError(`Key length must be at least ${bytes} bytes`);
  }
  let hmac = crypto.createHmac(`SHA${bits}`, key);
  hmac.update(protect);
  return crypto.timingSafeEqual(hmac.digest(), Buffer.from(mac, 'base64'));
}

// ===== RS256, RS384, RS512 ==================================================

function generateRsJws(protect, bits, key) {
  if (key instanceof Buffer) {
    key = key.toString();
  } else if (typeof key !== 'string') {
    throw new TypeError('Key must be a buffer or a UTF-8 string');
  }
  if (!key.includes('-----BEGIN') || !key.includes('KEY-----')) {
    throw new TypeError('Key must be a PEM formatted RSA private key');
  }
  let signer = crypto.createSign(`SHA${bits}`);
  let signature = buf2b64url(signer.update(protect).sign(key));
  return `${protect}.${signature}`;
}

function verifyRsJws(protect, signature, bits, key) {
  if (key instanceof Buffer) {
    key = key.toString();
  } else if (typeof key !== 'string') {
    throw new TypeError('Key must be a buffer or a UTF-8 string');
  }
  if (!key.includes('-----BEGIN') ||
      !(key.includes('KEY-----') || key.includes('CERTIFICATE-----'))) {
    throw new TypeError('Key must be a PEM formatted RSA public key');
  }
  let verifier = crypto.createVerify(`SHA${bits}`);
  verifier.update(protect);
  return verifier.verify(key, signature, 'base64');
}

// ===== ES256, ES384, ES512 ==================================================

function generateEsJws(protect, bits, key) {
  if (key instanceof Buffer) {
    key = key.toString();
  } else if (typeof key !== 'string') {
    throw new TypeError('Key must be a buffer or a UTF-8 string');
  }
  if (!key.includes('-----BEGIN') || !key.includes('KEY-----')) {
    throw new TypeError('Key must be a PEM formatted EC private key');
  }
  let signer = crypto.createSign(`SHA${bits}`);
  signer.update(protect);
  let size = 32;
  if (bits === 384) {
    size = 48;
  } else if (bits === 512) {
    size = 66;
  }
  let signature = buf2b64url(ecdsa.derToConcat(signer.sign(key), size));
  return `${protect}.${signature}`;
}

function verifyEsJws(protect, signature, bits, key) {
  if (key instanceof Buffer) {
    key = key.toString();
  } else if (typeof key !== 'string') {
    throw new TypeError('Key must be a buffer or a UTF-8 string');
  }
  if (!key.includes('-----BEGIN') ||
      !(key.includes('KEY-----') || key.includes('CERTIFICATE-----'))) {
    throw new TypeError('Key must be a PEM formatted EC public key');
  }
  signature = Buffer.from(signature, 'base64');
  let size = 32;
  if (bits === 384) {
    size = 48;
  } else if (bits === 512) {
    size = 66;
  }
  if (signature.length !== size << 1) {
    return false;
  }
  let verifier = crypto.createVerify(`SHA${bits}`);
  verifier.update(protect);
  return verifier.verify(key, ecdsa.concatToDer(signature, size));
}
