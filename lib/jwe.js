const crypto = require('crypto');
const { responder, buf2b64url, payloadVerifications } = require('./common.js');

const ALG_RE = /^(PBES2-HS(256|384|512)\053)?(RSA-OAEP|dir|A(128|192|256)KW)$/;
const ENC_RE = /^A(128|192|256)(GCM|CBC-HS(256|384|512))$/;

// ===== JWE GENERATION =======================================================

exports.generate = (alg, enc, payload, ...rest) => {
  // alg, enc, payload, key[, cb] or alg, enc, payload, keystore, kid[, cb]
  let key;
  let cb;
  let header = { alg: alg, enc: enc };
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
  let aMatch = typeof alg === 'string' ? alg.match(ALG_RE) : null;
  if (!aMatch || (aMatch[2] && +aMatch[2] !== aMatch[4] * 2)) {
    let error = new TypeError('Unrecognized key management algorithm');
    return responder(error, null, cb);
  }
  let eMatch = typeof enc === 'string' ? enc.match(ENC_RE) : null;
  if (!eMatch || (eMatch[3] && +eMatch[3] !== eMatch[1] * 2)) {
    let error = new TypeError('Unrecognized content encryption algorithm');
    return responder(error, null, cb);
  }
  let salt;
  if (aMatch[2]) {
    let p2s = crypto.randomBytes(16);
    header.p2c = 1024;
    header.p2s = buf2b64url(p2s);
    salt = Buffer.concat([Buffer.from(alg), Buffer.from([0]), p2s]);
    if (!cb) {
      let bits = Number(aMatch[2]);
      key = crypto.pbkdf2Sync(key, salt, header.p2c, bits >> 4, `sha${bits}`);
    }
  }
  let aad = buf2b64url(Buffer.from(JSON.stringify(header)));
  if (!aMatch[2] || !cb) {
    return generateJwe(aMatch, eMatch, aad, payload, key, cb);
  }
  let bits = Number(aMatch[2]);
  crypto.pbkdf2(key, salt, header.p2c, bits >> 4, `sha${bits}`, (err, key) => {
    if (err) return cb(err);
    generateJwe(aMatch, eMatch, aad, payload, key, cb);
  });
}

function generateJwe(aMatch, eMatch, aad, payload, key, cb) {
  let cekLen = eMatch[3] ? +eMatch[1] >> 2 : +eMatch[1] >> 3;
  let contEncr = eMatch[3] ? contentEncryptCbc : contentEncryptGcm;
  let cek;
  let cekEnc;
  if (aMatch[0] !== 'dir') {
    cek = crypto.randomBytes(cekLen);
    let keyEncr = aMatch[4] ? aesKeyWrap : rsaOaepEncrypt;
    try {
      cekEnc = keyEncr(cek, key, +aMatch[4]);
    } catch (error) {
      return responder(error, null, cb);
    }
  } else {
    // Key must be directly used for content encryption
    if (typeof key === 'string') {
      key = Buffer.from(key, 'base64');
    } else if (!(key instanceof Buffer)) {
      let error = new TypeError('Key must be a buffer or a base64 string');
      return responder(error, null, cb);
    }
    if (key.length < cekLen) {
      let error = new TypeError(`Key must be at least ${cekLen} bytes`);
      return responder(error, null, cb);
    }
    cek = key.slice(0, cekLen);
    cekEnc = '';
  }
  payload.iat = Math.floor(Date.now() / 1000);
  let token = contEncr(aad, cek, cekEnc, JSON.stringify(payload), +eMatch[1]);
  return responder(null, token, cb);
}

// ===== JWE VERIFICATION =====================================================

exports.verify = (parsed, key, cb) => {
  if (parsed.error) return responder(null, parsed, cb);
  if (typeof parsed.header.alg !== 'string') {
    parsed.error = { message: 'Missing or invalid alg claim in header' };
    return responder(null, parsed, cb);
  }
  if (typeof parsed.header.enc !== 'string') {
    parsed.error = { message: 'Missing or invalid enc claim in header' };
    return responder(null, parsed, cb);
  }
  let aMatch = parsed.header.alg.match(ALG_RE);
  if (!aMatch || (aMatch[2] && +aMatch[2] !== aMatch[4] * 2)) {
    parsed.error = {
      message: `Unrecognized key management algorithm ${parsed.header.alg}`
    };
    return responder(null, parsed, cb);
  }
  if (parsed.algList && !parsed.algList.includes(parsed.header.alg)) {
    parsed.error = {
      message: `Unwanted key management algorithm ${parsed.header.alg}`
    };
    return responder(null, parsed, cb);
  }
  let eMatch = parsed.header.enc.match(ENC_RE);
  if (!eMatch || (eMatch[3] && +eMatch[3] !== eMatch[1] * 2)) {
    parsed.error = {
      message: `Unrecognized content encryption algorithm ${parsed.header.enc}`
    };
    return responder(null, parsed, cb);
  }
  if (parsed.encList && !parsed.encList.includes(parsed.header.enc)) {
    parsed.error = {
      message: `Unwanted content encryption algorithm ${parsed.header.enc}`
    };
    return responder(null, parsed, cb);
  }
  let salt;
  let iter;
  if (aMatch[2]) {
    iter = parsed.header.p2c;
    if (!Number.isInteger(iter) || iter < 1 || iter > 16384) {
      parsed.error = { message: 'Missing or invalid p2c claim in header' };
      return responder(null, parsed, cb);
    } else if (!cb && iter > 1024) {
      parsed.error = { message: 'p2c value too large for synchronous mode' };
      return responder(null, parsed, cb);
    }
    if (typeof parsed.header.p2s !== 'string') {
      parsed.error = { message: 'Missing or invalid p2s claim in header' };
      return responder(null, parsed, cb);
    }
    let p2s = Buffer.from(parsed.header.p2s, 'base64');
    let alg = parsed.header.alg;
    salt = Buffer.concat([Buffer.from(alg), Buffer.from([0]), p2s]);
    if (!cb) {
      let bits = Number(aMatch[2]);
      key = crypto.pbkdf2Sync(key, salt, iter, bits >> 4, `sha${bits}`);
    }
  }
  if (!aMatch[2] || !cb) {
    return decryptJwe(parsed, aMatch, eMatch, key, cb);
  }
  let bits = Number(aMatch[2]);
  crypto.pbkdf2(key, salt, iter, bits >> 4, `sha${bits}`, (error, key) => {
    if (error) return cb(error);
    decryptJwe(parsed, aMatch, eMatch, key, cb);
  });
}

function decryptJwe(parsed, aMatch, eMatch, key, cb) {
  let aad = Buffer.from(parsed.parts[0]);
  let cekEnc = Buffer.from(parsed.parts[1], 'base64');
  let iv = Buffer.from(parsed.parts[2], 'base64');
  let content = Buffer.from(parsed.parts[3], 'base64');
  let tag = Buffer.from(parsed.parts[4], 'base64');
  let cekLen = eMatch[3] ? +eMatch[1] >> 2 : +eMatch[1] >> 3;
  let contDecr = eMatch[3] ? contentDecryptCbc : contentDecryptGcm;
  let cek;
  if (aMatch[0] !== 'dir') {
    let keyDecr = aMatch[4] ? aesKeyUnwrap : rsaOaepDecrypt;
    try {
      cek = keyDecr(cekEnc, key, +aMatch[4]);
    } catch (error) {
      parsed.error = { message: `Could not decrypt token. ${error.message}` };
      return responder(null, parsed, cb);
    }
  } else {
    // Key must be directly used for content decryption
    if (typeof key === 'string') {
      key = Buffer.from(key, 'base64');
    } else if (!(key instanceof Buffer)) {
      parsed.error = { message: 'Invalid key' };
      return responder(null, parsed, cb);
    }
    if (key.length < cekLen) {
      parsed.error = {
        message: `Invalid key length. Must be at least ${cekLen} bytes`
      };
      return responder(null, parsed, cb);
    }
    cek = key.slice(0, cekLen);
  }
  let plain;
  try {
    plain = contDecr(content, aad, tag, cek, iv, +eMatch[1]);
  } catch (error) {
    parsed.error = { message: `Could not decrypt token. ${error.message}` };
    return responder(null, parsed, cb);
  }
  try {
    parsed.payload = JSON.parse(plain);
  } catch (error) {
    parsed.error = { message: `Non parsable payload. ${error.message}` };
    return responder(null, parsed, cb);
  }
  return payloadVerifications(parsed, cb);
}

// ===== A128GCM, A192GCM, A256GCM ============================================

function contentEncryptGcm(aad, cek, cekEnc, plain, bits) {
  let iv = crypto.randomBytes(12);
  let cipher = crypto.createCipheriv(`id-aes${bits}-GCM`, cek, iv);
  cipher.setAutoPadding(false);
  cipher.setAAD(Buffer.from(aad));
  let enc = buf2b64url(Buffer.concat([cipher.update(plain), cipher.final()]));
  let tag = buf2b64url(cipher.getAuthTag());
  return `${aad}.${cekEnc}.${buf2b64url(iv)}.${enc}.${tag}`;
}

function contentDecryptGcm(content, aad, tag, cek, iv, bits) {
  let decipher = crypto.createDecipheriv(`id-aes${bits}-GCM`, cek, iv);
  decipher.setAutoPadding(false);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(content), decipher.final()]);
}

// ===== A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 ==========================

function contentEncryptCbc(aad, cek, cekEnc, plain, bits) {
  let iv = crypto.randomBytes(16);
  let bytes = bits >> 3;
  let cipher = crypto.createCipheriv(`AES-${bits}-CBC`, cek.slice(bytes), iv);
  let enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  let len = aad.length << 3;
  let al = Buffer.from(`000000000000000${len.toString(16)}`.slice(-16), 'hex');
  let hmac = crypto.createHmac(`SHA${bits << 1}`, cek.slice(0, bytes));
  hmac.update(Buffer.from(aad)).update(iv).update(enc).update(al);
  let tag = buf2b64url(hmac.digest().slice(0, bytes));
  return `${aad}.${cekEnc}.${buf2b64url(iv)}.${buf2b64url(enc)}.${tag}`;
}

function contentDecryptCbc(content, aad, tag, cek, iv, bits) {
  let bytes = bits >> 3;
  let len = aad.length << 3;
  let al = Buffer.from(`000000000000000${len.toString(16)}`.slice(-16), 'hex');
  let hmac = crypto.createHmac(`SHA${bits << 1}`, cek.slice(0, bytes));
  hmac.update(aad).update(iv).update(content).update(al);
  if (!crypto.timingSafeEqual(hmac.digest().slice(0, bytes), tag)) {
    throw new Error('Authentication of encrypted data failed');
  }
  let encKey = cek.slice(bytes);
  let decipher = crypto.createDecipheriv(`AES-${bits}-CBC`, encKey, iv);
  return Buffer.concat([decipher.update(content), decipher.final()]);
}

// ===== RSA-OAEP =============================================================

function rsaOaepEncrypt(cek, key) {
  if (key instanceof Buffer) {
    key = key.toString();
  } else if (typeof key !== 'string') {
    throw new TypeError('Key must be a buffer or a string');
  }
  if (!key.includes('-----BEGIN') ||
      !(key.includes('KEY-----') || key.includes('CERTIFICATE-----'))) {
    throw new TypeError('Key must be a PEM formatted RSA public key');
  }
  let options = {key: key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING};
  return buf2b64url(crypto.publicEncrypt(options, cek));
}

function rsaOaepDecrypt(cekEnc, key) {
  if (key instanceof Buffer) {
    key = key.toString();
  }
  if (typeof key !== 'string' ||
      !key.includes('-----BEGIN') || !key.includes('KEY-----')) {
    throw new TypeError('Key must be a PEM formatted RSA private key');
  }
  let options = {key: key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING};
  return crypto.privateDecrypt(options, cekEnc);
}

// ===== A128KW, A192KW, A256KW ===============================================

function aesKeyWrap(cek, key, bits) {
  let bytes = bits >> 3;
  if (typeof key === 'string') {
    key = Buffer.from(key, 'base64');
  } else if (!(key instanceof Buffer)) {
    throw new TypeError('Key must be a buffer or a base64-encoded string');
  }
  if (key.length < bytes) {
    throw new TypeError(`Key length must be at least ${bytes} bytes`);
  }
  key = key.slice(0, bytes);
  let r = [];
  for (let i = 0; i < cek.length; i += 8) {
    r.push(cek.slice(i, i + 8));
  }
  let iv = Buffer.alloc(16);
  let a = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
  let count = 1;
  for (let j = 0; j < 6; j++) {
    for (let i = 0; i < r.length; i++) {
      let cipher = crypto.createCipheriv(`AES${bits}`, key, iv);
      let c = `000000000000000${count.toString(16)}`.slice(-16);
      let b = cipher.update(Buffer.concat([a, r[i]]));
      a = Buffer.from(c, 'hex');
      for (let n = 0; n < 8; n++) {
        a[n] ^= b[n];
      }
      r[i] = b.slice(8, 16);
      count++;
    }
  }
  return buf2b64url(Buffer.concat([a].concat(r)));
}

function aesKeyUnwrap(cekEnc, key, bits) {
  let bytes = bits >> 3;
  if (typeof key === 'string') {
    key = Buffer.from(key, 'base64');
  } else if (!(key instanceof Buffer)) {
    throw new TypeError('Key must be a buffer or a base64 string');
  }
  if (key.length < bytes) {
    throw new TypeError(`Key must be at least ${bytes} bytes`);
  }
  key = key.slice(0, bytes);
  let a = cekEnc.slice(0, 8);
  let r = [];
  for (let i = 8; i < cekEnc.length; i += 8) {
    r.push(cekEnc.slice(i, i + 8));
  }
  let z = Buffer.alloc(16);
  let count = 6 * r.length;
  for (let j = 5; j >= 0 ; j--) {
    for (let i = r.length - 1; i >= 0; i--) {
      let c = `000000000000000${count.toString(16)}`.slice(-16);
      c = Buffer.from(c, 'hex');
      for (let n = 0; n < 8; n++) {
        a[n] ^= c[n];
      }
      let decipher = crypto.createDecipheriv(`AES${bits}`, key, z);
      let b = decipher.update(Buffer.concat([a, r[i], z]));
      a = b.slice(0, 8);
      r[i] = b.slice(8, 16);
      count--;
    }
  }
  if (!a.equals(Buffer.from('A6A6A6A6A6A6A6A6', 'hex'))) {
    throw new Error('Key unwrapping failed');
  }
  return Buffer.concat(r);
}
