const jws = require('./lib/jws.js');
const jwe = require('./lib/jwe.js');
const { responder } = require('./lib/common.js');

// ===== TOKEN GENERATION =====================================================

exports.generate = (alg, ...rest) => {
  // alg, payload, key[, cb] or alg, payload, keystore, kid[, cb]
  if (rest[0].constructor === Object) return jws.generate(alg, ...rest);
  // alg, enc, payload, key[, cb] or alg, enc, payload, keystore, kid[, cb]
  if (rest[1].constructor === Object) return jwe.generate(alg, ...rest);
  // There is no payload object where expected
  let idx = rest.length - 1;
  if (idx > 1 && idx < 5 && typeof rest[idx] === 'function') {
    rest[idx](error);
  } else {
    throw error;
  }
}

// ===== TOKEN PARSING ========================================================

exports.parse = (token) => new ParsedToken(token);

function ParsedToken(token) {
  this.parts = typeof token === 'string' ? token.split('.') : [];
  if (this.parts.length === 3) {
    this.type = 'JWS';
  } else if (this.parts.length === 5) {
    this.type = 'JWE';
  } else {
    this.error = { message: 'Invalid token' };
    return;
  }
  try {
    this.header = JSON.parse(Buffer.from(this.parts[0], 'base64'));
  } catch (error) {
    this.error = { message: `Non parsable header. ${error.message}` };
    return;
  }
  if (this.type === 'JWS') {
    // Parsing exposes payload for JWS only; for JWE happens at verify
    try {
      this.payload = JSON.parse(Buffer.from(this.parts[1], 'base64'));
    } catch (error) {
      this.error = { message: `Non parsable payload. ${error.message}` };
    }
  }
}

// ===== POST-PARSING UTLITIES ================================================

ParsedToken.prototype.setAlgorithmList = function(algList, encList) {
  // algList is ignored if not string or array of strings
  if (typeof algList === 'string') {
    this.algList = [algList];
  } else if (Array.isArray(algList)) {
    this.algList = algList;
  }
  // encList is ignored if not string or array of strings
  if (typeof encList === 'string') {
    this.encList = [encList];
  } else if (Array.isArray(encList)) {
    this.encList = encList;
  }
  return this;
}

ParsedToken.prototype.setTokenLifetime = function(lifetime) {
  // lifetime is ignored if not integer greater than 0
  if (Number.isInteger(lifetime) && lifetime > 0) this.lifetime = lifetime;
  return this;
}

ParsedToken.prototype.setAudience = function(audList) {
  // audList is ignored if not string or array of strings
  if (typeof audList === 'string') {
    this.audList = [audList];
  } else if (Array.isArray(audList)) {
    this.audList = audList;
  }
  return this;
}

ParsedToken.prototype.setIssuer = function(issList) {
  // issList is ignored if not string or array of strings
  if (typeof issList === 'string') {
    this.issList = [issList];
  } else if (Array.isArray(issList)) {
    this.issList = issList;
  }
  return this;
}

// ===== TOKEN VERIFICATION ===================================================

ParsedToken.prototype.verify = function(p0, cb) {
  // key[, cb] or keystore[, cb]
  cb = typeof cb === 'function' ? cb : undefined;
  if (this.error) return responder(null, this, cb);
  let key;
  if (p0.constructor !== Object) {
    key = p0;
  } else if (this.header.kid === undefined) {
    // Cannot extract key from keystore
    this.error = { message: 'Missing kid claim in header' };
    return responder(null, this, cb);
  } else if (p0[this.header.kid] === undefined) {
    // Key not found in keystore
    this.error = { message: 'Key with id not found', kid: this.header.kid };
    return responder(null, this, cb);
  } else {
    key = p0[this.header.kid];
  }
  let verify = this.type === 'JWS' ? jws.verify : jwe.verify;
  return verify(this, key, cb);
}
