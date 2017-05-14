const jws = require('./lib/jws.js');
const jwe = require('./lib/jwe.js');
const responder = require('./lib/common.js').responder;

// ===== TOKEN GENERATION =====================================================

exports.generate = function(alg, p1, p2, p3, p4, p5) {
  if (p1.constructor === {}.constructor) {
    // alg, payload, key[, cb] or alg, payload, keystore, kid[, cb]
    return jws.generate(alg, p1, p2, p3, p4);
  }
  if (p2.constructor === {}.constructor) {
    // alg, enc, payload, key[, cb] or alg, enc, payload, keystore, kid[, cb]
    return jwe.generate(alg, p1, p2, p3, p4, p5);
  }
  // there is no payload where expected
  var error = new TypeError('Invalid payload');
  if (typeof p5 === 'function') {
    p5(error);
  } else if (typeof p4 === 'function') {
    p4(error);
  } else if (typeof p3 === 'function') {
    p3(error);
  } else {
    throw error;
  }
}

// ===== TOKEN PARSING ========================================================

exports.parse = function(token) {
  return new ParsedToken(token);
}

function ParsedToken(token) {
	this.parts = [];
	if (typeof token === 'string') {
		this.parts = token.split('.');
	}
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
    // parsing exposes payload for JWS only; for JWE happens at verify
		try {
			this.payload = JSON.parse(Buffer.from(this.parts[1], 'base64'));
		} catch (error) {
	    this.error = { message: `Non parsable payload. ${error.message}` };
		}
	}
}

// ===== POST-PARSING UTLITIES ================================================

ParsedToken.prototype.setAlgorithmList = function(algList, encList) {
  // algList ignored if not string or array of strings
  if (typeof algList === 'string') {
    this.algList = [algList];
  } else if (Array.isArray(algList)) {
		this.algList = algList;
	}
  // encList ignored if not string or array of strings
  if (typeof encList === 'string') {
    this.encList = [encList];
  } else if (Array.isArray(encList)) {
		this.encList = encList;
	}
	return this;
}

ParsedToken.prototype.setTokenLifetime = function(lifetime) {
  // lifetime ignored if not integer greater than 0
  if (Number.isInteger(lifetime) && lifetime > 0) {
		this.lifetime = lifetime;
	}
  return this;
}

ParsedToken.prototype.setAudience = function(audList) {
  // audList ignored if not string or array of strings
  if (typeof audList === 'string') {
    this.audList = [audList];
  } else if (Array.isArray(audList)) {
		this.audList = audList;
	}
	return this;
}

ParsedToken.prototype.setIssuer = function(issList) {
  // issList ignored if not string or array of strings
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
  var key;
  if (p0.constructor !== {}.constructor) {
    key = p0;
  } else if (!this.header.kid) {
    // cannot extract key from keystore
    this.error = { message: 'Missing kid claim in header' }
    return responder(null, this, cb);
  } else if (!p0[this.header.kid]) {
    // key not found in keystore
    this.error = { message: 'Key with id not found', kid: this.header.kid };
    return responder(null, this, cb);
  } else {
    key = p0[this.header.kid];
  }
  return this.type === 'JWS'
         ? jws.verify(this, key, cb)
         : jwe.verify(this, key, cb);
}
