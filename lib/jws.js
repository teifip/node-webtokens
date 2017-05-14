const crypto = require('crypto');
const ecdsa = require('./ecdsa.js');
const responder = require('./common.js').responder;
const buf2b64url = require('./common.js').buf2b64url;
const payloadVerifications = require('./common.js').payloadVerifications;

const ALG_RE = /^(HS|RS|ES)(256|384|512)$/;

// ===== JWS GENERATION =======================================================

exports.generate = function(alg, payload, p2, p3, p4) {
	// alg, payload, key[, cb] or alg, payload, keystore, kid[, cb]
	var key;
	var cb;
	var header = { alg: alg };
	if (p2.constructor !== {}.constructor) {
		key = p2;
		cb = typeof p3 === 'function' ? p3 : undefined;
	} else {
		header.kid = p3;
		key = p2[p3];
		cb = typeof p4 === 'function' ? p4 : undefined;
		if (!key) {
			return responder(new TypeError('Invalid key identifier'), null, cb);
		}
	}
	var match;
	if (typeof alg === 'string') {
		match = alg.match(ALG_RE);
	}
	if (!match) {
		return responder(new TypeError('Unrecognized algorithm'), null, cb);
  }
	var generateJws;
	if (match[1] === 'HS') {
		generateJws = generateHsJws;
	} else if (match[1] === 'RS') {
    generateJws = generateRsJws;
	} else {
		generateJws = generateEsJws;
	}
	payload.iat = Math.floor(Date.now() / 1000);
	var h = buf2b64url(Buffer.from(JSON.stringify(header)));
	var p = buf2b64url(Buffer.from(JSON.stringify(payload)));
	try {
		var token = generateJws(`${h}.${p}`, +match[2], key);
	} catch (error) {
		return responder(error, null, cb);
	}
	return responder(null, token, cb);
}

// ===== JWS VERIFICATION =====================================================

exports.verify = function(parsed, key, cb) {
	if (parsed.error) {
		// invalid condition was detected during parsing
		return responder(null, parsed, cb);
	}
	if (typeof parsed.header.alg !== 'string') {
		parsed.error = { message: 'Missing or invalid alg claim in header' };
		return responder(null, parsed, cb);
	}
	var match = parsed.header.alg.match(ALG_RE);
	if (!match) {
		parsed.error = { message: `Unrecognized algorithm ${parsed.header.alg}` };
		return responder(null, parsed, cb);
  }
	if (parsed.algList && parsed.algList.indexOf(parsed.header.alg) === -1) {
		parsed.error = { message: `Unwanted algorithm ${parsed.header.alg}` };
		return responder(null, parsed, cb);
	}
	var protect = `${parsed.parts[0]}.${parsed.parts[1]}`;
	var verifyJws;
	if (match[1] === 'HS') {
		verifyJws = verifyHsJws;
	} else if (match[1] === 'RS') {
		verifyJws = verifyRsJws;
	} else {
		verifyJws = verifyEsJws;
	}
	try {
		var integrity = verifyJws(protect, parsed.parts[2], +match[2], key);
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
	var bytes = bits >> 3;
	if (key.length < bytes) {
		throw new TypeError(`Key length must be at least ${bytes} bytes`);
	}
	var hmac = crypto.createHmac(`SHA${bits}`, key);
	var mac = buf2b64url(hmac.update(protect).digest());
	return `${protect}.${mac}`;
}

function verifyHsJws(protect, mac, bits, key) {
	if (typeof key === 'string') {
		key = Buffer.from(key, 'base64');
	} else if (!(key instanceof Buffer)) {
		throw new TypeError('Key must be a buffer or a base64 string');
	}
	var bytes = bits >> 3;
	if (key.length < bytes) {
		throw new TypeError(`Key length must be at least ${bytes} bytes`);
	}
	var hmac = crypto.createHmac(`SHA${bits}`, key);
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
	if (key.indexOf('RSA PRIVATE KEY') === -1) {
		throw new TypeError('Key must be a PEM formatted RSA private key');
	}
	var signer = crypto.createSign(`SHA${bits}`);
  var signature = buf2b64url(signer.update(protect).sign(key));
	return `${protect}.${signature}`;
}

function verifyRsJws(protect, signature, bits, key) {
	if (key instanceof Buffer) {
		key = key.toString();
	} else if (typeof key !== 'string') {
		throw new TypeError('Key must be a buffer or a UTF-8 string');
	}
	if (key.indexOf('KEY') === -1) {
		throw new TypeError('Key must be a PEM formatted RSA public key');
	}
	var verifier = crypto.createVerify(`SHA${bits}`);
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
	if (key.indexOf('EC PRIVATE KEY') === -1) {
		throw new TypeError('Key must be a PEM formatted EC private key');
	}
	var signer = crypto.createSign(`SHA${bits}`);
  signer.update(protect);
  var size = 32;
	if (bits === 384) {
		size = 48;
	} else if (bits === 512) {
		size = 66;
	}
  var signature = buf2b64url(ecdsa.derToConcat(signer.sign(key), size));
	return `${protect}.${signature}`;
}

function verifyEsJws(protect, signature, bits, key) {
	if (key instanceof Buffer) {
		key = key.toString();
	} else if (typeof key !== 'string') {
		throw new TypeError('Key must be a buffer or a UTF-8 string');
	}
	if (key.indexOf('KEY') === -1) {
		throw new TypeError('Key must be a PEM formatted EC public key');
	}
	signature = Buffer.from(signature, 'base64');
	var size = 32;
	if (bits === 384) {
		size = 48;
	} else if (bits === 512) {
		size = 66;
	}
	if (signature.length !== 2 * size) {
		return false;
	}
	var verifier = crypto.createVerify(`SHA${bits}`);
	verifier.update(protect);
	return verifier.verify(key, ecdsa.concatToDer(signature, size));
}
