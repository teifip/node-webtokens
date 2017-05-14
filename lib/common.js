exports.buf2b64url = function(buf) {
  return buf.toString('base64')
            .replace(/\+/g, '-')
	          .replace(/\//g, '_')
						.replace(/=/g, '');
}

function responder(error, result, callback) {
  if (callback) {
    callback(error, result);
  } else if (error) {
    throw error;
  } else {
    return result;
  }
}

exports.responder = responder;

exports.payloadVerifications = function(parsed, cb) {
  if (parsed.audList) {
    if (!parsed.payload.aud) {
      parsed.error = { message: 'Missing aud claim in payload' };
      return responder(null, parsed, cb);
    } else if (parsed.audList.indexOf(parsed.payload.aud) === -1) {
      parsed.error = { message: 'Mismatching aud claim in payload' };
      return responder(null, parsed, cb);
    }
  }
  if (parsed.issList) {
    if (!parsed.payload.iss) {
      parsed.error = { message: 'Missing iss claim in payload' };
      return responder(null, parsed, cb);
    } else if (parsed.issList.indexOf(parsed.payload.iss) === -1) {
      parsed.error = { message: 'Mismatching iss claim in payload' };
      return responder(null, parsed, cb);
    }
  }
  var iat = Number(parsed.payload.iat);
  if (!iat) {
    parsed.error = { message: 'Missing or invalid iat claim in payload' };
    return responder(null, parsed, cb);
  }
  var expiration = Number(parsed.payload.exp);
  if (parsed.lifetime) {
    var iatExp = iat + parsed.lifetime;
    if (!expiration || iatExp < expiration) {
      expiration = iatExp;
    }
  }
  if (expiration && Date.now() > expiration * 1000) {
    parsed.expired = expiration;
    return responder(null, parsed, cb);
  }
  parsed.valid = true;
  return responder(null, parsed, cb);
}