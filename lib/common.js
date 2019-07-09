exports.buf2b64url = (data) => {
  return data.toString('base64')
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

exports.payloadVerifications = (parsed, cb) => {
  if (parsed.audList) {
    if (parsed.payload.aud === undefined) {
      parsed.error = { message: 'Missing aud claim in payload' };
      return responder(null, parsed, cb);
    } else if (!parsed.audList.includes(parsed.payload.aud)) {
      parsed.error = { message: 'Mismatching aud claim in payload' };
      return responder(null, parsed, cb);
    }
  }
  if (parsed.issList) {
    if (parsed.payload.iss === undefined) {
      parsed.error = { message: 'Missing iss claim in payload' };
      return responder(null, parsed, cb);
    } else if (!parsed.issList.includes(parsed.payload.iss)) {
      parsed.error = { message: 'Mismatching iss claim in payload' };
      return responder(null, parsed, cb);
    }
  }
  let iat = Number(parsed.payload.iat);
  if (!iat) {
    parsed.error = { message: 'Missing or invalid iat claim in payload' };
    return responder(null, parsed, cb);
  }
  let expiration = Number(parsed.payload.exp);
  if (parsed.lifetime) {
    let iatExp = iat + parsed.lifetime;
    if (!expiration || iatExp < expiration) expiration = iatExp;
  }
  if (expiration && Date.now() > expiration * 1000) {
    parsed.expired = expiration;
    return responder(null, parsed, cb);
  }
  parsed.valid = true;
  return responder(null, parsed, cb);
}
