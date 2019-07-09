const ERR_MSG = 'Could not extract parameters from DER signature';

exports.derToConcat = (signature, size) => {
  let offset = 0;
  if (signature[offset++] !== 0x30) throw new Error(ERR_MSG);
  let seqLength = signature[offset++];
  if (seqLength === 0x81) seqLength = signature[offset++];
  if (seqLength > signature.length - offset || signature[offset++] !== 0x02) {
    throw new Error(ERR_MSG);
  }
  let rLength = signature[offset++];
  if (rLength > signature.length - offset - 2 || rLength > size + 1) {
    throw new Error(ERR_MSG);
  }
  let rOffset = offset;
  offset += rLength;
  if (signature[offset++] !== 0x02) throw new Error(ERR_MSG);
  let sLength = signature[offset++];
  if (sLength !== signature.length - offset || sLength > size + 1) {
    throw new Error(ERR_MSG);
  }
  let sOffset = offset;
  offset += sLength;
  if (offset !== signature.length) throw new Error(ERR_MSG);
  let rPadding = size - rLength;
  let sPadding = size - sLength;
  let dst = Buffer.allocUnsafe(rPadding + rLength + sPadding + sLength);
  for (offset = 0; offset < rPadding; offset++) dst[offset] = 0;
  let rPad = Math.max(-rPadding, 0);
  signature.copy(dst, offset, rOffset + rPad, rOffset + rLength);
  offset = size;
  for (let o = offset; offset < o + sPadding; offset++) dst[offset] = 0;
  let sPad = Math.max(-sPadding, 0);
  signature.copy(dst, offset, sOffset + sPad, sOffset + sLength);
  return dst;
}

exports.concatToDer = (signature, size) => {
  let rPadding = countPadding(signature, 0, size);
  let sPadding = countPadding(signature, size, signature.length);
  let rLength = size - rPadding;
  let sLength = size - sPadding;
  let rsBytes = rLength + sLength + 4;
  let shortLength = rsBytes < 0x80;
  let dst = Buffer.allocUnsafe((shortLength ? 2 : 3) + rsBytes);
  let offset = 0;
  dst[offset++] = 0x30;
  if (shortLength) {
    dst[offset++] = rsBytes;
  } else {
    dst[offset++] = 0x81;
    dst[offset++] = rsBytes & 0xFF;
  }
  dst[offset++] = 0x02;
  dst[offset++] = rLength;
  if (rPadding < 0) {
    dst[offset++] = 0;
    offset += signature.copy(dst, offset, 0, size);
  } else {
    offset += signature.copy(dst, offset, rPadding, size);
  }
  dst[offset++] = 0x02;
  dst[offset++] = sLength;
  if (sPadding < 0) {
    dst[offset++] = 0;
    signature.copy(dst, offset, size);
  } else {
    signature.copy(dst, offset, size + sPadding);
  }
  return dst;
}

function countPadding(buf, start, stop) {
  let padding = 0;
  while (start + padding < stop && buf[start + padding] === 0) padding++;
  let needsSign = buf[start + padding] >= 0x80;
  return needsSign ? --padding : padding;
}
