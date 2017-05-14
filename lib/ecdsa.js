const ERR_MSG = 'Could not extract parameters from DER signature';

exports.derToConcat = function(signature, size) {
	var offset = 0;
	if (signature[offset++] !== 0x30) {
		throw new Error(ERR_MSG);
	}
	var seqLength = signature[offset++];
	if (seqLength === 0x81) {
		seqLength = signature[offset++];
	}
	if (seqLength > signature.length - offset) {
		throw new Error(ERR_MSG);
	}
	if (signature[offset++] !== 0x02) {
		throw new Error(ERR_MSG);
	}
	var rLength = signature[offset++];
	if (rLength > signature.length - offset - 2) {
		throw new Error(ERR_MSG);
	}
	if (rLength > size + 1) {
		throw new Error(ERR_MSG);
	}
	var rOffset = offset;
	offset += rLength;
	if (signature[offset++] !== 0x02) {
		throw new Error(ERR_MSG);
	}
	var sLength = signature[offset++];
	if (sLength !== signature.length - offset) {
		throw new Error(ERR_MSG);
	}
	if (sLength > size + 1) {
		throw new Error(ERR_MSG);
	}
	var sOffset = offset;
	offset += sLength;
	if (offset !== signature.length) {
		throw new Error(ERR_MSG);
	}
	var rPadding = size - rLength;
	var sPadding = size - sLength;
	var dst = Buffer.allocUnsafe(rPadding + rLength + sPadding + sLength);
	for (offset = 0; offset < rPadding; ++offset) {
		dst[offset] = 0;
	}
	var rPad = Math.max(-rPadding, 0);
	signature.copy(dst, offset, rOffset + rPad, rOffset + rLength);
	offset = size;
	for (var o = offset; offset < o + sPadding; ++offset) {
		dst[offset] = 0;
	}
	var sPad = Math.max(-sPadding, 0);
	signature.copy(dst, offset, sOffset + sPad, sOffset + sLength);
	return dst;
}

exports.concatToDer = function(signature, size) {
	var rPadding = countPadding(signature, 0, size);
	var sPadding = countPadding(signature, size, signature.length);
	var rLength = size - rPadding;
	var sLength = size - sPadding;
	var rsBytes = rLength + sLength + 4;
	var shortLength = rsBytes < 0x80;
	var dst = Buffer.allocUnsafe((shortLength ? 2 : 3) + rsBytes);
	var offset = 0;
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
	var padding = 0;
	while (start + padding < stop && buf[start + padding] === 0) {
		++padding;
	}
	var needsSign = buf[start + padding] >= 0x80;
	if (needsSign) {
		--padding;
	}
	return padding;
}
