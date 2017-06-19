const crypto = require('crypto');
const jwt = require('../index.js');

const KEYS_DIR = __dirname + '/pem_keys/';

var key = crypto.randomBytes(64);

var payload = {
  sub: 'jack.sparrow@example.com',
  info: 'Hello World!',
  list: [1, 2, 3]
}

var token = jwt.generate('HS512', payload, key);

var parsed = jwt.parse(token)
                .setAudience('A1B2C3D4E5.com.mydomain.myservice')
                .verify(key);

if (parsed.error && parsed.error.message.includes('Missing aud claim')) {
  console.log('\n[OK] Missing aud enforced when setAudience is used');
} else {
  console.log('\n[NOK] Missing aud enforced when setAudience is used');
  process.exit();
}

parsed = jwt.parse(token)
            .setIssuer('auth.mydomain.com')
            .verify(key);

if (parsed.error && parsed.error.message.includes('Missing iss claim')) {
  console.log('[OK] Missing iss enforced when setIssuer is used');
} else {
  console.log('[NOK] Missing iss enforced when setIssuer is used');
  process.exit();
}

payload.iss = 'auth.mydomain.com';
payload.aud = 'A1B2C3D4E5.com.mydomain.myservice';

token = jwt.generate('HS512', payload, key);

parsed = jwt.parse(token)
            .setAudience('AABBCCDDEE.com.mydomain.myservice')
            .verify(key);

if (parsed.error && parsed.error.message.includes('Mismatching aud claim')) {
  console.log('[OK] Mismatching aud enforced when setAudience is used');
} else {
  console.log('[NOK] Mismatching aud enforced when setAudience is used');
  process.exit();
}

parsed = jwt.parse(token)
            .setAudience(['AABBCCDDEE.com.mydomain.myservice'])
            .verify(key);

if (parsed.error && parsed.error.message.includes('Mismatching aud claim')) {
  console.log('[OK] Mismatching aud enforced when setAudience is used');
} else {
  console.log('[NOK] Mismatching aud enforced when setAudience is used');
  process.exit();
}

parsed = jwt.parse(token)
            .setAudience([
              'A1B2C3D4E5.com.mydomain.myservice',
              'AABBCCDDEE.com.mydomain.myservice'])
            .verify(key);

if (!parsed.error) {
  console.log('[OK] Matching aud recognized when setAudience is used');
} else {
  console.log('[NOK] Matching aud recognized when setAudience is used');
  process.exit();
}

parsed = jwt.parse(token)
            .setIssuer('aaaa.mydomain.com')
            .verify(key);

if (parsed.error && parsed.error.message.includes('Mismatching iss claim')) {
  console.log('[OK] Mismatching iss enforced when setIssuer is used');
} else {
  console.log('[NOK] Mismatching iss enforced when setIssuer is used');
  process.exit();
}

parsed = jwt.parse(token)
            .setIssuer(['aaaa.mydomain.com'])
            .verify(key);

if (parsed.error && parsed.error.message.includes('Mismatching iss claim')) {
  console.log('[OK] Mismatching iss enforced when setIssuer is used');
} else {
  console.log('[NOK] Mismatching iss enforced when setIssuer is used');
  process.exit();
}

parsed = jwt.parse(token)
            .setIssuer(['auth.mydomain.com', 'aaaa.mydomain.com'])
            .verify(key);

if (!parsed.error) {
  console.log('[OK] Matching iss recognized when setIssuer is used');
} else {
  console.log('[NOK] Matching iss recognized when setIssuer is used');
  process.exit();
}
