const crypto = require('crypto');
const jwt = require('../index.js');

const KEYS_DIR = __dirname + '/pem_keys/';

const key = crypto.randomBytes(64);

const payload = {
  iss: 'auth.mydomain.com',
  aud: 'A1B2C3D4E5.com.mydomain.myservice',
  sub: 'jack.sparrow@example.com',
  info: 'Hello World!',
  list: [1, 2, 3, 4],
  exp: Math.floor(Date.now() / 1000) + 4  // expires in 4 seconds
};

function pause(duration) {
  return new Promise((resolve) => {
    setTimeout(resolve, duration);
  });
}

function testExpirationByIatAsync(token) {
  return new Promise((resolve) => {
    jwt.parse(token).setTokenLifetime(2).verify(key, (error, parsed) => {
      if (parsed.expired && parsed.expired === parsed.payload.iat + 2) {
        console.log('[OK] Expiration by iat; asynchronous verification API');
        resolve();
      } else {
        console.log('[NOK] Expiration by iat; asynchronous verification API');
        process.exit();
      }
    });
  });
}

function testExpirationByExpAsync(token) {
  return new Promise((resolve) => {
    jwt.parse(token).setTokenLifetime(60).verify(key, (error, parsed) => {
      if (parsed.expired && parsed.expired === parsed.payload.exp) {
        console.log('[OK] Expiration by exp; asynchronous verification API');
        resolve();
      } else {
        console.log('[NOK] Expiration by exp; asynchronous verification API');
        process.exit();
      }
    });
  });
}

(async () => {
  let token = jwt.generate('HS512', payload, key);

  await pause(1500);
  let parsed = jwt.parse(token).setTokenLifetime(1).verify(key);
  if (parsed.expired && parsed.expired === parsed.payload.iat + 1) {
    console.log('\n[OK] Expiration by iat; synchronous verification API');
  } else {
    console.log('\n[NOK] Expiration by iat; synchronous verification API');
    process.exit();
  }

  await pause(1500);
  await testExpirationByIatAsync(token);

  await pause(1500);
  parsed = jwt.parse(token).setTokenLifetime(60).verify(key);
  if (parsed.expired && parsed.expired === parsed.payload.exp) {
    console.log('[OK] Expiration by exp; synchronous verification API');
  } else {
    console.log('[NOK] Expiration by exp; synchronous verification API');
    process.exit();
  }

  payload.exp = Math.floor(Date.now() / 1000) + 1  // expires in 1 second
  token = jwt.generate('HS512', payload, key);
  await pause(1500);
  await testExpirationByExpAsync(token);
  
})();
