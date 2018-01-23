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
}

let token = jwt.generate('dir', 'A256CBC-HS512', payload, key);

testExpirationByIatSync(() => {
  testExpirationByIatAsync(() => {
    testExpirationByExpSync(() => {
      testExpirationByExpAsync(() => {
        console.log('\ndone');
      });
    });
  });
});

function testExpirationByIatSync(callback) {
  setTimeout(() => {
    let parsed = jwt.parse(token).setTokenLifetime(1).verify(key);
    if (parsed.expired && parsed.expired === parsed.payload.iat + 1) {
      console.log('\n[OK] Expiration by iat; synchronous verification API');
      callback();
    } else {
      console.log('\n[NOK] Expiration by iat; synchronous verification API');
      process.exit();
    }
  }, 1500);
}

function testExpirationByIatAsync(callback) {
  setTimeout(() => {
    jwt.parse(token).setTokenLifetime(2).verify(key, (error, parsed) => {
      if (parsed.expired && parsed.expired === parsed.payload.iat + 2) {
        console.log('[OK] Expiration by iat; asynchronous verification API');
        callback();
      } else {
        console.log('[NOK] Expiration by iat; asynchronous verification API');
        process.exit();
      }
    });
  }, 1500);
}

function testExpirationByExpSync(callback) {
  setTimeout(() => {
    let parsed = jwt.parse(token).setTokenLifetime(60).verify(key);
    if (parsed.expired && parsed.expired === parsed.payload.exp) {
      console.log('[OK] Expiration by exp; synchronous verification API');
      callback();
    } else {
      console.log('[NOK] Expiration by exp; synchronous verification API');
      process.exit();
    }
  }, 1500);
}

function testExpirationByExpAsync(callback) {
  payload.exp = Math.floor(Date.now() / 1000) + 1  // expires in 1 second
  token = jwt.generate('dir', 'A256CBC-HS512', payload, key);
  setTimeout(() => {
    jwt.parse(token).setTokenLifetime(60).verify(key, (error, parsed) => {
      if (parsed.expired && parsed.expired === parsed.payload.exp) {
        console.log('[OK] Expiration by exp; asynchronous verification API');
        callback();
      } else {
        console.log('[NOK] Expiration by exp; asynchronous verification API');
        process.exit();
      }
    });
  }, 1500);
}
