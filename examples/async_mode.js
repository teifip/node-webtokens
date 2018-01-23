const crypto = require('crypto');
const jwt = require('../index.js');

const key = crypto.randomBytes(64);

const payload = {
  iss: 'auth.mydomain.com',
  aud: 'A1B2C3D4E5.com.mydomain.myservice',
  sub: 'jack.sparrow@example.com',
  info: 'Hello World!',
  list: [1, 2, 3, 4]
}

console.log('\nTOKEN GENERATION WITH ASYNCHRONOUS API\n');

jwt.generate('PBES2-HS512+A256KW', 'A256GCM', payload, key, (error, token) => {
  console.log(token);

  console.log('\nTOKEN VERIFICATION WITH ASYNCHRONOUS API\n');

  jwt.parse(token).setTokenLifetime(600).verify(key, (error, parsed) => {
    console.log(parsed.valid);
    console.log(parsed.header);
    console.log(parsed.payload);
  });
});
