const crypto = require('crypto');

// get password's md5 hash
const password = '674477dc75d9c69cbfaa087357792a508cae20d24c0dacf2c962da01d273ff32';
const passwordHash = crypto.createHash('md5').update(password, 'utf-8').digest('hex').toUpperCase();
console.log('key=', passwordHash); // 098F6BCD4621D373CADE4E832627B4F6

// our data to encrypt
const data = '12b688f3bd94e3ebbc688e0c8ba0f772c955b22ef3630553268caaefd0643523';
console.log('data=', data);

// generate initialization vector
const iv = new Buffer.alloc(16); // fill with zeros
console.log('iv=', iv);

// encrypt data
const cipher = crypto.createCipheriv('aes-256-cbc', passwordHash, iv);
const encryptedData = cipher.update(data, 'hex', 'hex') + cipher.final('hex');
console.log('encrypted data=', encryptedData.toUpperCase());
