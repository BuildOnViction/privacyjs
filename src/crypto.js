const crypto = require('crypto');
const ecurve = require('ecurve');
const EC = require('elliptic').ec;

const ec = new EC('secp256k1');

// hack to get bigi without including it as a dep
const ecparams = ecurve.getCurveByName('secp256k1');
export const BigInteger = ecparams.n.constructor;

export function hash160(buffer) {
    const sha256 = crypto.createHash('sha256').update(buffer).digest();
    return crypto.createHash('rmd160').update(sha256).digest();
}

export function hmacSha256(buffer) {
    return crypto.createHmac('sha256', new Buffer([])).update(buffer).digest();
}

export function sha256x2(buffer) {
    const sha256 = crypto.createHash('sha256').update(buffer).digest();
    return crypto.createHash('sha256').update(sha256).digest();
}

// export function aesEncrypt(data) {
//     const password = '<8{Qu;rnB3RnSq/*+<FGEsaff9&J/{$V^p5FkZ}`m,!eAB(&.H]auDJsW=64{PW@';
//     const passwordHash = crypto.createHash('md5').update(password, 'utf-8').digest('hex').toUpperCase();

//     const iv = crypto.randomBytes(16);

//     // encrypt data
//     const cipher = crypto.createCipheriv('aes-256-cbc', passwordHash, iv);
//     const encryptedData = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');

//     return encryptedData;
// }

// export function aesDecrypt(data) {
//     const password = '<8{Qu;rnB3RnSq/*+<FGEsaff9&J/{$V^p5FkZ}`m,!eAB(&.H]auDJsW=64{PW@';
//     const passwordHash = crypto.createHash('md5').update(password, 'utf-8').digest('hex').toUpperCase();

//     const iv = crypto.randomBytes(16);

//     // encrypt data
//     const cipher = crypto.createCipheriv('aes-256-cbc', passwordHash, iv);
//     const encryptedData = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');

//     return encryptedData;
// }

const algorithm = 'aes-256-cbc';
const _iv = '8*5g!aU(.[LUBQ_2';

export function aesEncrypt(plaintext, key) {
    const sha256sum = crypto.createHash('sha256');
    const _key = sha256sum.update(key).digest();
    console.log(_key);
    const cipher = crypto.createCipheriv(algorithm, _key, _iv);
    console.log('plaintext ', plaintext);
    const encrypted = cipher.update(plaintext, 'ascii', 'hex') + cipher.final('hex');

    console.log('encrypted ', encrypted);

    return encrypted;
}

export function aesDecrypt(encrypted, key) {
    // const sha256sum = crypto.createHash('sha256');
    // const _key = sha256sum.update(key).digest();
    const decipher = crypto.createDecipheriv(algorithm, key, _iv);
    const decrypted = decipher.update(encrypted, 'ascii', 'hex') + decipher.final('binary');

    console.log('decrypted ', decrypted);

    return decrypted;
}

/**
 * Random a hex string with size bytes, no prefix 0x, add it yourself if needed
 * a common private key (length 64) = 32 bytes
 * @returns {string} Hex string without prefix 0x
 */
export function randomHex() {
    const result = ec.genKeyPair().getPrivate().toString('hex');
    if (result.length % 2 === 1) {
        return '0' + result;
    }

    return result;
}
