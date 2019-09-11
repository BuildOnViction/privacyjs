// TODO replace this module by third-party one, this is NATIVE LIB OF NODEJS, WOULD NOT RUN ON BROWSER
var crypto = require('crypto')
var ecurve = require('ecurve')

// hack to get bigi without including it as a dep
var ecparams = ecurve.getCurveByName('secp256k1')
var BigInteger = ecparams.n.constructor

function hash160(buffer) {
    buffer = crypto.createHash('sha256').update(buffer).digest()
    return crypto.createHash('rmd160').update(buffer).digest()
}

function hmacSha256(buffer) {
    return crypto.createHmac('sha256', new Buffer([])).update(buffer).digest()
}

function sha256x2(buffer) {
    buffer = crypto.createHash('sha256').update(buffer).digest()
    return crypto.createHash('sha256').update(buffer).digest()
}

/**
 * Random a hex string with size bytes, no prefix 0x, add it yourself if needed
 * @param {number} Number of bytes, notice a hex = 4 bit = 0.5 byte, a common private key (length 64) = 32 bytes
 * @param {function} Callback
 * @returns {string} Hex string without prefix 0x
 */
function randomHex (size, callback) {
    var crypto = require('crypto') || window.crypto;
    var isCallback = (typeof callback === 'function');


    if (size > 65536) {
        if (isCallback) {
            callback(new Error('Requested too many random bytes.'));
        } else {
            throw new Error('Requested too many random bytes.');
        }
    };

    // is node
    if (typeof crypto !== 'undefined' && crypto.randomBytes) {

        if (isCallback) {
            crypto.randomBytes(size, function (err, result) {
                if (!err) {
                    callback(null, result.toString('hex'));
                } else {
                    callback(error);
                }
            })
        } else {
            return crypto.randomBytes(size).toString('hex');
        }

        // is browser
    } else {
        var cryptoLib;

        if (typeof crypto !== 'undefined') {
            cryptoLib = crypto;
        } else if (typeof msCrypto !== 'undefined') {
            cryptoLib = msCrypto;
        }

        if (cryptoLib && cryptoLib.getRandomValues) {
            var randomBytes = cryptoLib.getRandomValues(new Uint8Array(size));
            var returnValue = Array.from(randomBytes).map(function (arr) { return arr.toString(16); }).join('');

            if (isCallback) {
                callback(null, returnValue);
            } else {
                return returnValue;
            }

            // not crypto object
        } else {
            var error = new Error('No "crypto" object available. This Browser doesn\'t support generating secure random bytes.');

            if (isCallback) {
                callback(error);
            } else {
                throw error;
            }
        }
    }
};

module.exports = {
    BigInteger: BigInteger,
    ecparams: ecparams,
    hash160: hash160,
    hmacSha256: hmacSha256,
    sha256x2: sha256x2,
    randomHex: randomHex
}
