const { keccak256 } = require('js-sha3');
const assert = require('assert');
const atob = require('atob') || window.atob;
const utf8 = require('utf8');
const BN = require('bignumber.js');
const isBoolean = require('lodash/isBoolean');
const isString = require('lodash/isString');
const isObject = require('lodash/isObject');
const isNull = require('lodash/isNull');

/**
 * hextobin converts string to Buffer
 * @param {string} hex Hex string wants to conver to buffer
 * @returns {Buffer} Buffer
 */
function hextobin(hex) {
    // assert(hex.length % 2 === 0, 'Hex string has invalid length!');
    const res = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length / 2; ++i) {
        res[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return res;
}

/**
 * bintohex converts Buffer to hex string
 * @param {Buffer} bin Buffer wants to conver to hex string
 * @returns {string} Hex string of input buffer
 */
function bintohex(bin) {
    const out = [];
    for (let i = 0; i < bin.length; ++i) {
        out.push((`0${bin[i].toString(16)}`).slice(-2));
    }
    return out.join('');
}

/**
 * validHex Test out the input hex is valid
 * @param {*} hex
 * @returns {boolean} true - is valid hex and false if not
 */
function validHex(hex) {
    const exp = new RegExp(`[0-9a-fA-F]{${hex.length}}`);
    return exp.test(hex);
}

/**
 * fastHash hashs a hex string using keccak256
 * @param {string} input Hex-string want to hash
 * @returns {string} keccak256 of input
 */atob
function fastHash(input) {
    return keccak256(input);
}

function base64tohex(base64) {
    var raw = atob(base64);
    var HEX = '';
    for (var i = 0; i < raw.length; i++) {
        var _hex = raw.charCodeAt(i).toString(16)
        HEX += (_hex.length == 2 ? _hex : '0' + _hex);
    }
    return HEX.toUpperCase();
}

/**
 * bconcat makes a buffer from a buffer list
 * @param {array} arr List Buffer want to concat
 * @returns {Buffer} concated buffer
 */
function bconcat (arr) {
    arr = arr.map(function (item) {
      return Buffer.isBuffer(item) ? item : new Buffer([item])
    });
    return Buffer.concat(arr)
}

/**
 * Should be called to get utf8 from it's hex representation
 *
 * @method hexToUtf8
 *
 * @param {String} hex
 *
 * @returns {String} ascii string representation of hex value
 */
const hexToUtf8 = (hex) => {
    if (!isHexStrict(hex)) throw new Error(`The parameter "${hex}" must be a valid HEX string.`);

    let string = '';
    let code = 0;
    hex = hex.replace(/^0x/i, '');

    // remove 00 padding from either side
    hex = hex.replace(/^(?:00)*/, '');
    hex = hex
        .split('')
        .reverse()
        .join('');
    hex = hex.replace(/^(?:00)*/, '');
    hex = hex
        .split('')
        .reverse()
        .join('');

    const l = hex.length;

    for (let i = 0; i < l; i += 2) {
        code = parseInt(hex.substr(i, 2), 16);
        // if (code !== 0) {
        string += String.fromCharCode(code);
        // }
    }

    return utf8.decode(string);
};

/**
 * Converts value to it's number representation
 *
 * @method hexToNumber
 *
 * @param {String|Number|BN} value
 *
 * @returns {Number}
 */
const hexToNumber = (value) => {
    if (!value) {
        return value;
    }

    return toBN(value).toNumber();
};

/**
 * Converts value to it's decimal representation in string
 *
 * @method hexToNumberString
 *
 * @param {String|Number|BN} value
 *
 * @returns {String}
 */
const hexToNumberString = (value) => {
    if (!value) return value;

    if (isString(value)) {
        if (!isHexStrict(value)) throw new Error(`Given value "${value}" is not a valid hex string.`);
    }

    return BN(value).toString(10);
};

/**
 * Converts value to it's hex representation
 *
 * @method numberToHex
 *
 * @param {String|Number|BN} value
 *
 * @returns {String}
 */
const numberToHex = (value) => {
    if (isNull(value) || typeof value === 'undefined') {
        return value;
    }

    if (!isFinite(value) && !isHexStrict(value)) {
        throw new Error(`Given input "${value}" is not a number.`);
    }

    const number = toBN(value);
    const result = number.toString(16);

    return number.lt(new BN(0)) ? `-0x${result.substr(1)}` : `0x${result}`;
};

/**
 * Convert a byte array to a hex string
 *
 * Note: Implementation from crypto-js
 *
 * @method bytesToHex
 *
 * @param {Array} bytes
 *
 * @returns {String} the hex string
 */
const bytesToHex = (bytes) => {
    let hex = [];

    for (let i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xf).toString(16));
    }

    return `0x${hex.join('').replace(/^0+/, '')}`;
};

/**
 * Convert a hex string to a byte array
 *
 * Note: Implementation from crypto-js
 *
 * @method hexToBytes
 *
 * @param {String} hex
 *
 * @returns {Array} the byte array
 */
const hexToBytes = (hex) => {
    hex = hex.toString(16);

    if (!isHexStrict(hex)) {
        throw new Error(`Given value "${hex}" is not a valid hex string.`);
    }

    hex = hex.replace(/^0x/i, '');
    hex = hex.length % 2 ? '0' + hex : hex;

    let bytes = [];
    for (let c = 0; c < hex.length; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }

    return bytes;
};

/**
 * Auto converts any given value into it's hex representation.
 * And even stringifys objects before.
 *
 * @method toHex
 *
 * @param {String|Number|BN|Object} value
 * @param {Boolean} returnType
 *
 * @returns {String}
 */
const toHex = (value, returnType) => {
    if (isAddress(value)) {
        return returnType ? 'address' : `0x${value.toLowerCase().replace(/^0x/i, '')}`;
    }

    if (isBoolean(value)) {
        return returnType ? 'bool' : value ? '0x01' : '0x00';
    }

    if (isObject(value) && !isBigNumber(value) && !isBN(value)) {
        return returnType ? 'string' : utf8ToHex(JSON.stringify(value));
    }

    // if its a negative number, pass it through numberToHex
    if (isString(value)) {
        if (value.indexOf('-0x') === 0 || value.indexOf('-0X') === 0) {
            return returnType ? 'int256' : numberToHex(value);
        } else if (value.indexOf('0x') === 0 || value.indexOf('0X') === 0) {
            return returnType ? 'bytes' : value;
        } else if (!isFinite(value)) {
            return returnType ? 'string' : utf8ToHex(value);
        }
    }

    return returnType ? (value < 0 ? 'int256' : 'uint256') : numberToHex(value);
};

/**
 * Takes an input and transforms it into an BN
 *
 * @method toBN
 *
 * @param {Number|String|BN} number, string, HEX string or BN
 *
 * @returns {BN} BN
 */
export const toBN = (number) => {
    try {
        return BN(number);
    } catch (error) {
        throw new Error(`${error} Given value: "${number}"`);
    }
};

/**
 * Check if string is HEX, requires a 0x in front
 *
 * @method isHexStrict
 *
 * @param {String} hex to be checked
 *
 * @returns {Boolean}
 */
export const isHexStrict = (hex) => {
    return true;
};

module.exports = {
    hextobin,
    bintohex,
    validHex,
    fastHash,
    base64tohex,
    bconcat,
    hexToUtf8,
    hexToNumber,
    hexToNumberString,
    numberToHex,
    bytesToHex,
    hexToBytes,
    toHex
};
