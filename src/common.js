import { keccak256 as Hash } from 'js-sha3';
import numberToBN from 'number-to-bn';
import isBoolean from 'lodash/isBoolean';
import isString from 'lodash/isString';
import isNumber from 'lodash/isNumber';
import isObject from 'lodash/isObject';
import isNull from 'lodash/isNull';
import isFinite from 'lodash/isFinite';
import utf8 from 'utf8';
import BN from 'bn.js';

const atob = require('atob') || window.atob;
/**
 * hextobin converts string to Buffer
 * @param {string} hex Hex string wants to conver to buffer
 * @returns {Buffer} Buffer
 */
export const hextobin = (hex) => {
    // assert(hex.length % 2 === 0, 'Hex string has invalid length!');
    const res = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length / 2; ++i) {
        res[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return res;
};

/**
 * bintohex converts Buffer to hex string
 * @param {Buffer} bin Buffer wants to conver to hex string
 * @returns {string} Hex string of input buffer
 */
export const bintohex = (bin) => {
    const out = [];
    for (let i = 0; i < bin.length; ++i) {
        out.push((`0${bin[i].toString(16)}`).slice(-2));
    }
    return out.join('');
};

/**
 * validHex Test out the input hex is valid
 * @param {*} hex
 * @returns {boolean} true - is valid hex and false if not
 */
export const validHex = (hex) => {
    const exp = new RegExp(`[0-9a-fA-F]{${hex.length}}`);
    return exp.test(hex);
};

/**
 * fastHash hashs a hex string using keccak256
 * @param {string} input Hex-string want to hash
 * @returns {string} keccak256 of input
 */
export const fastHash = input => Hash(input);

export const base64tohex = (base64) => {
    const raw = atob(base64);
    let HEX = '';
    for (let i = 0; i < raw.length; i++) {
        const _hex = raw.charCodeAt(i).toString(16);
        HEX += (_hex.length === 2 ? _hex : `0${_hex}`);
    }
    return HEX.toUpperCase();
};

/**
 * bconcat makes a buffer from a buffer list
 * @param {array} arr List Buffer want to concat
 * @returns {Buffer} concated buffer
 */
export const bconcat = (arr) => {
    arr = arr.map(item => (Buffer.isBuffer(item) ? item : new Buffer([item])));
    return Buffer.concat(arr);
};

// Borrow the utils from Web3js - not needed all web3 package

/**
 * Returns true if object is BN, otherwise false
 *
 * @method isBN
 *
 * @param {Object} object
 *
 * @returns {Boolean}
 */
export const isBN = object => BN.isBN(object);

/**
 * Returns true if object is BigNumber, otherwise false
 *
 * @method isBigNumber
 *
 * @param {Object} object
 *
 * @returns {Boolean}
 */
export const isBigNumber = object => object && object.constructor && object.constructor.name === 'BigNumber';

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
        return numberToBN(number);
    } catch (error) {
        throw new Error(`${error} Given value: "${number}"`);
    }
};

/**
 * Takes and input transforms it into BN and if it is negative value, into two's complement
 *
 * @method toTwosComplement
 *
 * @param {Number|String|BN} number
 *
 * @returns {String}
 */
export const toTwosComplement = number => `0x${toBN(number)
    .toTwos(256)
    .toString(16, 64)}`;

/**
 * Checks if the given string is an address
 *
 * @method isAddress
 *
 * @param {String} address the given HEX address
 *
 * @param {Number} chainId to define checksum behavior
 *
 * @returns {Boolean}
 */
export const isAddress = (address, chainId = null) => {
    // check if it has the basic requirements of an address
    if (!/^(0x)?[0-9a-f]{40}$/i.test(address)) {
        return false;
        // If it's ALL lowercase or ALL upppercase
    } if (/^(0x|0X)?[0-9a-f]{40}$/.test(address) || /^(0x|0X)?[0-9A-F]{40}$/.test(address)) {
        return true;
        // Otherwise check each case
    }
    return checkAddressChecksum(address, chainId);
};

/**
 * Removes prefix from address if exists.
 *
 * @method stripHexPrefix
 *
 * @param {string} string
 *
 * @returns {string} address without prefix
 */
export const stripHexPrefix = string => (string.startsWith('0x') || string.startsWith('0X') ? string.slice(2) : string);

/**
 * Checks if the given string is a checksummed address
 *
 * @method checkAddressChecksum
 *
 * @param {String} address the given HEX address
 *
 * @param {number} chain where checksummed address should be valid.
 *
 * @returns {Boolean}
 */
export const checkAddressChecksum = (address, chainId = null) => {
    const stripAddress = stripHexPrefix(address).toLowerCase();
    const prefix = chainId != null ? `${chainId.toString()}0x` : '';
    const keccakHash = Hash(prefix + stripAddress)
        .toString('hex')
        .replace(/^0x/i, '');

    for (let i = 0; i < stripAddress.length; i++) {
        const output = parseInt(keccakHash[i], 16) >= 8 ? stripAddress[i].toUpperCase()
            : stripAddress[i];
        if (stripHexPrefix(address)[i] !== output) {
            return false;
        }
    }
    return true;
};

/**
 * Should be called to pad string to expected length
 *
 * @method leftPad
 *
 * @param {String} string to be padded
 * @param {Number} chars that result string should have
 * @param {String} sign, by default 0
 *
 * @returns {String} left aligned string
 */
export const leftPad = (string, chars, sign) => {
    const hasPrefix = /^0x/i.test(string) || typeof string === 'number';
    string = string.toString(16).replace(/^0x/i, '');

    const padding = chars - string.length + 1 >= 0 ? chars - string.length + 1 : 0;

    return (hasPrefix ? '0x' : '') + new Array(padding).join(sign || '0') + string;
};

/**
 * Should be called to pad string to expected length
 *
 * @method rightPad
 *
 * @param {String} string to be padded
 * @param {Number} chars that result string should have
 * @param {String} sign, by default 0
 *
 * @returns {String} right aligned string
 */
export const rightPad = (string, chars, sign) => {
    const hasPrefix = /^0x/i.test(string) || typeof string === 'number';
    string = string.toString(16).replace(/^0x/i, '');

    const padding = chars - string.length + 1 >= 0 ? chars - string.length + 1 : 0;

    return (hasPrefix ? '0x' : '') + string + new Array(padding).join(sign || '0');
};

/**
 * Should be called to get hex representation (prefixed by 0x) of utf8 string
 *
 * @method utf8ToHex
 *
 * @param {String} value
 *
 * @returns {String} hex representation of input string
 */
export const utf8ToHex = (value) => {
    value = utf8.encode(value);
    let hex = '';

    /* eslint-disable no-control-regex */
    // remove \u0000 padding from either side
    value = value.replace(/^(?:\u0000)*/, '');
    value = value
        .split('')
        .reverse()
        .join('');
    value = value.replace(/^(?:\u0000)*/, '');
    value = value
        .split('')
        .reverse()
        .join('');
    /* eslint-enable no-control-regex */

    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        // if (code !== 0) {
        const n = code.toString(16);
        hex += n.length < 2 ? `0${n}` : n;
        // }
    }

    return `0x${hex}`;
};

/**
 * Should be called to get utf8 from it's hex representation
 *
 * @method hexToUtf8
 *
 * @param {String} hex
 *
 * @returns {String} ascii string representation of hex value
 */
export const hexToUtf8 = (hex) => {
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
export const hexToNumber = (value) => {
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
export const hexToNumberString = (value) => {
    if (!value) return value;

    if (isString(value)) {
        if (!isHexStrict(value)) throw new Error(`Given value "${value}" is not a valid hex string.`);
    }

    return toBN(value).toString(10);
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
export const numberToHex = (value) => {
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
export const bytesToHex = (bytes) => {
    const hex = [];

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
export const hexToBytes = (hex) => {
    hex = hex.toString(16);

    if (!isHexStrict(hex)) {
        throw new Error(`Given value "${hex}" is not a valid hex string.`);
    }

    hex = hex.replace(/^0x/i, '');
    hex = hex.length % 2 ? `0${hex}` : hex;

    const bytes = [];
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
export const toHex = (value, returnType) => {
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
        } if (value.indexOf('0x') === 0 || value.indexOf('0X') === 0) {
            return returnType ? 'bytes' : value;
        } if (!isFinite(value)) {
            return returnType ? 'string' : utf8ToHex(value);
        }
    }

    return returnType ? (value < 0 ? 'int256' : 'uint256') : numberToHex(value);
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
export const isHexStrict = hex => (isString(hex) || isNumber(hex)) && /^(-)?0x[0-9a-f]*$/i.test(hex);

/**
 * Check if string is HEX
 *
 * @method isHex
 *
 * @param {String} hex to be checked
 *
 * @returns {Boolean}
 */
export const isHex = hex => (isString(hex) || isNumber(hex)) && /^(-0x|0x)?[0-9a-f]*$/i.test(hex);

/**
 * Returns true if given string is a valid Ethereum block header bloom.
 *
 * TODO UNDOCUMENTED
 *
 * @method isBloom
 *
 * @param {String} bloom encoded bloom filter
 *
 * @returns {Boolean}
 */
export const isBloom = (bloom) => {
    if (!/^(0x)?[0-9a-f]{512}$/i.test(bloom)) {
        return false;
    } if (/^(0x)?[0-9a-f]{512}$/.test(bloom) || /^(0x)?[0-9A-F]{512}$/.test(bloom)) {
        return true;
    }
    return false;
};

/**
 * Returns true if given string is a valid log topic.
 *
 * TODO UNDOCUMENTED
 *
 * @method isTopic
 *
 * @param {String} topic encoded topic
 *
 * @returns {Boolean}
 */
export const isTopic = (topic) => {
    if (!/^(0x)?[0-9a-f]{64}$/i.test(topic)) {
        return false;
    } if (/^(0x)?[0-9a-f]{64}$/.test(topic) || /^(0x)?[0-9A-F]{64}$/.test(topic)) {
        return true;
    }
    return false;
};

/**
 * Hashes values to a keccak256 hash using keccak 256
 *
 * To hash a HEX string the hex must have 0x in front.
 *
 * @method keccak256
 * @return {String} the keccak256 string
 */
const KECCAK256_NULL_S = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

export const keccak256 = (value) => {
    if (isHexStrict(value) && /^0x/i.test(value.toString())) {
        value = hexToBytes(value);
    }

    const returnValue = Hash(value); // jshint ignore:line

    if (returnValue === KECCAK256_NULL_S) {
        return null;
    }
    return returnValue;
};
// expose the under the hood keccak256
keccak256._Hash = Hash;

/**
 * Gets the r,s,v values from a signature
 *
 * @method getSignatureParameters
 *
 * @param {String} ECDSA signature
 *
 * @return {Object} with r,s,v values
 */
export const getSignatureParameters = (signature) => {
    if (!isHexStrict(signature)) {
        throw new Error(`Given value "${signature}" is not a valid hex string.`);
    }

    const r = signature.slice(0, 66);
    const s = `0x${signature.slice(66, 130)}`;
    let v = `0x${signature.slice(130, 132)}`;
    v = hexToNumber(v);

    if (![27, 28].includes(v)) v += 27;

    return {
        r,
        s,
        v,
    };
};
