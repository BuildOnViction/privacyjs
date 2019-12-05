/* eslint-disable no-prototype-builtins */
import { keccak256 as Hash, sha3_256 as sha3 } from 'js-sha3';
import numberToBN from 'number-to-bn';
import * as _ from 'lodash';
import isBoolean from 'lodash/isBoolean';
import isString from 'lodash/isString';
import isNumber from 'lodash/isNumber';
import isObject from 'lodash/isObject';
import isNull from 'lodash/isNull';
import isFinite from 'lodash/isFinite';
import utf8 from 'utf8';
import BN from 'bn.js';
import assert from 'assert';
import { BigInteger } from './crypto';

// const atob = require('atob') || window.atob;
const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');
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

// export const base64tohex = (base64) => {
//     const raw = atob(base64);
//     let HEX = '';
//     for (let i = 0; i < raw.length; i++) {
//         const _hex = raw.charCodeAt(i).toString(16);
//         HEX += (_hex.length === 2 ? _hex : `0${_hex}`);
//     }
//     return HEX.toUpperCase();
// };

/**
 * bconcat makes a buffer from a buffer list
 * @param {array} arr List Buffer want to concat
 * @returns {Buffer} concated buffer
 */
export const bconcat = (arr) => {
    arr = arr.map((item) => {
        const res = (Buffer.isBuffer(item) ? item : new Buffer([item]));
        // console.log('bconcat ------------------ ');
        // console.log(item);
        // console.log(res);
        // console.log('bconcat ------------------ ');
        return res;
    });

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

// /**
//  * Takes an input and transforms it into an BN.js object
//  *
//  * @method toBN
//  *
//  * @param {Number|String|BN} number, string, HEX string or BN
//  *
//  * @returns {BN} BN
//  */
// export const toBN = (number) => {
//     try {
//         return numberToBN(number);
//     } catch (error) {
//         throw new Error(`${error} Given value: "${number}"`);
//     }
// };


/**
 * Takes an input and transforms it into an bigi object
 * TODO - need to replace bigi by bn.js
 * @method toBN
 *
 * @param {Number|String} number, string, HEX string or BN
 *
 * @returns {BigInteger} BigInteger
 */
export const toBN = (number) => {
    try {
        let hexstr = numberToBN(number).toString(16);
        if (hexstr.length % 2 === 1) {
            hexstr = '0' + hexstr;
        }
        return BigInteger.fromHex(
            hexstr,
        );
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
export const toTwosComplement = number => `0x${numberToBN(number)
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

    return numberToBN(value).toNumber();
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

    if (value.indexOf('0x') !== 0) {
        value = '0x' + value;
    }

    // if (value.length % 2 === 1) {
    //     value = '0' + value;
    // }
    return numberToBN(value).toString(10);
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
    const number = numberToBN(value);
    const result = number.toString(16);
    const hexString = number.lt(new BN(0)) ? `-${result.substr(1)}` : `${result}`;

    if (hexString.length % 2 === 1) {
        return `0${hexString}`;
    }

    return hexString;
};

/**
 * Convert a byte array to a hex string
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
 * @method hexToBytes
 *
 * @param {String} hex
 *
 * @returns {Array} the byte array
 */
export const hexToBytes = (hex) => {
    hex = hex.toString(16);
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

const _elementaryName = function (name) {
    if (name.startsWith('int[')) {
        return 'int256' + name.slice(3);
    }
    if (name === 'int') {
        return 'int256';
    }
    if (name.startsWith('uint[')) {
        return 'uint256' + name.slice(4);
    }
    if (name === 'uint') {
        return 'uint256';
    }
    if (name.startsWith('fixed[')) {
        return 'fixed128x128' + name.slice(5);
    }
    if (name === 'fixed') {
        return 'fixed128x128';
    }
    if (name.startsWith('ufixed[')) {
        return 'ufixed128x128' + name.slice(6);
    }
    if (name === 'ufixed') {
        return 'ufixed128x128';
    }
    return name;
};

// Parse N from type<N>
const _parseTypeN = function (type) {
    const typesize = /^\D+(\d+).*$/.exec(type);
    return typesize ? parseInt(typesize[1], 10) : null;
};

// Parse N from type[<N>]
const _parseTypeNArray = function (type) {
    const arraySize = /^\D+\d*\[(\d+)\]$/.exec(type);
    return arraySize ? parseInt(arraySize[1], 10) : null;
};

const _parseNumber = function (arg) {
    const type = typeof arg;
    if (type === 'string') {
        if (isHexStrict(arg)) {
            return new BN(arg.replace(/0x/i, ''), 16);
        }
        return new BN(arg, 10);
    }
    if (type === 'number') {
        return new BN(arg);
    }

    if (isBigNumber(arg)) {
        return new BN(arg.toString(10));
    }

    if (isBN(arg)) {
        return arg;
    }

    throw new Error(arg + ' is not a number');
};

const _solidityPack = function (type, value, arraySize) {
    let size;
    let num;
    type = _elementaryName(type);

    if (type === 'bytes') {
        if (value.replace(/^0x/i, '').length % 2 !== 0) {
            throw new Error('Invalid bytes characters ' + value.length);
        }

        return value;
    } if (type === 'string') {
        return utf8ToHex(value);
    } if (type === 'bool') {
        return value ? '01' : '00';
    } if (type.startsWith('address')) {
        if (arraySize) {
            size = 64;
        } else {
            size = 40;
        }

        if (!isAddress(value)) {
            throw new Error(value + ' is not a valid address, or the checksum is invalid.');
        }

        return leftPad(value.toLowerCase(), size);
    }

    size = _parseTypeN(type);

    if (type.startsWith('bytes')) {
        if (!size) {
            throw new Error('bytes[] not yet supported in solidity');
        }

        // must be 32 byte slices when in an array
        if (arraySize) {
            size = 32;
        }

        if (size < 1 || size > 32 || size < value.replace(/^0x/i, '').length / 2) {
            throw new Error('Invalid bytes' + size + ' for ' + value);
        }

        return rightPad(value, size * 2);
    } if (type.startsWith('uint')) {
        if ((size % 8) || (size < 8) || (size > 256)) {
            throw new Error('Invalid uint' + size + ' size');
        }

        num = _parseNumber(value);
        if (num.bitLength() > size) {
            throw new Error('Supplied uint exceeds width: ' + size + ' vs ' + num.bitLength());
        }

        if (num.lt(new BN(0))) {
            throw new Error('Supplied uint ' + num.toString() + ' is negative');
        }

        return size ? leftPad(num.toString('hex'), size / 8 * 2) : num;
    } if (type.startsWith('int')) {
        if ((size % 8) || (size < 8) || (size > 256)) {
            throw new Error('Invalid int' + size + ' size');
        }

        num = _parseNumber(value);
        if (num.bitLength() > size) {
            throw new Error('Supplied int exceeds width: ' + size + ' vs ' + num.bitLength());
        }

        if (num.lt(new BN(0))) {
            return num.toTwos(size).toString('hex');
        }
        return size ? leftPad(num.toString('hex'), size / 8 * 2) : num;
    }
    // FIXME: support all other types
    throw new Error('Unsupported or invalid type: ' + type);
};

const _processSoliditySha3Args = function (arg) {
    /* jshint maxcomplexity:false */

    if (_.isArray(arg)) {
        throw new Error('Autodetection of array types is not supported.');
    }

    let type; let
        value = '';
    let hexArg; let
        arraySize;

    // if type is given
    if (_.isObject(arg) && (arg.hasOwnProperty('v') || arg.hasOwnProperty('t') || arg.hasOwnProperty('value') || arg.hasOwnProperty('type'))) {
        type = arg.hasOwnProperty('t') ? arg.t : arg.type;
        value = arg.hasOwnProperty('v') ? arg.v : arg.value;

    // otherwise try to guess the type
    } else {
        type = toHex(arg, true);
        value = toHex(arg);

        if (!type.startsWith('int') && !type.startsWith('uint')) {
            type = 'bytes';
        }
    }

    if ((type.startsWith('int') || type.startsWith('uint')) && typeof value === 'string' && !/^(-)?0x/i.test(value)) {
        value = new BN(value);
    }

    // get the array size
    if (_.isArray(value)) {
        arraySize = _parseTypeNArray(type);
        if (arraySize && value.length !== arraySize) {
            throw new Error(type + ' is not matching the given array ' + JSON.stringify(value));
        } else {
            arraySize = value.length;
        }
    }

    if (_.isArray(value)) {
        hexArg = value.map(val => _solidityPack(type, val, arraySize).toString('hex').replace('0x', ''));
        return hexArg.join('');
    }
    hexArg = _solidityPack(type, value, arraySize);
    return hexArg.toString('hex').replace('0x', '');
};

/**
 * Hashes solidity values to a sha3 hash using keccak 256
 *
 * @method soliditySha3
 * @return {Object} the sha3
 */
export const soliditySha3 = function (...args) {
    const hexArgs = _.map(...args, _processSoliditySha3Args);

    return sha3('0x' + hexArgs.join(''));
};

/**
 * Decimal to binary
 * @param {number} val
 * @returns {array} array include 0, 1
 */
export const d2b = (val) => {
    let i = 0;
    const amountb = [];
    while (val !== 0) {
        amountb[i] = val & 1;
        i++;
        val >>= 1;
    }
    while (i < 64) {
        amountb[i] = 0;
        i++;
    }
    return amountb;
};


/**
 * Calculate inner product of two vector
 * return sum = v1[i]*v2[i]
 * @param {Array<BigInteger>} v1
 * @param {Array<BigInteger>} v2
 * @returns {BigInteger}
 */
export const innerProduct = (v1, v2) => {
    assert(v1.length === v2.length, 'Incompatible sizes of vector input');
    let sum = numberToBN(0);
    for (let i = 0; i < v1.length; i++) {
        sum = sum.add(
            v1[i]
                .mul(
                    v2[i],
                ).umod(secp256k1.n),
        );
    }

    return sum.umod(secp256k1.n);
};


/**
 * Calculate vector commitment
 * return Gi*a[i] + Hi*b[i]
 * @param {secp256k1.curve.point} Gi
 * @param {secp256k1.curve.point} Hi
 * @param {Array<BigInteger>} a
 * @param {Array<BigInteger>} b
 * @returns {secp256k1.curve.point}
 */
export function twoVectorPCommitWithGens(Gi, Hi, a, b) {
    let commitment;

    for (let i = 0; i < Gi.length; i++) {
        const modA = a[i].umod(secp256k1.n);
        const modB = b[i].umod(secp256k1.n);

        if (modA.toString(16).length) {
            commitment = commitment ? commitment.add(
                Gi[i].mul(modA),
            ) : Gi[i].mul(modA);
        }

        if (modB.toString(16).length) {
            commitment = commitment ? commitment.add(
                Hi[i].mul(modB),
            ) : Hi[i].mul(modB);
        }
    }

    return commitment;
}
