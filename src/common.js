const { keccak256 } = require('js-sha3');

/**
 * hextobin converts string to Buffer
 * @param {string} hex Hex string wants to conver to buffer
 * @returns {Buffer} Buffer
 */
function hextobin(hex) {
  if (hex.length % 2 !== 0) throw 'Hex string has invalid length!';
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
 */
function fastHash(input) {
  if (input.length % 2 !== 0 || !validHex(input)) {
    throw 'Invalid Hex input for hashing Keccak256';
  }
  return keccak256(input);
}

module.exports = {
  hextobin,
  bintohex,
  validHex,
  fastHash,
};
