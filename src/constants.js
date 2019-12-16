
import BN from 'bn.js';

// all constant in hex string
export const ETH_ADDRESS_LENGTH = 42;
export const PRIVATE_KEY_LENGTH = 64;
export const PRIVACY_ADDRESS_LENGTH = 95; // we used base 58
export const SHORT_FORM_CURVE_POINT = 66;
export const LONG_FORM_CURVE_POINT = 134;
export const DEFAULT_GAS_PRICE = '250000000';
export const DEFAULT_GAS = '3000000';

BN.fromHex = hexstring => new BN(hexstring.toString(), 16);

BN.fromBuffer = buffer => new BN(buffer.toString('hex'), 16);
BN.TWO = () => new BN('10', 2);
BN.ZERO = () => new BN('0', 2);
BN.ONE = () => new BN('01', 2);

export const BigInteger = BN;
const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');
export const baseH = secp256k1.curve.point(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    '31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904',
);
