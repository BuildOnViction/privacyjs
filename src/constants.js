
import toBN from 'number-to-bn';

export const ETH_ADDRESS_LENGTH = 42;
export const PRIVATE_KEY_LENGTH = 64;
export const PRIVACY_ADDRESS_LENGTH = 95; // we used base 58
export const SHORT_FORM_CURVE_POINT = 66;
export const LONG_FORM_CURVE_POINT = 134;

export const DEFAULT_GAS_PRICE = '250000000';
export const DEFAULT_GAS = '20000000';

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');
export const baseH = secp256k1.curve.point(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    '31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904',
);

export const UTXO_RING_SIZE = 12;
export const MAXIMUM_ALLOWED_RING_NUMBER = 8;
export const PRIVACY_FLAT_FEE = toBN(
    '10000000',
); // 0.01 TOMO

export const DEPOSIT_FEE_WEI = toBN(
    '1000000',
); // 0.001 TOMO

export const PRIVACY_TOKEN_UNIT = toBN(
    '1000000000',
); // use gwei as base unit for reducing size of rangeproof
