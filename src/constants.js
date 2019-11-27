
import BN from 'bn.js';

// all constant in hex string
export const ETH_ADDRESS_LENGTH = 42;
export const PRIVATE_KEY_LENGTH = 64;
export const PRIVACY_ADDRESS_LENGTH = 95; // we used base 58
export const SHORT_FORM_CURVE_POINT = 66;
export const LONG_FORM_CURVE_POINT = 134;
export const DEFAULT_GAS_PRICE = '250000000';
export const DEFAULT_GAS = '20000000';

BN.fromHex = hexstring => new BN(hexstring, 16);
BN.TWO = () => new BN('10', 2);
BN.ZERO = () => new BN('0', 2);
BN.ONE = () => new BN('01', 2);

export const BigInteger = BN;
