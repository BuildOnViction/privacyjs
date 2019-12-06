import BI from './node_modules/bigi/lib';
import { BigInteger } from './src/constants';
import { hexToNumberString } from './src/common';

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

// eslint-disable-next-line max-len
const bf = Buffer.from([0x78, 0x6a, 0x37, 0xd1, 0x6d, 0x0d, 0x68, 0x77, 0xb2, 0x4b, 0x53, 0xaa, 0xfd, 0xf7, 0xd2, 0x9c, 0x7e, 0x53, 0xb7, 0xbe, 0x43, 0x13, 0x4c, 0x3d, 0xb7, 0xb3, 0xe2, 0xee, 0xdd, 0x66, 0xdd, 0xea]);
const privKey = 'df36295d380e6b288bf9f1b7b44c4d2b0b22f43bb0ec1ea209f8de7a8ffc0fa9';
// <EC Point x: 1fe604ce2cef74f81b004bbb13cc8d0b249630e0eb824243a1f643ecd1901106 y: d4ff6e3c3c59862c606e017cb280c74e4f660f398883781e49bab6b8e486dcc1>
console.log(BigInteger.fromBuffer(bf).toString(10));
console.log(
  secp256k1.g.mul(
    BigInteger.fromHex(privKey),
  ).encode('hex', false),
);
