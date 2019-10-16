import { toBN } from './src/common';

const ecurve = require('ecurve');
// hack to get bigi without including it as a dep
const ecparams = ecurve.getCurveByName('secp256k1');
const BigInteger = ecparams.n.constructor;

console.log(toBN(-1));
console.log(toBN(-1).toString(10));
console.log(
  BigInteger.fromHex('01').not().toString(10),
);
console.log(
  BigInteger.fromHex('01')
    .multiply(
      BigInteger.fromHex('01').not(),
    )
  ,
);
