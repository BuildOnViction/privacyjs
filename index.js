const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

console.log(secp256k1.keyFromPrivate('4b3963708a7e33b2efc540e772c9fc9189fdf093c0fc0a42248a55e77012191b').getPublic().encodeCompressed('hex'));
