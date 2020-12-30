// console.log(secp256k1.keyFromPrivate('4b3963708a7e33b2efc540e772c9fc9189fdf093c0fc0a42248a55e77012191b').getPublic().encodeCompressed('hex'));

const { createECDH, ECDH } = require("crypto");
const bip39 = require('bip39')
const ecdh = createECDH("secp256k1");
    ecdh.generateKeys();
const privateKey = ecdh.getPrivateKey("hex");
console.log(privateKey)
console.log(bip39.mnemonicToSeedSync().toString('hex'))

var crypto = require("crypto");
var randombytes = require('randombytes');
var eccrypto = require("eccrypto");

// A new random 32-byte private key.
console.log(eccrypto.generatePrivate().toString("hex"));

randombytes(32).toString('hex')