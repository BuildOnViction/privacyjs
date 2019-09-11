tomoprivacy
=======
# This repo includes all utils for generating
- `keys`: private view key, public spend key, public view key.
- `privacy address`: address from privacy transaction.
- `Person commitment`: Pederson commitment is cryptographic commitment scheme equivalent to secretly writing a secret message m in a sealed, tamper-evident, individually numbered (or/and countersigned) envelope kept by who wrote the message. The envelope's content can't be changed by any means, and the message does not leak any information.
- `Bullet proof`: Range proofs is a type of zero-knowledge proof used for proving that a secret is within a value range without revealing the precise value of the secret. Bulletproofs is a new non-interactive zero-knowledge proof protocol with very short proofs and without a trusted setup; the proof size is only logarithmic in the witness size. Bulletproofs are especially well suited for efficient range proofs on committed values: they enable proving that a committed value is in a range using only (2 logn + 9) group and field elements, where n is the bit length of the range. Proof generation and verification times are linear in n.
- `Transaction public key`: equal blinding factor * G (the standard secp256k1 base point)
- `Stealth Address`: Fork from https://github.com/cryptocoinjs/stealth (EdDSA - ed25519) customize to use ECDSA - secp256k1. The key and address are in different format. We remove the optional bit, prefix network bytes, just use private spend key, private view key and checksum, encode by base58.


Additional requests/features please contact anhnt@tomochain.com

[![js-standard-style](https://raw.githubusercontent.com/feross/standard/master/badge.png)](https://github.com/feross/standard)


Usage
-----

First, you should really read this excellent resource:
- https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-introduction
- https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-part-2-stealth-addresses
- https://cryptonote.org/whitepaper.pdf - Cryptonote white paper

#### If you're the payer (sender), assume you got secret key - private spend key

```js
var Stealth = require('tomoprivacyjs').stealth
var Commitment = require('tomoprivacyjs').commitment

var stealth = Stealth.fromString(privacy_address_of_reciever)

// create proof this tx belong to receiver
var proof = sender.genTransactionProof(receiver.pubSpendKey, receiver.pubViewKey) // this 

// create pederson commitment for hiding the amount, this is for smart contract checking our spend is not larger than balance
// ECDH_secret for this transaction = 
var commitment = sender.genCommiment(receiver.pubSpendKey, receiver.pubViewKey) // this

// encode amount by any symmetric-key algorithm using ECDH_shared_secret this is for account know the balance
// Mask = AES(amount, ECDH_secret) 

```


#### If you're the payee (recipient)

```js
var Stealth = require('tomoprivacyjs').stealth

// you need to scan every transaction and look for the following:
// 1. does the transaction contain an OP_RETURN?
// 2. if yes, then extract the OP_RETURN
// 3. is the OP_RETURN data a compressed public key (33 bytes)?
// 4. if yes, check if mine

// generate two key pairs, can use CoinKey, bitcoinjs-lib, bitcore, etc
var payloadKeyPair = require('coinkey').createRandom()
var scanKeyPair = require('coinkey').createRandom()

// note, the private keys are NOT encoded in the Stealth address
// you need to save them somewhere
var stealth = new Stealth({
  privViewKey: payloadKeyPair.privateKey,
  pubViewKey: payloadKeyPair.publicKey,
  privSpendKey: scanKeyPair.privateKey,
  pubSpendKey: scanKeyPair.publicKey
})

var addr = stealth.toString()
// => 'vJmtuUb8ysKiM1HtHQF23FGfjGAKu5sM94UyyjknqhJHNdj5CZzwtpGzeyaATQ2HvuzomNVtiwsTJSWzzCBgCTtUZbRFpzKVq9MAUr'

// publish addr or give it someone
// unlike regular Bitcoin addresses, you can use
// stealth address as much as you like

// scan and decode transactions

var opReturnPubKey = /* */
var pubKeyHashWithPayment = /* */

var keypair = stealth.checkPaymentPubKeyHash(opReturnPubKey, pubKeyHashWithPayment)

// it NOT YOURS, `keypair` will be falsey

if (keypair == null) {
  console.log('payment is not mine')
} else {
  console.log('payment is mine')

  // redeem with `privKey`
  console.log(keypair.privKey)
}
```

#TODO
- Use babel for development
- Setup test runer on the cloud (coverage above 80% if you run it on local right now npm test)
- Minify the build
- Shorten the address for saving

API
---

License
-------

MIT
