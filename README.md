tomoprivacy
Low-level apis for working in Tomoprivacy protocal
=======
Terms
- `keys`: private view key, public spend key, public view key.
- `privacy address`: address from privacy transaction.
- `Pederson commitment`: Pederson commitment is cryptographic commitment scheme equivalent to secretly writing a secret message m in a sealed, tamper-evident, individually numbered (or/and countersigned) envelope kept by who wrote the message. The envelope's content can't be changed by any means, and the message does not leak any information.
- `Bullet proof`: Range proofs is a type of zero-knowledge proof used for proving that a secret is within a value range without revealing the precise value of the secret. Bulletproofs is a new non-interactive zero-knowledge proof protocol with very short proofs and without a trusted setup; the proof size is only logarithmic in the witness size. Bulletproofs are especially well suited for efficient range proofs on committed values: they enable proving that a committed value is in a range using only (2 logn + 9) group and field elements, where n is the bit length of the range. Proof generation and verification times are linear in n.
- `Transaction public key`: equal blinding factor * G (the standard secp256k1 base point)
- `Stealth Address`: in other word - oneTimeAddress or tomo privacy address
- `RingCT`: ring confidental transaction protocol, base on Cryptonote's with modifying for tomochain only

Reference 
- https://eprint.iacr.org/2015/1098.pdf
- https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-introduction
- https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-part-2-stealth-addresses
- https://cryptonote.org/whitepaper.pdf - Cryptonote white paper
Additional requests/features please contact anhnt@tomochain.com

[![Build Status](https://travis-ci.org/tomochain/privacyjs.svg?branch=master)](https://travis-ci.org/tomochain/privacyjs)
### TODO
- [] Support high level api for instantly use: deposit, check balance, withdraw, privatesend - right now just low-level apis for interacting with Smart-contract and generating fields following  the protocol
- [] Support auto RingCT and bullet-proof (with auto select, mix spending utxos, noising array utxos)
- [] Use type flows for helping other developer understand the structure, bytes length of fiels in privacy protocol
- [x] Review the randomHex function -> replace by eclliptic.genPair for make sure the random value in range > 0 and < p in Zp secck256
- [x] Use babel for development
- [x] Fully support browser 
- [x] Setup test runer on the cloud (coverage above 80% if you run it on local right now npm test)
- [x] Minify the build
- [x] Deploy to npm

Usage
-----

***The fun part of privacy is the client must calculate all the things. Any wrong calculation results in money loss :)***

#### If you're the payer (sender), assume you got secret key - private spend key

```js
var Stealth = require('tomoprivacyjs').stealth
var Commitment = require('tomoprivacyjs').commitment

var stealth = Stealth.fromString(privacy_address_of_reciever)

var AMOUNT = 1000

// create tx send to receiver 1000 tomo
var proof = sender.genTransactionProof(AMOUNT, receiver.pubSpendKey, receiver.pubViewKey) // this 

// create pederson commitment for hiding the amount, this is for smart contract checking our spend is not larger than balance
var commitment = sender.genCommiment(receiver.pubSpendKey, receiver.pubViewKey) // this

// in the end the tx information includes
/**
 * proof.mask
 * commitment
 * onetimeAddress (stealth address)
 * transaction public key
 */

```

#### If you're the payee (recipient)

```js
var Stealth = require('tomoprivacyjs').stealth
var Address = require('tomoprivacyjs').address

// you need to scan every transaction and look for the following:
var receiver = new Stealth({
    ...Address.generateKeys(privKey)
})

var result = receiver.checkTransactionProof(proof.txPublicKey, proof.onetimeAddress, proof.mask)

if (result == null) {
  console.log('payment is not mine')
} else {
  console.log('payment is mine')

  console.log(result.amount)
}
```

#### Deposit into your private account
```js
let amount = 1000000000000000000; // 1 tomo
// generate a tx 1 tomo from normal addess to privacy address
let sender = new Stealth({
    ...Address.generateKeys(privateKey)
})

// create proof for a transaction 
let proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);

privacyContract.methods.deposit(
    '0x' + proof.onetimeAddress.toString('hex').substr(2, 64), // the X part of curve 
    '0x' + proof.onetimeAddress.toString('hex').substr(-64), // the Y part of curve
    '0x' + proof.txPublicKey.toString('hex').substr(2, 64), // the X part of curve
    '0x' + proof.txPublicKey.toString('hex').substr(-64), // the Y par of curve,
    '0x' + proof.mask,
    '0x' + proof.encryptedAmount// encrypt of amount using ECDH
)
    .send({
        from: SENDER_WALLET.address,
        value: amount // in plain number
    })
    .on('error', function(error) {
        done(error);
    })
    .then(function(receipt){
      // you would get an utxo inside receipt.events receipt.events.NewUTXO
      // with following field
      /**
       *  0 - commitmentX:
        * 1 - _commitmentYBit: '0',
        * 2 - _pubkeyX: stealth_address_X, short form of a point in ECC
        * 3 - _pubkeyYBit: '', // bit indicate odd or even of stealth_address_Y
        * 4 - _amount: encrypt_AES(shared_ECDH, amount),
        *_5 - _txPubX: transation_public_key_X, short form of a point in ECC
        * 6 - _txPubYBit
        * 7 - _index
      */
    });
```

#### Calculate balance
You should always listen to event newUTXO and save your index in cookies or localstorage
When user uses this feature on new device you need to scan all belongings
and get utxo detail

```js
function getUTXO(index) {
    return new Promise((resolve, reject) => {
        privacyContract.methods.getUTXO(index)
                .call({
                    from: WALLETS[0].address
                })
                .then(function (utxo) {
                    return resolve(utxo);
                }).catch(exception => {
                    reject(exception);
                })
    });
}

const scanAllUTXO = async() => {
    let index = 0;
    var utxo = {};
    var balance = 0;

    do {
        try {
            utxo = await getUTXO(index);
            let utxoInstance = new UTXO(utxo);
            let isMine = utxoInstance.checkOwnership(SENDER_WALLET.privateKey);
            
            if (isMine && parseFloat(isMine.amount).toString() == isMine.amount ) {
                balance += isMine.amount;
            }
            index++;
        } catch(exception) {
            utxo = null;
            break;
        }
    } while (utxo);

    return balance;
}
```

### Private Send
You do the same thing like deposite but
1. Creating proof by receiver's public view key and receiver's public spend key
2. select the list utxo's index you want to send
3. select the encrypted money amount you wanna send

```js
// you got privacy address of receiver
// create a steath from privacy address
let receiver = Stealth.fromString(privacy_address_of_receiver);
let proof = sender.genTransactionProof(amount, receiver.pubSpendKey, receiver.pubViewKey);
privacyContract.methods.privatesend(
    [utxo1, utxo2, utxo3],
    Web3.utils.hexToNumberString(proof.onetimeAddress.toString('hex').substr(2, 64)), // the X part of curve 
    Web3.utils.hexToNumberString(proof.onetimeAddress.toString('hex').substr(-64)), // the Y part of curve
    Web3.utils.hexToNumberString(proof.txPublicKey.toString('hex').substr(2, 64)), // the X part of curve
    Web3.utils.hexToNumberString(proof.txPublicKey.toString('hex').substr(-64)), // the Y par of curve,
    Web3.utils.hexToNumberString(proof.mask),
    Web3.utils.hexToNumberString(proof.encryptedAmount)// encrypt of amount using ECDH
)
    .send({
        from: SENDER_WALLET.address
    })
    .on('error', function(error) {
        done(error);
    })
    .then(function(receipt){
      // you would get an utxo inside receipt.events receipt.events.NewUTXO
      // with following field
      /**
       *  0 - commitmentX:
        * 1 - _commitmentYBit: '0',
        * 2 - _pubkeyX: stealth_address_X, short form of a point in ECC
        * 3 - _pubkeyYBit: '', // bit indicate odd or even of stealth_address_Y
        * 4 - _amount: encrypt_AES(shared_ECDH, amount),
        *_5 - _txPubX: transation_public_key_X, short form of a point in ECC
        * 6 - _txPubYBit
        * 7 - _index
      */
    });
```

### Withdraw
Right now we just support withdraw from a single utxo. That mean if you want
to withdraw more, you have to calculate yourself base on utxo info.
Need 5 parameters
1. index - utxo's index, integer number
2. _amounts - a two elements array includes:
  1 - amount want to spend in plain number ie 5.5,
  2 - encrypted by secretKey (in inside src/stealth.js for more detail) of remaining amount in this utxo
3. the signature of the utxo using ECDSA
4. commitment of remain amount in this utxo = utxo's mask + remain_money*H

***Comming Soon***

TEST
---
- [x] Unit test - done
- Smock test - not implemented yet
- [x] End to end test on tomochain testnet - cover main flow deposit, withdraw, sendtoprivate

License
-------

MIT
