import UTXO from '../../src/utxo';
import assert from 'assert';

import { ec as EC} from 'elliptic';
let ec = new EC('secp256k1');

// test data from json
let data = require('./utxos');
let utxos = data.mine;
let privateKey = data.keys.privateKey;
let otherUtxos = data.other;

describe('#unittest #utxo', function () {
    describe('#isMineUTXO()', function () {
        utxos.forEach(function (utxo) {
            it('should claim belonging utxos', function (done) {
                let utxoIns = new UTXO(utxo);
                let isMineUTXO = utxoIns.isMineUTXO(privateKey);

                assert.notEqual(isMineUTXO, null);
                // don't check amount here because the algorithm can be changed
                // should check amount in stealth.js
                done();
            })
        });

    });

    otherUtxos.forEach(function (utxo) {
        it('should not claim utxo not belongs', function (done) {
            let utxoIns = new UTXO(utxo);
            let isMineUTXO = utxoIns.isMineUTXO(privateKey);

            assert.equal(isMineUTXO, null);
            done();
        })
    });

    describe('#sign()', function () {
        it('should sign correctly - check the signed message with public key correct', function (done) {
            let key = ec.keyFromPrivate(privateKey);
            let utxoIns = new UTXO(utxos[0]);
            var msgHash = utxoIns.getHashData(privateKey);
            let signature = utxoIns.sign(privateKey);

            let pubPoint = key.getPublic();
            let x = pubPoint.getX();
            let y = pubPoint.getY();

            // Public Key MUST be either:
            // 1) '04' + hex string of x + hex string of y; or
            // 2) object with two hex string properties (x and y); or
            // 3) object with two buffer properties (x and y)
            let pub = pubPoint.encode('hex');                                 // case 1

            // Import public key
            let verifingKey = ec.keyFromPublic(pub, 'hex');

            // Signature MUST be either:
            // 1) DER-encoded signature as hex-string; or
            // 2) DER-encoded signature as buffer; or
            // 3) object with two hex-string properties (r and s); or
            // 4) object with two buffer properties (r and s)

            let verifyingSignature = new Buffer(signature); // case 2

            // Verify signature
            assert.equal(verifingKey.verify(msgHash, verifyingSignature), true);

            done()
        })
    })
})
