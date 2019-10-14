import assert from 'assert';

import { ec as EC } from 'elliptic';
import UTXO from '../../src/utxo';

const ec = new EC('secp256k1');

// test data from json
const data = require('./utxos');

const utxos = data.mine;
const { privateKey } = data.keys;
const targetAddress = data.keys.address;
const otherUtxos = data.other;

describe('#unittest #utxo', () => {
    describe('#isMineUTXO()', () => {
        utxos.forEach((utxo) => {
            it('should claim belonging utxos', (done) => {
                const utxoIns = new UTXO(utxo);
                const isMineUTXO = utxoIns.checkOwnership(privateKey);

                assert.notEqual(isMineUTXO, null);
                // don't check amount here because the algorithm can be changed
                // should check amount in stealth.js
                done();
            });
        });

    });

    otherUtxos.forEach((utxo) => {
        it('should not claim utxo not belongs', (done) => {
            const utxoIns = new UTXO(utxo);
            const isMineUTXO = utxoIns.checkOwnership(privateKey);

            assert.equal(isMineUTXO, null);
            done();
        });
    });

    describe('#sign()', () => {
        it('should sign correctly - check the signed message with public key correct', (done) => {
            const key = ec.keyFromPrivate(privateKey);
            const utxoIns = new UTXO(utxos[0]);
            const msgHash = utxoIns.getHashData(privateKey);
            const signature = utxoIns.sign(privateKey, targetAddress);

            const pubPoint = key.getPublic();

            // Public Key MUST be either:
            // 1) '04' + hex string of x + hex string of y; or
            // 2) object with two hex string properties (x and y); or
            // 3) object with two buffer properties (x and y)
            const pub = pubPoint.encode('hex'); // case 1

            // Import public key
            const verifingKey = ec.keyFromPublic(pub, 'hex');

            // Signature MUST be either:
            // 1) DER-encoded signature as hex-string; or
            // 2) DER-encoded signature as buffer; or
            // 3) object with two hex-string properties (r and s); or
            // 4) object with two buffer properties (r and s)

            const verifyingSignature = new Buffer(signature.toDER()); // case 2

            // Verify signature
            assert.equal(verifingKey.verify(msgHash, verifyingSignature), true);

            done();
        });
    });
});
