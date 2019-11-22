import assert from 'assert';
import { randomHex } from '../../src/crypto';
import * as Address from '../../src/address';
import Stealth from '../../src/stealth';

const fixtures = require('./fixtures');

describe('#unittest #stealth', () => {
    fixtures.valid.forEach((fixture) => {
        describe('fromString()', () => {
            it('should convert from base58-check string to a stealth', () => {
                const stealth = Stealth.fromString(fixture.base58);

                assert.equal(stealth.pubSpendKey.toString('hex'), fixture.receiverSpend.pubKey);
                assert.equal(stealth.pubViewKey.toString('hex'), fixture.receiverView.pubKey);
            });
        });

        describe('#genTransactionProof()', () => {
            it('should generate the payment pubkeyhash for the sender (payer) to send money to', () => {
                const stealth = Stealth.fromString(fixture.base58);
                const proof = stealth.genTransactionProof(1000);

                assert.equal(proof.onetimeAddress.length, 130);
                assert.equal(proof.txPublicKey.length, 130);
                // assert.equal(proof.encryptedAmount.length, 28)
                assert.equal(proof.mask.length, 64);
            });
        });

        describe('#checkTransactionProof()', () => {
            it('should claim proof for right account', () => {
                const sender = new Stealth({
                    ...Address.generateKeys(fixture.sender.privKey),
                });
                const receiver = new Stealth({
                    ...Address.generateKeys(fixture.receiverSpend.privKey),
                });

                // create proof for a transaction
                const proof = sender.genTransactionProof(1000,
                    receiver.pubSpendKey, receiver.pubViewKey);

                console.log('result ', proof);

                // prove above information belong to receiver
                const result = receiver.checkTransactionProof(
                    proof.txPublicKey, proof.onetimeAddress, proof.encryptedAmount,
                );

                // prove above information belong to receiver
                assert.notEqual(result, null);
                assert.equal(result.amount, 1000);
            });

            it('should not claim proof for tx not belong', () => {
                const sender = new Stealth({
                    ...Address.generateKeys(fixture.sender.privKey),
                });
                const receiver = new Stealth({
                    ...Address.generateKeys(randomHex()),
                });

                // create proof for a transaction for an other receiver - not above one
                const proof = sender.genTransactionProof(1000, new Buffer(fixture.receiverSpend.pubKey, 'hex'), new Buffer(fixture.receiverView.pubKey, 'hex'));

                // try to claim the ownership and not success
                const result = receiver.checkTransactionProof(
                    proof.txPublicKey, proof.onetimeAddress,
                );
                assert.equal(result, null);
            });
        });

        describe('#encryptedAmount()', () => {
            it('should return correct encrypted new amount from same txPublic/stealth address', () => {
                const sender = new Stealth({
                    ...Address.generateKeys(fixture.sender.privKey),
                });
                const receiver = new Stealth({
                    ...Address.generateKeys(fixture.receiverSpend.privKey),
                });

                // create proof for a transaction
                const temp = sender.genTransactionProof(1000,
                    receiver.pubSpendKey, receiver.pubViewKey);

                // use same txPublickey and onetimeaddress for generate another encrypted amount
                // for using in withdraw
                const encryptedAmount = receiver.encryptedAmount(temp.txPublicKey,
                    temp.onetimeAddress, 5000);

                // try to claim the ownership and not success
                const result = receiver.checkTransactionProof(
                    temp.txPublicKey, temp.onetimeAddress, encryptedAmount,
                );

                // prove above information belong to receiver
                assert.notEqual(result, null);
                assert.equal(
                    result.amount,
                    '5000',
                );
            });
        });
    });
});
