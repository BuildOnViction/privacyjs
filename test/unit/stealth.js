import assert from 'assert';
import {randomHex} from '../../src/crypto';
import Address from '../../src/address';
import Stealth from '../../src/stealth';

var fixtures = require('./fixtures')

/* global describe, it */
// trinity: mocha

describe('#unittest #stealth', function () {
    fixtures.valid.forEach(function (fixture) {
        describe('fromString()', function () {
            it('should convert from base58-check string to a stealth', function () {
                var stealth = Stealth.fromString(fixture.base58)

                assert.equal(stealth.pubSpendKey.toString('hex'), fixture.receiverSpend.pubKey)
                assert.equal(stealth.pubViewKey.toString('hex'), fixture.receiverView.pubKey)
            })
        })

        describe('#genTransactionProof()', function () {
            it('should generate the payment pubkeyhash for the sender (payer) to send money to', function () {
                var stealth = Stealth.fromString(fixture.base58)
                var proof = stealth.genTransactionProof(1000)

                assert.equal(proof.onetimeAddress.toString('hex').length, 130)
                assert.equal(proof.txPublicKey.toString('hex').length, 130)
                // assert.equal(proof.encryptedAmount.length, 28)
                assert.equal(proof.mask.length, 64)
            })
        })

        describe('#checkTransactionProof()', function () {
            it('should claim proof for right account', function () {
                var sender = new Stealth({
                    ...Address.generateKeys(fixture.sender.privKey)
                })
                var receiver = new Stealth({
                    ...Address.generateKeys(fixture.receiverSpend.privKey)
                })

                // create proof for a transaction 
                var proof = sender.genTransactionProof(1000, receiver.pubSpendKey, receiver.pubViewKey)
                // prove above information belong to receiver
                var result = receiver.checkTransactionProof(proof.txPublicKey, proof.onetimeAddress, proof.encryptedAmount)
                
                // prove above information belong to receiver
                assert.notEqual(result, null)
                assert.equal(result.amount, 1000)
            })

            it('should not claim proof for tx not belong', function () {
                var sender = new Stealth({
                    ...Address.generateKeys(fixture.sender.privKey)
                })
                var receiver = new Stealth({
                    ...Address.generateKeys(randomHex(64))
                })

                // create proof for a transaction for an other receiver - not above one
                var proof = sender.genTransactionProof(1000, new Buffer(fixture.receiverSpend.pubKey, "hex"), new Buffer(fixture.receiverView.pubKey, "hex"))

                // try to claim the ownership and not success
                var result = receiver.checkTransactionProof(proof.txPublicKey, proof.onetimeAddress)
                assert.equal(result, null)
            })
        })

        describe('#encryptedAmount()', function () {
            it('should return correct encrypted new amount from same txPublic/stealth address', function () {
                var sender = new Stealth({
                    ...Address.generateKeys(fixture.sender.privKey)
                })
                var receiver = new Stealth({
                    ...Address.generateKeys(fixture.receiverSpend.privKey)
                })

                // create proof for a transaction 
                var temp = sender.genTransactionProof(1000, receiver.pubSpendKey, receiver.pubViewKey)

                // use same txPublickey and onetimeaddress for generate another encrypted amount
                // for using in withdraw
                var encryptedAmount = receiver.encryptedAmount(temp.txPublicKey, temp.onetimeAddress, 5000);

                // try to claim the ownership and not success
                var result = receiver.checkTransactionProof(temp.txPublicKey, temp.onetimeAddress, encryptedAmount)

                // prove above information belong to receiver
                assert.notEqual(result, null)
                assert.equal(result.amount, 5000)
            })
        })
    })
})
