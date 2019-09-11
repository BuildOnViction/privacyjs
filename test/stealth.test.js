var assert = require('assert')
var Stealth = require('../').stealth
var Address = require('../').address
var common = require('../')
var fixtures = require('./fixtures')

/* global describe, it */
// trinity: mocha

describe('stealth', function () {
    fixtures.valid.forEach(function (f) {
        describe('fromString()', function () {
            it('should convert from base58-check string to object', function () {
                var stealth = Stealth.fromString(f.base58)

                assert.equal(stealth.pubSpendKey.toString('hex'), f.receiverSpend.pubKey)
                assert.equal(stealth.pubViewKey.toString('hex'), f.receiverView.pubKey)
            })
        })

        describe('#genTransactionProof()', function () {
            it('should generate the payment pubkeyhash for the sender (payer) to send money to', function () {
                var stealth = Stealth.fromString(f.base58)
                var proof = stealth.genTransactionProof(1000)

                assert.equal(proof.onetimeAddress.toString('hex').length, 66)
                assert.equal(proof.txPublicKey.toString('hex').length, 66)
                assert.equal(proof.mask.length, 28)
            })
        })

        describe('#checkTransactionProof()', function () {
            it('should claim proof for right account', function () {
                var sender = new Stealth({
                    ...Address.generateKeys(f.sender.privKey)
                })
                var receiver = new Stealth({
                    ...Address.generateKeys(f.receiverSpend.privKey)
                })

                // create proof for a transaction 
                var proof = sender.genTransactionProof(1000, receiver.pubSpendKey, receiver.pubViewKey)
                // prove above information belong to receiver
                var result = receiver.checkTransactionProof(proof.txPublicKey, proof.onetimeAddress, proof.mask)
                
                // prove above information belong to receiver
                assert.notEqual(result, null)
                assert.equal(result.amount, 1000)
            })

            it('should not claim proof for tx not belong', function () {
                var sender = new Stealth({
                    ...Address.generateKeys(f.sender.privKey)
                })
                var receiver = new Stealth({
                    ...Address.generateKeys(common.randomHex(64))
                })

                // create proof for a transaction for an other receiver - not above one
                var proof = sender.genTransactionProof(1000, new Buffer(f.receiverSpend.pubKey, "hex"), new Buffer(f.receiverView.pubKey, "hex"))

                // try to claim the ownership and not success
                var result = receiver.checkTransactionProof(proof.onetimeAddress, proof.txPublicKey)
                assert.equal(result, null)
            })
        })

    })
})
