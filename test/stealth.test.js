var assert = require('assert')
var Stealth = require('../').stealth
var crypto = require('../lib/crypto')
var fixtures = require('./fixtures')

/* global describe, it */
// trinity: mocha

describe('stealth', function () {
    fixtures.valid.forEach(function (f) {
        describe('fromString()', function () {
            it('should convert from base58-check string to object', function () {
                var stealth = Stealth.fromString("9dDbC9FzZ74r8njQkXD6W27gtrxLiWaeFPHxeo1fynQRXPt6izuCD63xBquh2L3KYkrAyhe3c2Y8AB1V7fKBjk5dHFMmHQq")

                assert.equal(stealth.spendPubKey.toString('hex'), f.receiverSpend.pubKey)
                assert.equal(stealth.viewPubKey.toString('hex'), f.receiverView.pubKey)
            })
        })

        describe('#genTransactionProof()', function () {
            it('should generate the payment pubkeyhash for the sender (payer) to send money to', function () {
                var stealth = Stealth.fromString(f.base58)
                var { onetimeAdress, txPublicKey} = stealth.genTransactionProof()

                assert.equal(onetimeAdress.toString('hex').length, 66)
                assert.equal(txPublicKey.toString('hex').length, 66)
            })
        })

    })
})
