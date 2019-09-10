var assert = require('assert')
const common = require('../');
const address = require('../').address;
const elliptic = require('elliptic');
const ec = new elliptic.ec('secp256k1');
const Base58 = require('bs58');

describe('address', function () {
    describe('#generateKeys()', function () {
        const key = ec.genKeyPair();
        const privateKey = key.getPrivate('hex');
        const generatedKeys = address.generateKeys(privateKey);
        
        it("Should return correct public spend key in hex", function () {
            assert.equal(generatedKeys.pubSpend, key.getPublic().encodeCompressed('hex'))
        })
    
        it("Should return correct private view key", function () {
            assert.equal(generatedKeys.privView, common.fastHash(privateKey));
        })
    
        it("Should return correct public view key", function () {
            assert.equal(generatedKeys.pubView, address.privateKeyToPub(generatedKeys.privView))
        })
    
        it("Return address with format Base58.encode(public spend key + public view key + checksum", function () {
            // length after using base58 should reduce from 140 to 95
            assert.equal(generatedKeys.pubAddr.length, 95);
            
            // decode the public address to get public spend key and public view key - length 140
            let decodedPrivacyAddress = common.bintohex(Base58.decode(generatedKeys.pubAddr));
    
            // get first 33 bytes - 66 hex string of public spend key
            let publicSpendKey = decodedPrivacyAddress.substr(0, 66);
            assert.equal(generatedKeys.pubSpend, publicSpendKey);
    
            // get first 33 bytes - 66 hex string of public view key
            let publicViewKey = decodedPrivacyAddress.substr(66, 66);
            assert.equal(generatedKeys.pubView, publicViewKey);
    
            // double test check sum
            let preAddr = generatedKeys.pubSpend + generatedKeys.pubView;
            let hash = common.fastHash(preAddr).slice(0, 8);
            assert.equal(hash, decodedPrivacyAddress.substr(132, 8));
        })

    })
})

