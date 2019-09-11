var assert = require('assert')
import common from '../src/';
import address from '../src/address';

const elliptic = require('elliptic');
const ec = new elliptic.ec('secp256k1');
const Base58 = require('bs58');

describe('address', function () {
    describe('#generateKeys()', function () {
        const key = ec.genKeyPair();
        const privateKey = key.getPrivate('hex');
        const generatedKeys = address.generateKeys(privateKey);
        
        it("Should return correct public spend key in hex", function () {
            assert.equal(generatedKeys.pubSpendKey, key.getPublic().encodeCompressed('hex'))
        })
    
        it("Should return correct private view key", function () {
            assert.equal(generatedKeys.privViewKey, common.fastHash(privateKey));
        })
    
        it("Should return correct public view key", function () {
            assert.equal(generatedKeys.pubViewKey, address.privateKeyToPub(generatedKeys.privViewKey))
        })
    
        it("Return address with format Base58.encode(public spend key + public view key + checksum", function () {
            // length after using base58 should reduce from 140 to 95
            assert.equal(generatedKeys.pubAddr.length, 95);
            
            // decode the public address to get public spend key and public view key - length 140
            var decodedPrivacyAddress = common.bintohex(Base58.decode(generatedKeys.pubAddr));
    
            // get first 33 bytes - 66 hex string of public spend key
            var publicSpendKey = decodedPrivacyAddress.substr(0, 66);
            assert.equal(generatedKeys.pubSpendKey, publicSpendKey);
    
            // get first 33 bytes - 66 hex string of public view key
            var publicViewKey = decodedPrivacyAddress.substr(66, 66);
            assert.equal(generatedKeys.pubViewKey, publicViewKey);
    
            // double test check sum
            var preAddr = generatedKeys.pubSpendKey + generatedKeys.pubViewKey;
            var hash = common.fastHash(preAddr).slice(0, 8);
            assert.equal(hash, decodedPrivacyAddress.substr(132, 8));
        })

    })
})

