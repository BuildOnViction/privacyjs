const assert = require('assert');
const elliptic = require('elliptic');
const Base58 = require('bs58');
const common = require('../../src/common');
const address = require('../../src/address');

const ec = new elliptic.ec('secp256k1');
describe('#unittest #address', () => {
    describe('#generateKeys()', () => {
        const key = ec.genKeyPair();
        const privateKey = key.getPrivate('hex');
        const generatedKeys = address.generateKeys(privateKey);

        it('Should return correct public spend key in hex', () => {
            assert.equal(generatedKeys.pubSpendKey, key.getPublic().encodeCompressed('hex'));
        });

        it('Should return correct private view key', () => {
            assert.equal(generatedKeys.privViewKey, common.fastHash(privateKey));
        });

        it('Should return correct public view key', () => {
            assert.equal(generatedKeys.pubViewKey,
                address.privateKeyToPub(generatedKeys.privViewKey));
        });

        it('Return address with format Base58.encode(public spend key + public view key + checksum', (done) => {
            // length after using base58 should reduce from 140 to 95
            assert.equal(generatedKeys.pubAddr.length, 95);

            // decode the public address to get public spend key and public view key - length 140
            const decodedPrivacyAddress = common.bintohex(Base58.decode(generatedKeys.pubAddr));

            // get first 33 bytes - 66 hex string of public spend key
            const publicSpendKey = decodedPrivacyAddress.substr(0, 66);
            assert.equal(generatedKeys.pubSpendKey, publicSpendKey);

            // get first 33 bytes - 66 hex string of public view key
            const publicViewKey = decodedPrivacyAddress.substr(66, 66);
            assert.equal(generatedKeys.pubViewKey, publicViewKey);

            // double test check sum
            const isValidted = address.validate(generatedKeys.pubAddr);

            if (!isValidted) {
                return done(new Error('Privacy address is malform'));
            }

            done();
        });

    });
});
