import chai from 'chai';
import TestConfig from '../config.json';
import Wallet from '../../src/wallet';

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;

/* eslint-disable max-len */
// eslint-disable-next-line max-len
/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */

describe('#wallet #decoys', () => {
    const wallet = new Wallet(WALLETS[0].privateKey, {
        RPC_END_POINT: TestConfig.RPC_END_POINT,
        ABI: TestConfig.PRIVACY_ABI,
        ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
    }, WALLETS[0].address);
    for (let count = 0; count < 10; count++) {
        it('Should get decoys successfully', (done) => {
            wallet.scannedTo = 100;
            wallet.getDecoys(2, [1, 5]).then((res) => {
                expect(res.length).to.equal(2);
                expect(res[0].length).to.equal(11);
                expect(res[1].length).to.equal(11);
                // expect(typeof res[0][0]).to.equal('UTXO');

                const randomElement = res[
                    Math.round(Math.random() * 1)
                ][
                    Math.round(Math.random() * 11)
                ];
                expect(randomElement).has.property('lfCommitment');
                expect(randomElement).has.property('index');
                expect(randomElement).has.property('lfStealth');
                done();
            }).catch((err) => {
                done(err);
            });
        });
    }

    it('Should get single utxo successfully', (done) => {
        wallet.scannedTo = 100;
        wallet.getUTXO(10).then((res) => {
            expect(res[0].length).to.equal(3);
            expect(res[1].length).to.equal(3);
            expect(res[2].length).to.equal(2);
            expect(res[3]).to.equal(10);
            done();
        }).catch((err) => {
            done(err);
        });
    });
});
