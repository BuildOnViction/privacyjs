/* eslint-disable no-loop-func */
import chai from 'chai';
import TestConfig from '../config.json';
import Wallet from '../../src/wallet';
import { generateKeys } from '../../src/address';

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;

/* eslint-disable max-len */
// eslint-disable-next-line max-len
/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */

describe('#wallet #ete', () => {
    let wallet: Wallet;

    beforeEach((done) => {
        wallet = new Wallet(WALLETS[0].privateKey, {
            RPC_END_POINT: TestConfig.RPC_END_POINT,
            ABI: TestConfig.PRIVACY_ABI,
            ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
        }, WALLETS[0].address);
        done();
    });

    for (let count = 0; count < 5; count++) {
        it('Should get decoys successfully for 5 rings', (done) => {
            wallet.scannedTo = 100;
            wallet._getDecoys(5, [1, 5]).then((res) => {
                expect(res.length).to.equal(5);
                expect(res[0].length).to.equal(11);
                expect(res[1].length).to.equal(11);
                // expect(typeof res[0][0]).to.equal('UTXO');

                const randomElement = res[
                    Math.round(Math.random() * 1)
                ][
                    Math.round(Math.random() * 10)
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

    it('Should able to create ringCT and output UTXO', (done) => {
        // just lazy don't wanna store privacy address in config, gen it here from private key
        const receiver = generateKeys(WALLETS[1].privateKey);
        try {
            wallet.send(receiver.pubAddr, '100000').then((res) => {
                console.log(res);
                done();
            }).catch((err) => {
                done(err);
            });
        } catch (ex) {
            done(ex);
        }
    });
});
