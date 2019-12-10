/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */

import chai from 'chai';
import TestConfig from '../config.json';
import { scanUTXOs } from '../utils';

const { expect } = chai;
chai.should();


const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[1]; // hold around 1 mil tomo

describe('#ete #balance', () => {
    it('#scanUTXOs and sum balance', (done) => {
        // scan all UTXO
        scanUTXOs(SENDER_WALLET.privateKey).then((ret) => {
            expect(ret.balance > 0).to.be.equal(true);
            done();
        }).catch((ex) => {
            done(ex);
        });
    });
});
