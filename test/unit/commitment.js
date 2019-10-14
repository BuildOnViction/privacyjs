import chai from 'chai';
import TestConfig from '../config.json';
import Stealth from '../../src/stealth';
import * as Address from '../../src/address';
import Commitment from '../../src/commitment';

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

const TOMO = 1000000000000000000;
const sender = new Stealth({
    ...Address.generateKeys(SENDER_WALLET.privateKey),
});

describe('#unittest #commitment', () => {
    describe('#sumCommitments', () => {

        it('Should generateCommitment correctly', (done) => {
            const proof = sender.genTransactionProof(TOMO, sender.pubSpendKey, sender.pubViewKey);
            const regeneratedCommitment = Commitment.genCommitment(TOMO, proof.mask, false);
            expect(proof.commitment.toString('hex')).to.equal(regeneratedCommitment.toString('hex'));
            done();
        });

        it('Should split comitments correctly in private send', (done) => {
            done(new Error('not implemented yet'));
        });

    });
});
