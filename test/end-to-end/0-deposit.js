/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */

import chai from 'chai';
import TestConfig from '../config.json';
import * as TestUtils from '../utils';
import * as Address from '../../src/address';
import Stealth from '../../src/stealth';
import Commitment from '../../src/commitment';
import UTXO from '../../src/utxo';

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

const amount = 1000000000000000000;
const sender = new Stealth({
    ...Address.generateKeys(SENDER_WALLET.privateKey),
});

describe('#deposit', () => {
    for (let count = 0; count < 2; count++) {
        it('Successful deposit to to privacy account', (done) => {
            TestUtils.deposit(amount).then((result) => {
                const returnedValue = result.utxo;
                const { proof } = result;

                const utxoIns = new UTXO(returnedValue);

                const isMineUTXO = utxoIns.checkOwnership(SENDER_WALLET.privateKey);

                expect(isMineUTXO).to.not.equal(null);
                expect(isMineUTXO.amount).to.equal(amount.toString());

                // make sure decoded mask = generated mask
                expect(isMineUTXO.mask).to.equal(proof.mask);

                // validate return commitment from amount,mask -
                expect(
                    Commitment.verifyCommitment(
                        amount,
                        proof.mask,
                        {
                            X: utxoIns.commitmentX,
                            YBit: utxoIns.commitmentYBit,
                        },
                    ),
                ).to.equal(true);

                const expectedCommitment = Commitment.genCommitment(amount, proof.mask).toString('hex');

                expect(
                    Commitment.genCommitmentFromTxPub(amount, {
                        X: utxoIns.txPubX,
                        YBit: utxoIns.txPubYBit,
                    }, sender.privViewKey).toString('hex') === expectedCommitment,
                ).to.equal(true);
                done();
            })
                .catch((err) => {
                    done(err);
                });

        });
    }

    for (let count = 0; count < 2; count++) {
        it('Successful deposit to create decoys', (done) => {
            const { privateKey, address } = WALLETS[2];
            TestUtils.deposit(1000000000, privateKey, address).then(() => {
                done();
            })
                .catch((err) => {
                    done(err);
                });

        });
    }
});
