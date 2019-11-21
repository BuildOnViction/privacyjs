/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */

import chai from 'chai';
import * as _ from 'lodash';
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

const amount = 10000000000000000000;
const sender = new Stealth({
    ...Address.generateKeys(SENDER_WALLET.privateKey),
});

describe('#ete #deposit', () => {
    for (let count = 0; count < 10; count++) {
        // eslint-disable-next-line no-loop-func
        it('Successful deposit to to privacy account', (done) => {
            TestUtils.deposit(amount).then((result) => {
                const returnedValue = result.utxo;
                const { proof } = result;

                const utxoIns = new UTXO(returnedValue);

                const isMineUTXO = utxoIns.checkOwnership(SENDER_WALLET.privateKey);

                // make sure SC doesn't change anything
                expect(proof.encryptedAmount).to.equal(utxoIns.amount);
                expect(isMineUTXO).to.not.equal(null);
                expect(isMineUTXO.amount).to.equal(amount.toString());

                // make sure decoded mask = generated mask
                expect(utxoIns.mask).to.equal(proof.encryptedMask);
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
                    utxoIns.lfCommitment.getEncoded(true).toString('hex') === expectedCommitment,
                ).to.equal(true);
                done();
            })
                .catch((err) => {
                    done(err);
                });

        });
    }

    for (let count = 0; count < 5; count++) {
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
