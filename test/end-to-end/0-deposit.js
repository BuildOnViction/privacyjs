/**
 * End To End tests using tomochain testnet deployed smart-contract, change config in ./test/config.json ./test/config.json
 */

import TestConfig from '../config.json';
import chai from 'chai';
import TestUtils from '../utils';
import Address from '../../src/address';
import Stealth from '../../src/stealth';
import Commitment from '../../src/commitment';
import UTXO from '../../src/utxo';

const expect = chai.expect;
chai.should();

const WALLETS = TestConfig.WALLETS;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

const amount = 1000000000000000000;
let sender = new Stealth({
    ...Address.generateKeys(SENDER_WALLET.privateKey)
})

describe('#deposit', () => {
    for (var count = 0; count < 1; count++) {
        it('Successful deposit to to privacy account', (done) => {
            TestUtils.deposit(amount).then((result) => {
                let returnedValue = result.utxo;
                let proof = result.proof;

                let utxoIns = new UTXO(returnedValue);

                let isMineUTXO = utxoIns.isMineUTXO(SENDER_WALLET.privateKey);

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
                            YBit: utxoIns.commitmentYBit
                        }
                    )
                ).to.equal(true);

                let expectedCommitment = Commitment.genCommitment(amount, proof.mask).toString('hex');
                
                expect(
                    Commitment.genCommitmentFromTxPub(amount, {
                        X: utxoIns.txPubX,
                        YBit: utxoIns.txPubYBit
                    }, sender.privViewKey).toString('hex') === expectedCommitment
                ).to.equal(true);
                done();
            })
            .catch(function(err){
                done(err);
            });

        });
    }
});
