/* eslint-disable no-loop-func */
import * as _ from 'lodash';
import chai from 'chai';
// import Web3 from 'web3';
import toBN from 'number-to-bn';
import TestConfig from '../config.json';
import MLSAG_DATA from './mlsag.json';
import MLSAG, { hashToPoint } from '../../src/mlsag';
import Stealth, { toPoint } from '../../src/stealth';
import { hexToNumberString, BigInteger } from '../../src/common';
import UTXO from '../../src/utxo';
import { randomBI } from '../../src/crypto';

import { generateKeys } from '../../src/address';

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[2]; // hold around 1 mil tomo

/**
 * Multilayered linkable spontaneous ad-hoc group signatures test
 * Cover unit test for
 * 1. Hash turn point to point in seccp256k1 ECC
 * 2. MLSAG sign message
 * 3. MLSAG verify signature
 */

// TODO write more test case
describe('#unittest #ringct #mlsag', () => {
    describe('#hashToPoint', () => {
        // because of this randomization, we do this 50 times to make sure
        // it always return new point on hash
        for (let times = 0; times < 5; times++) {
            it('Should turn a hex into a point in seccp256 ECC correctly', (done) => {
                const publicKey = secp256k1.genKeyPair().getPublic().encodeCompressed('hex');
                const newPoint = hashToPoint(publicKey);

                expect(newPoint.validate()).to.be.equal(true);
                done();
            });
        }
    });

    describe('#sign', () => {
        it('Should able to verify signer belong belong to a group', (done) => {
            const sender = new Stealth({
                ...generateKeys(SENDER_WALLET.privateKey),
            });
            const index = 3;

            MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);

            let totalSpending = BigInteger.ZERO();
            const ins = new UTXO(MLSAG_DATA.SPENDING_UTXOS[0]);
            ins.checkOwnership(SENDER_WALLET.privateKey);

            totalSpending = totalSpending.add(
                toBN(ins.decodedAmount),
            );
            const proof = sender.genTransactionProof(
                hexToNumberString(totalSpending.toString(16)),
            );

            const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));
            // console.log('inputUTXOS ', inputUTXOS);
            // console.log('proof.commitment ', proof.commitment);
            // ct ring
            const {
                privKey,
                publicKeys,
            } = MLSAG.genCTRing(
                SENDER_WALLET.privateKey,
                [inputUTXOS],
                [{
                    lfCommitment: toPoint(proof.commitment),
                    decodedMask: proof.mask,
                }],
                index,
            );

            // ring-signature of utxos
            const signature = MLSAG.mulSign(
                [
                    BigInteger.fromHex(ins.privKey), privKey],
                [_.map(inputUTXOS, utxo => utxo.lfStealth), publicKeys],
                index,
            );
            expect(signature.I).not.to.equal(null);
            expect(signature.c1).not.to.equal(null);
            expect(signature.s).not.to.equal(null);

            expect(
                MLSAG.verifyMul(
                    [_.map(inputUTXOS, utxo => utxo.lfStealth), publicKeys],
                    signature.I,
                    signature.c1,
                    signature.s,
                ),
            ).to.be.equal(true);

            done();
        });

    });

    it('Should not able to verify a privatekey not in ring', (done) => {
        const index = 3;

        MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);

        const ins = new UTXO(MLSAG_DATA.SPENDING_UTXOS[0]);
        ins.checkOwnership(SENDER_WALLET.privateKey);

        const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));

        // ring-signature of utxos
        const signature = MLSAG.mulSign(
            [
                randomBI()],
            [_.map(inputUTXOS, utxo => utxo.lfStealth)],
            index,
        );
        expect(signature.I).not.to.equal(null);
        expect(signature.c1).not.to.equal(null);
        expect(signature.s).not.to.equal(null);

        expect(
            MLSAG.verifyMul(
                [_.map(inputUTXOS, utxo => utxo.lfStealth)],
                signature.I,
                signature.c1,
                signature.s,
            ),
        ).to.be.equal(false);

        done();
    });

});
