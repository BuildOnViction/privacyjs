import assert from 'assert';
import chai from 'chai';
import Wallet from '../../src/wallet';
import Configs from '../config.json';
import * as CONSTANT from '../../src/constants';
import UTXO from '../../src/utxo';

const { expect } = chai;
chai.should();

const { WALLETS } = Configs;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

describe('#unittest #wallet', () => {
    describe('#init()', () => {
        it('should not able to init wallet with wrong from private key', (done) => {
            try {
                const wallet = new Wallet(`${SENDER_WALLET.privateKey}AA`);
                console.log(wallet);
            } catch (exception) {
                expect(exception.toString()).to.be.equal('AssertionError [ERR_ASSERTION]: Malform private key !!');
                done();
            }
        });

        it('should able to init wallet from private key', (done) => {
            const wallet = new Wallet(SENDER_WALLET.privateKey, {
                RPC_END_POINT: Configs.RPC_END_POINT,
                ABI: Configs.PRIVACY_ABI,
                ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
                gasPrice: '250000000',
                gas: '2000000',
            }, SENDER_WALLET.address);

            expect(wallet.addresses).to.not.equal(null);
            expect(wallet.addresses.privSpendKey.length).to.equal(CONSTANT.PRIVATE_KEY_LENGTH);
            expect(wallet.addresses.privViewKey.length).to.equal(CONSTANT.PRIVATE_KEY_LENGTH);
            expect(wallet.addresses.pubSpendKey.length).to.equal(CONSTANT.SHORT_FORM_CURVE_POINT);
            expect(wallet.addresses.pubViewKey.length).to.equal(CONSTANT.SHORT_FORM_CURVE_POINT);
            expect(wallet.addresses.pubAddr.length).to.equal(CONSTANT.PRIVACY_ADDRESS_LENGTH);

            done();
        });
    });

    describe('#deposit()', () => {
        const wallet = new Wallet(SENDER_WALLET.privateKey, {
            RPC_END_POINT: Configs.RPC_END_POINT,
            ABI: Configs.PRIVACY_ABI,
            ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
            gasPrice: '250000000',
            gas: '2000000',
        }, SENDER_WALLET.address);

        it('should able to create a belonging utxo', (done) => {
            // should move to before
            const proof = wallet._genUTXOProof(1000000000);
            const utxo = new UTXO({
                0: {
                    0: proof[0], // ignore the commitment cuz we don't check it
                    1: proof[0],
                    2: proof[2],
                },
                1: {
                    0: proof[1], // ignore the commitment cuz we don't check it
                    1: proof[1],
                    2: proof[3],
                },
                2: {
                    0: proof[5],
                    1: proof[6],
                },
                3: 10, // index of UTXO
            });
            let decodedUTXO = utxo.checkOwnership(SENDER_WALLET.privateKey);
            expect(decodedUTXO).to.not.equal(null);
            expect(decodedUTXO.amount).to.not.equal(1000000000);

            // make sure other can't decode
            decodedUTXO = utxo.checkOwnership(WALLETS[1].privateKey);
            expect(decodedUTXO).to.equal(null);

            done();
        });
        it('should able to deposit', (done) => {
            done(new Error('Not implemented yet'));
        });
    });

    describe('#withdraw()', () => {
        it('should able to withdraw', (done) => {
            done(new Error('Not implemented yet'));
        });
    });

    describe('#send()', () => {
        it('should able to send', (done) => {
            done(new Error('Not implemented yet'));
        });
    });
});
