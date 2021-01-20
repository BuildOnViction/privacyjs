/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */
import Web3 from 'web3';
import HDWalletProvider from '@truffle/hdwallet-provider';
import chai from 'chai';
import toBN from 'number-to-bn';
import * as _ from 'lodash';
import TestConfig from '../config.json';
import * as CONSTANT from '../../src/constants';
import UTXO from '../../src/utxo';
import Wallet from '../../src/wallet';
import { toHex, padLeft, BigInteger } from '../../src/common';
import MLSAG, { keyImage } from '../../src/mlsag'; // hold around 1 mil tomo

import FAKE_DATA from './fake_utxos.json';
import PROOF from './proof.json';

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0];

const pvk = '6378de134e758bd024ccaf0e6d5508f4911ba57d2c1e79d15c099d0d7f285a8d';
let privacyContract;
const provider = new HDWalletProvider(pvk, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

privacyContract = new web3.eth.Contract(
    TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
        from: SENDER_WALLET.address, // default from address
        gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
        gas: '20000000',
    },
);

async function privateSend(proof) {
    return new Promise((resolve, reject) => {
        const randomPrivatekey = Web3.utils.randomHex(32).slice(2);

        const provider = new HDWalletProvider(randomPrivatekey, TestConfig.RPC_END_POINT);
        const web3 = new Web3(provider);
        const account = web3.eth.accounts.privateKeyToAccount(`0x${randomPrivatekey}`);

        const { address } = account;

        const privacyContract = new web3.eth.Contract(
            TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
                from: SENDER_WALLET.address, // default from address
                gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
                gas: '20000000',
            },
        );
        privacyContract.methods.privateSend(...proof)
            .send({
                from: address,
            })
            .on('error', (error) => {
                reject(error);
            })
            .then((receipt) => {
                resolve(receipt.events);
            });
    });
}

async function generateFakeDecoys(utxosIndexs) {
    return new Promise((resolve, reject) => {
        privacyContract.methods.getUTXOs(
            utxosIndexs[0],
        )
            .call()
            .then((utxos) => {
                utxos = _.map(utxos, (raw, index) => {
                    const utxoData = _.cloneDeep(raw);
                    utxoData.index = utxosIndexs[parseInt(index)];
                    // console.log(utxoData);
                    return new UTXO({ ...utxoData });
                });
                resolve(utxos);
            }).catch((exception) => {
                reject(exception);
            });
    });
}


describe('#ete #keyimages', async () => {
    it('Successful deposit to to privacy account', async () => {
        const wallet = new Wallet(pvk, {});

        let balance = toBN(0);
        const totalUTXOs = FAKE_DATA.map((raw) => {
            const utxo = new UTXO(raw);
            balance = balance.add(
                toBN(raw.decodedAmount),
            );
            utxo.checkOwnership(pvk);

            return utxo;
        });
        wallet.state({
            balance,
            utxos: totalUTXOs,
            scannedTo: 200,
        });
        // extract sending UTXOs
        const amountInTomoP = '1000000000';
        const biAmount = toBN(amountInTomoP);
        const {
            utxos,
        } = wallet.getSpendingUTXO(
            biAmount,
            false,
        );
        // Get decoying UTXOs
        const decoysIndex = wallet.getDecoys(utxos.length, _.map(utxos, utxo => utxo.index));
        const decoys = await generateFakeDecoys(decoysIndex);

        // make Send Proof
        const proofs = wallet.genWithdrawProof('0xa865c293d64C5580efFbfef24D62bae0328614D2', amountInTomoP, [decoys], '');

        return proofs;
    });


});
