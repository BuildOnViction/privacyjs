/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */

import chai from 'chai';
import TestConfig from '../config.json';
import * as TestUtils from '../utils';
import Commitment from '../../src/commitment';
import UTXO from '../../src/utxo';
import Wallet from '../../src/wallet';
import * as _ from 'lodash';
import { toHex, padLeft, BigInteger } from '../../src/common';
import MLSAG, { keyImage } from '../../src/mlsag';

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

describe('#ete #keyimages', async() => {
    it('Successful deposit to to privacy account', async (done) => {
        const wallet = new Wallet("cd25bd45c6e276ceebb2a939c44f36cd7fa83681e2319c3ce9fe31167ad19924", {
            RPC_END_POINT: TestConfig.RPC_END_POINT,
            ABI: TestConfig.PRIVACY_ABI,
            ADDRESS: "0x773f08511DCd7cF4cf259C3D3Bf102a85B81487C",
        }, WALLETS[0].address);

        let utxos = await wallet.getUTXOs([75]);
        console.log(
            Buffer.from(_.map(utxos, (utxo) => {
                utxo = new UTXO(utxo)
                const ringctKeys = utxo.getRingCTKeys("cd25bd45c6e276ceebb2a939c44f36cd7fa83681e2319c3ce9fe31167ad19924");
                return keyImage(
                    BigInteger.fromHex(ringctKeys.privKey),
                    utxo.lfStealth.encode('hex', false).slice(2),
                ).encode('hex', true);
            }).join(''), 'hex')
        )

        utxos[0] = new UTXO(utxos[0])
        utxos[0].checkOwnership("cd25bd45c6e276ceebb2a939c44f36cd7fa83681e2319c3ce9fe31167ad19924");
        console.log(
            utxos[0]
        )
        const isSpent = await wallet.isSpent(utxos[0])

        console.log(isSpent)

            // const privKey = this.addresses.privSpendKey;
        // const utxos = _.map(rawUTXOs, utxo => new UTXO(utxo));
        
        

        done()
    })
    

});
