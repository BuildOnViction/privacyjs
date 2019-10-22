/* eslint-disable max-len */
// eslint-disable-next-line max-len
// 0x0000000000000002000000000000000ab532dcc3b57dee190245c8430ceaae86a52d5a3738e76b3ce7d10c48f216128a95acda6d062063881f91c15e41be152d6ca18de6c7c7fabaaac3347fba917d529ecfa068fc69f6da08827237b5b9556aa70417a2307d2fc6fe6c3c7995014166ace68e84e38fc891182e3f96501e6438532d0c288608705d3ec09aff12dbae39c7bc5f5af712f215a6718a9a36add97f3d6d79cc6232bd9de554ed707524dcfc26eb38951a532ef97e88100c1d4c45a86777ce832bc71e303d2f53619fa709bc0d87b5e5789279709739644c411b8ed2bc90d8bc0841f2ad06d1f5a3d0109dd6cfc4ff0738811c12e1e6cef95e84e7aff74762ee7509ae0379d3e92f74871a132fbe61c7611cd42a7f72b890a17e3f58db1a7215303a41e269f4a34477c68edd2bf65885db70ee4fc66abd334aef3f5a49ccf0c5ecc442db6d7d984100eb28f8ace51309e44ce9d8938457febe9626e3b1085776707596ab15b7f33493bc0fa90fefcca2a7e812783242144ca4313754cdc1216c114d615d5f964cf74a1727894f0c51eb9ffd89b1e17cb5ccde4035c7d88c928099053ffa3787be2a30f87adead75f8e06f3373ae90b7ad1bebeb6a1f88ba0b1cb2ce2095a15ca1b84938decb5abfba48ae748b4cad24553818bd68eea66902ba28ce36a6b9e294416372e8c5369dfa7b85818c1ea91dc1a94e1faad05d52b61e5499ccb3528a82d993c1a32c23c5039ad9500885701338d33abbcc4e5282b86d60fb70d32473aff96e215552f1eacac8f941867c2afe9d0844dd0ae1dd5a10453bae3d8a0e17e8488e3c4e3e310f2de23bc51a34f317d24d95d5ebffa40b577f3e3e78a7b6a9c1fc200b34daebd5a5b8820d5e0b6e913cdf3cc927f1c1205036829f87a037a4621023115daa69904c6fce8ee9b37ef1281626a6609d591df6a85ac71add5e81467ed56a957a40291ae04afebab2aaf7fc71bc7a8fcf6d36eb84c989a7c9745c5b8d10d2ed920345cff6cc7f577b83683c5fc889f77b9e2572d3e40a7f854f7c5e5a5f0eea063803adff46889cc01925a69ea309272461a1592b19acf37f4b57ae413ea3198e58cd0223cc5cfe8601c66ddbfae58d00f4e1df1567142215b2dab4e5a618e288b091ad0391d6d548b4e555bbc862e94092be267accf12755bd311f43eaaa34b026a97b21022723146eb8bd86454307ea3913c2309efa0cc852f867de579262bad944e22615021a94ef801e285b5dab2d3f671cb3de05982cff3d67ce20178e5107a040a59d9902412fe2365e4fab6aae3309c12b40ed6e702b80fa330212e1b70bdafbe4f4b81d02916c5712e31e580e049d6f24048fe595680b03609276a612d25f527243a6aded03edc4882c872bd3258b10db4e02241394253296a6ff83aad1408bfa278af9c646020adf5955ee0204244e6f0a774fc114cfb63891f1bd142d1bcd942e6cddb8f0fd02f7bfa1e5f70b09f7308b312592c9652d81c5507017748fc3d944283b745afad4039a4941c6a6ea3f8a866047db8f8f8e9ac08b9ffa8b3ac9a7470e8fe45c169f28025997ef06008b5fe1503c0a50211becd2817f085d6d314d75f738e5209fd2a350034ed69c8dbb5af9d2129132f47da174e3fafd95ae2873e894fcdaa1b057278f75036ee379e0005e078100b093a98c0eb056745ef9a3b81b80efba5eff9000d79d4d02d12737caff7b0c6b86dd8f0f79b770b3c33d2c63c2f2bc54baa6d126f8684c420209ac7982b523b96f0a1ad2517e54843fe832229787239fa82610f84614b697e6032424fd4178decdca61441e8951eab4213c8e12ea25acab759c026de5b335725f0330bf820b06cbc287189ef60d22b7541bb7953120545fe64b41b230380b24544202bc6203a4c35196d7ae27d4726d6aaa3d3719d4bbfd0734505ca39b466067b80603e784e716d64f19efec5433cdb4676ab9c3009d4d7ce10c00938cd9442dd010490384c5ca6631613e656ed9e562b221fa0e2d34481234553500cb7eafc2bd379ff7
/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */
import Web3 from 'web3';
import chai from 'chai';
import assert from 'assert';
import HDWalletProvider from 'truffle-hdwallet-provider';
import numberToBN from 'number-to-bn';
import * as _ from 'lodash';
import TestConfig from '../config.json';
import * as TestUtils from '../utils';
import MLSAG from '../../src/mlsag';
import UTXO from '../../src/utxo.js';
import RINGCT_DATA from './ringct.json';

const BN = require('bn.js');

const { expect } = chai;
chai.should();

const { RINGCT_PRECOMPILED_CONTRACT, WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

const TOMO = 1000000000000000000;

// load single private key as string
const provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

const privacyContract = new web3.eth.Contract(
    RINGCT_PRECOMPILED_CONTRACT.ABI, RINGCT_PRECOMPILED_CONTRACT.ADDRESS, {
        from: SENDER_WALLET.address, // default from address
        gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
        gas: '2000000',
    },
);

describe('#ringct #verify', () => {
    it('Successful create single ring-signature', (done) => {
        // TestUtils.depositNTimes(12, TOMO).then((utxos) => {
        //     const index = 3;
        const pubkeys = [[]];
        //     const signature = MLSAG.mulSign(
        //         '',
        //         SENDER_WALLET.privateKey,
        //         [utxos.slice(0, 1)],
        //         index,
        //     );

        //     expect(signature.I).not.to.equal(null);
        //     expect(signature.c1).not.to.equal(null);
        //     expect(signature.s).not.to.equal(null);

        //     console.log(
        //         numberToBN(1).toString(16, 16)
        //             + numberToBN(12).toString(16, 16)
        //             + numberToBN(1000).toString(16, 64)
        //             + signature.c1.toString(16, 64)
        //             + _.map(_.flatten(signature.s), element => element.toString(16, 64)).join('')
        //             + _.map(_.flatten(pubkeys), pubkey => new BN(
        //                 pubkey.getEncoded(true).toString('hex'), 16,
        //             ).toString(16, 64)).join('')
        //             + _.map(_.flatten(signature.I), element => element.toString(16, 64)).join(''),
        //     );
        const index = 3;
        RINGCT_DATA.NOISING_UTXOS.splice(index, 0, RINGCT_DATA.SPENDING_UTXOS[0]);

        const inputUTXOS = _.map(RINGCT_DATA.NOISING_UTXOS, (ut) => {
            const utxo = new UTXO(ut);
            pubkeys[0].push(
                utxo.lfStealth,
            );
            return utxo;
        });

        const signature = MLSAG.mulSign(
            '',
            SENDER_WALLET.privateKey,
            [inputUTXOS],
            index,
        );

        const sendingBytes = `${numberToBN(1).toString(16, 16)
        }${numberToBN(12).toString(16, 16)
        }${numberToBN(0).toString(16, 64)
        }${signature.c1.toHex(32)
        }${_.map(_.flatten(signature.s), element => element.toHex(32)).join('')
        }${_.map(_.flatten(pubkeys), pubkey => pubkey.getEncoded(true).toString('hex')).join('')
        }${_.map(_.flatten(signature.I), element => element.getEncoded(true).toString('hex')).join('')}`;

        assert(sendingBytes.length === (16 + 16 + 64 + 64 + 12 * 64 + 66 * 12 + 66), 'Wrong calculation bytes');

        expect(signature.I).not.to.equal(null);
        expect(signature.c1).not.to.equal(null);
        expect(signature.s).not.to.equal(null);

        // self verify
        expect(
            MLSAG.verifyMul(
                '',
                [inputUTXOS],
                signature.I,
                signature.c1,
                signature.s,
            ),
        ).to.be.equal(true);

        console.log(sendingBytes);

        // verify on Smart-contract
        privacyContract.methods.VerifyRingCT(
            Buffer.from(sendingBytes, 'hex'),
        )
            .send({
                from: SENDER_WALLET.address,
            })
            .then((receipt) => {
                console.log(receipt);
                done();
            })
            .catch((error) => {
                console.log(error);
                done(error);
            });
        // });
    });

    it('Successful create single commitment-ring', (done) => {
        const pubkeys = [[]];
        const index = 3;
        RINGCT_DATA.NOISING_UTXOS.splice(index, 0, RINGCT_DATA.SPENDING_UTXOS[0]);

        const inputUTXOS = _.map(RINGCT_DATA.NOISING_UTXOS, (ut) => {
            const utxo = new UTXO(ut);
            pubkeys[0].push(
                utxo.lfStealth,
            );
            return utxo;
        });

        const signature = MLSAG.signCommitment(
            SENDER_WALLET.privateKey,
            [inputUTXOS],
            index,
        );

        const sendingBytes = `${numberToBN(1).toString(16, 16)
        }${numberToBN(12).toString(16, 16)
        }${numberToBN(0).toString(16, 64)
        }${signature.c1.toHex(32)
        }${_.map(_.flatten(signature.s), element => element.toHex(32)).join('')
        }${_.map(_.flatten(pubkeys), pubkey => pubkey.getEncoded(true).toString('hex')).join('')
        }${_.map(_.flatten(signature.I), element => element.getEncoded(true).toString('hex')).join('')}`;

        assert(sendingBytes.length === (16 + 16 + 64 + 64 + 12 * 64 + 66 * 12 + 66), 'Wrong calculation bytes');

        expect(signature.I).not.to.equal(null);
        expect(signature.c1).not.to.equal(null);
        expect(signature.s).not.to.equal(null);

        // self verify
        expect(
            MLSAG.verifyMul(
                '',
                [inputUTXOS],
                signature.I,
                signature.c1,
                signature.s,
            ),
        ).to.be.equal(true);

        // verify on Smart-contract
        privacyContract.methods.VerifyRingCT(
            Buffer.from(sendingBytes, 'hex'),
        )
            .send({
                from: SENDER_WALLET.address,
            })
            .then((receipt) => {
                console.log(receipt);
                done();
            })
            .catch((error) => {
                console.log(error);
                done(error);
            });
        // });
    });

    it('Successful create 5 rings', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Successful create 10 rings', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Unsuccessful validate a ring', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Successful create 1 ring ct', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Should reject tx with commitment from negative value', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Should reject tx with used-ring', (done) => {
        done(new Error('Not implemented yet'));
    });
});
