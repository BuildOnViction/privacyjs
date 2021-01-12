// import '@babel/polyfill';
import toBN from 'number-to-bn';
import Stealth from './stealth';
import Commitment from './commitment';
import * as Address from './address';
import * as common from './common';
import * as Crypto from './crypto';
import UTXO from './utxo';
import Wallet from './wallet';

export default {
    Stealth,
    Address,
    common,
    Crypto,
    UTXO,
    Commitment,
    Wallet,
    toBN,
};
