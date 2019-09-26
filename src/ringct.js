// import * as _ from 'lodash';
// // import { keccak256 as Hash, sha3_256 as sha3 } from 'js-sha3';
// // import crypto from './crypto';
// // import * as common from './common';

// // const assert = require('assert');
// // const bs58 = require('bs58');
// // const ecurve = require('ecurve');
// // const aesjs = require('aes-js');

// // const ecparams = ecurve.getCurveByName('secp256k1');
// // const { Point } = ecurve;
// // const { BigInteger } = crypto;

// // The initialization vector (must be 16 bytes) for ctr aes256 encrypt/decrypt
// // const aesIv = [27, 34, 23, 26, 33, 31, 24, 22, 19, 30, 49, 11, 36, 35, 59, 21];

// class RingCT {
//     // def sumCi(Cis):
//     // CSum = MiniNero.identity()
//     // for i in Cis:
//     //     CSum = MiniNero.addKeys(CSum, i)
//     // return CSum

//     //proveRange and verRange
//     //proveRange gives C, and mask such that \sumCi = C
//     //   c.f. http:#eprint.iacr.org/2015/1098 section 5.1
//     //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
//     //   thus this proves that "amount" is in [0, 2^ATOMS]
//     //   mask is a such that C = aG + bH, and b = amount
//     //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
//     //"prove" returns a rangeSig (list) containing a list [L1, s2, s] and a key64 list [C0, C1, ..., C64] of keys, it also returns C = sum(Ci) and mask, which in the c++ version are returned by reference
//     //inputs key C, key mask, number amount
//     //"ver" returns true or false, and inputs a key, and a rangesig list "as"
//     //  proveRange(amount):
//     //     bb = d2b(amount, ATOMS) #gives binary form of bb in "digits" binary digits
//     //     print("amount, amount in binary", amount, bb)
//     //     ai = [None] * len(bb)
//     //     Ci = [None] * len(bb)
//     //     CiH = [None] * len(bb) #this is like Ci - 2^i H
//     //     H2 = getH2ForCT()
//     //     a = MiniNero.sc_0()
//     //     ii = [None] * len(bb)
//     //     indi = [None] * len(bb)
//     //     for i in range(0, ATOMS):
//     //         ai[i] = PaperWallet.skGen()
//     //         a = MiniNero.addScalars(a, ai[i]) #creating the total mask since you have to pass this to receiver...
//     //         if bb[i] == 0:
//     //             Ci[i] =  MiniNero.scalarmultBase(ai[i])
//     //         if bb[i] == 1:
//     //             Ci[i] = MiniNero.addKeys(MiniNero.scalarmultBase(ai[i]), H2[i])
//     //         CiH[i] = MiniNero.subKeys(Ci[i], H2[i])

//     //     A = asnlSig()
//     //     A.L1, A.s2, A.s = AggregateSchnorr.GenASNL(ai, Ci, CiH, bb)

//     //     R = rangeSig()
//     //     R.asig = A
//     //     R.Ci = Ci

//     //     mask = a
//     //     C = sumCi(Ci)
//     //     return C, mask, R

//     //  verRange(Ci, ags):
//     //     n = ATOMS
//     //     CiH = [None] * n
//     //     H2 = getH2ForCT()
//     //     for i in range(0, n):
//     //         CiH[i] = MiniNero.subKeys(ags.Ci[i], H2[i])
//     //     return AggregateSchnorr.VerASNL(ags.Ci, CiH, ags.asig.L1, ags.asig.s2, ags.asig.s)

//     //Ring-ct MG sigs
//     //Prove:
//     //   c.f. http:#eprint.iacr.org/2015/1098 section 4. definition 10.
//     //   This does the MG sig on the "dest" part of the given key matrix, and
//     //   the last row is the sum of input commitments from that column - sum output commitments
//     //   this shows that sum inputs = sum outputs
//     //Ver:
//     //   verifies the above sig is created corretly
//     //  proveRctMG(pubs, inSk, outSk, outPk, index):
//     //     //pubs is a matrix of ctkeys [P, C]
//     //     //inSk is the keyvector of [x, mask] secret keys
//     //     //outMasks is a keyvector of masks for outputs
//     //     //outPk is a list of output ctkeys [P, C]
//     //     //index is secret index of where you are signing (integer)
//     //     //returns a list (mgsig) [ss, cc, II] where ss is keymatrix, cc is key, II is keyVector of keyimages

//     //     //so we are calling MLSAG2.MLSAG_Gen from here, we need a keymatrix made from pubs
//     //     //we also need a keyvector made from inSk
//     //     rows = len(pubs[0])
//     //     cols = len(pubs)
//     //     print("rows in mg", rows)
//     //     print("cols in mg", cols)
//     //     M = MLSAG2.keyMatrix(rows + 1, cols) #just a simple way to initialize a keymatrix, doesn't need to be random..
//     //     sk = MLSAG2.keyVector(rows + 1)

//     //     for j in range(0, cols):
//     //         M[j][rows] = MiniNero.identity()
//     //     sk[rows] = MiniNero.sc_0()
//     //     for i in range(0, rows):
//     //         sk[i] = inSk[i].dest #get the destination part
//     //         sk[rows] = MiniNero.sc_add_keys(sk[rows], inSk[i].mask) #add commitment part
//     //         for j in range(0, cols):
//     //             M[j][i] = pubs[j][i].dest # get the destination part
//     //             M[j][rows] = MiniNero.addKeys(M[j][rows], pubs[j][i].mask) #add commitment part
//     //     //next need to subtract the commitment part of all outputs..
//     //     for j in range(0, len(outSk)):
//     //         sk[rows] = MiniNero.sc_sub_keys(sk[rows], outSk[j].mask)
//     //         for i in range(0, len(outPk)):
//     //             M[j][rows] = MiniNero.subKeys(M[j][rows], outPk[i].mask) # subtract commitment part
//     //     MG = mgSig()
//     //     MG.II, MG.cc, MG.ss = MLSAG2.MLSAG_Gen(M, sk, index)

//     //     return MG #mgSig

//     //  verRctMG(MG, pubs, outPk):
//     //     //mg is an mgsig (list [ss, cc, II] of keymatrix ss, keyvector II and key cc]
//     //     //pubs is a matrix of ctkeys [P, C]
//     //     //outPk is a list of output ctkeys [P, C] for the transaction
//     //     //returns true or false
//     //     rows = len(pubs[0])
//     //     cols = len(pubs)
//     //     M = MLSAG2.keyMatrix(rows + 1, cols) #just a simple way to initialize a keymatrix, doesn't need to be random..
//     //     for j in range(0, cols):
//     //         M[j][rows] = MiniNero.identity()
//     //     for i in range(0, rows):
//     //         for j in range(0, cols):
//     //             M[j][i] = pubs[j][i].dest # get the destination part
//     //             M[j][rows] = MiniNero.addKeys(M[j][rows], pubs[j][i].mask) #add commitment part
//     //     //next need to subtract the commitment part of all outputs..
//     //     for j in range(0, cols):
//     //         for i in range(0, len(outPk)):
//     //             M[j][rows] = MiniNero.subKeys(M[j][rows], outPk[i].mask) # subtract commitment part
//     //     return MLSAG2.MLSAG_Ver(M, MG.II, MG.cc, MG.ss)

//     //These functions get keys from blockchain
//     //replace these when connecting blockchain
//     //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
//     //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
//     //   the return value are the key matrix, and the index where inPk was put (random).
//     //  getKeyFromBlockchain(reference_index):
//     //     //returns a ctkey a (randomly)
//     //     rv = ctkey()
//     //     rv.dest = PaperWallet.pkGen()
//     //     rv.mask = PaperWallet.pkGen()
//     //     return rv

//     //  populateFromBlockchain(inPk, mixin):
//     //     //returns a ckKeyMatrix with your public input keys at "index" which is the second returned parameter.
//     //     //the returned ctkeyMatrix will have number of columns = mixin
//     //     rv = [None] * mixin
//     //     index = rand.getrandbits(mixin - 1)
//     //     blockchainsize = 10000
//     //     for j in range(0, mixin):
//     //         if j != index:
//     //             rv[j] = [getKeyFromBlockchain(rand.getrandbits(blockchainsize)) for i in range(0, len(inPk))]
//     //         else:
//     //             rv[j] = inPk
//     //     return rv, index


//     //Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
//     // where C= aG + bH
//     //  ecdhEncode(unmasked, receiverPk):
//     //     rv = ecdhTuple()
//     //     //compute shared secret
//     //     esk, rv.senderPk =  PaperWallet.skpkGen()
//     //     sharedSec1 = MiniNero.cn_fast_hash(MiniNero.scalarmultKey(receiverPk, esk));
//     //     sharedSec2 = MiniNero.cn_fast_hash(sharedSec1)
//     //     //encode
//     //     rv.mask = MiniNero.sc_add_keys(unmasked.mask, sharedSec1)
//     //     rv.amount = MiniNero.sc_add_keys(unmasked.amount, sharedSec1)
//     //     return rv

//     //  ecdhDecode(masked, receiverSk):
//     //     rv = ecdhTuple()
//     //     //compute shared secret
//     //     sharedSec1 = MiniNero.cn_fast_hash(MiniNero.scalarmultKey(masked.senderPk, receiverSk))
//     //     sharedSec2 = MiniNero.cn_fast_hash(sharedSec1)
//     //     //encode
//     //     rv.mask = MiniNero.sc_sub_keys(masked.mask, sharedSec1)
//     //     rv.amount = MiniNero.sc_sub_keys(masked.amount, sharedSec1)
//     //     return rv

//     //RingCT protocol
//     //genRct:
//     //   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
//     //   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
//     //   Also contains masked "amount" and "mask" so the receiver can see how much they received
//     //verRct:
//     //   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
//     //decodeRct: (c.f. http:#eprint.iacr.org/2015/1098 section 5.1.1)
//     //   uses the attached ecdh info to find the amounts represented by each output commitment
//     //   must know the destination private key to find the correct amount, else will return a random number

//     genRct(inSk, inPk, destinations, amounts, mixin) {
//         rv = rctSig()
//         rv.outPk = ctkeyV(len(destinations))
//         rv.rangeSigs = [None] * len(destinations)
//         outSk = ctkeyV(len(destinations))
//         rv.ecdhInfo = [None] * len(destinations)
//         for i in range(0, len(destinations)):
//             rv.ecdhInfo[i] = ecdhTuple()
//         rv.outPk[i] = ctkey()
//         rv.outPk[i].dest = destinations[i]
//         rv.outPk[i].mask, outSk[i].mask, rv.rangeSigs[i] = proveRange(amounts[i])
//         //do ecdhinfo encode / decode
//         rv.ecdhInfo[i].mask = outSk[i].mask
//         rv.ecdhInfo[i].amount = MiniNero.intToHex(amounts[i])
//         rv.ecdhInfo[i] = ecdhEncode(rv.ecdhInfo[i], destinations[i])
//         rv.mixRing, index = populateFromBlockchain(inPk, mixin)
//         rv.MG = proveRctMG(rv.mixRing, inSk, outSk, rv.outPk, index)
//         return rv
//     }
//     //inputs:
//     //inSk is signers secret ctkeyvector
//     //inPk is signers public ctkeyvector
//     //destinations is a keyvector of output addresses
//     //amounts is a list of amounts corresponding to above output addresses
//     //mixin is an integer which is the desired mixin
//     //outputs:
//     //rctSig is a list [ rangesigs, MG, mixRing, ecdhInfo, outPk]
//     //rangesigs is a list of one rangeproof for each output
//     //MG is the mgsig [ss, cc, II]
//     //mixRing is a ctkeyMatrix
//     //ecdhInfo is a list of masks / amounts for each output
//     //outPk is a vector of ctkeys (since we have computed the commitment for each amount)


// // def verRct(rv):
// //     //inputs:
// //     //rv is a list [rangesigs, MG, mixRing, ecdhInfo, outPk]
// //     //rangesigs is a list of one rangeproof for each output
// //     //MG is the mgsig [ss, cc, II]
// //     //mixRing is a ctkeyMatrix
// //     //ecdhInfo is a list of masks / amounts for each output
// //     //outPk is a vector of ctkeys (since we have computed the commitment for each amount)
// //     //outputs:
// //     //true or false
// //     rvb = True
// //     tmp = True
// //     for i in range(0, len(rv.outPk)):
// //         tmp = verRange(rv.outPk[i].mask, rv.rangeSigs[i])
// //         print(tmp)
// //         rvb = rvb and tmp
// //     mgVerd = verRctMG(rv.MG, rv.mixRing, rv.outPk)
// //     print(mgVerd)
// //     return (rvb and mgVerd)

// // def decodeRct(rv, sk, i):
// //     //inputs:
// //     //rctSig is a list [ rangesigs, MG, mixRing, ecdhInfo, outPk]
// //     //rangesigs is a list of one rangeproof for each output
// //     //MG is the mgsig [ss, cc, II]
// //     //mixRing is a ctkeyMatrix
// //     //ecdhInfo is a list of masks / amounts for each output
// //     //outPk is a vector of ctkeys (since we have computed the commitment for each amount)
// //     //sk is the secret key of the receiver
// //     //i is the index of the receiver in the rctSig (in case of multiple destinations)
// //     //outputs:
// //     //the amount received
// //     decodedTuple = ecdhDecode(rv.ecdhInfo[i], sk)
// //     mask = decodedTuple.mask
// //     amount = decodedTuple.amount
// //     C = rv.outPk[i].mask
// //     H = getHForCT()
// //     Ctmp = MiniNero.addKeys(MiniNero.scalarmultBase(mask), MiniNero.scalarmultKey(H, amount))
// //     if (MiniNero.subKeys(C, Ctmp) != MiniNero.identity()):
// //         print("warning, amount decoded incorrectly, will be unable to spend")
// //     return MiniNero.hexToInt(amount)

// }

// export default RingCT;
