/* eslint-disable camelcase */
/**
 * The bulletproof implementation bases on https://eprint.iacr.org/2017/1066.pdf
 * please refer below for denoting, we replace some denotes in the paper by our owns
 * related knowledge
 * inner product
 * inner product proof
 * multi-exponentiation
 *
 */

import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';

import BigInteger from 'bn.js';
import toBN from 'number-to-bn';
import { randomHex } from './crypto';
import InnerProduct from './inner_product';
import {
    bconcat,
} from './common';

// TODO move to one place
BigInteger.fromHex = hexstring => new BigInteger(hexstring, 16);

const ZERO = new BigInteger('0', 16);
const ONE = new BigInteger('01', 2);

const EC = require('elliptic').ec;
// type Point = Curve.short.ShortPoint;

const secp256k1 = new EC('secp256k1');

const baseG = secp256k1.g;
const baseH = secp256k1.curve.point(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    '31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904',
);

const N = 64; // bitsize of the elements whose range one wants to prove
const MAX_2_EXPN = BigInteger.fromHex('0100000000000000000000000000000000');

const bn2b = (bn, size) => {
    let result = bn.toString(2);
    if (size) {
        while (result.length < (size || 2)) { result = '0' + result; }
        return result.split('');
    }
    return result.split('');
};

const genECPrimeGroupKey = (n) => {
    const Gi = [];
    const Hi = [];
    for (let i = 0; i < n; ++i) {
        Hi[i] = baseH.mul(
            toBN(i * 2 + 1),
        );
        Gi[i] = baseG.mul(
            toBN(i * 2 + 2),
        );
    }

    const U = baseG.mul(
        toBN(n + 3),
    );

    return {
        ...secp256k1,
        Gi,
        Hi,
        U,
    };
};


/**
 * Bulletproof is composed of:
 * V: a vector o curve points, = Pedersen commitments to v[i] with hiding values masks[i],
 *    V[i] = G*masks[i] + H*v[i]
 * A: a curve point, vector commitment to aL and aR with hiding value alpha
 * S: a curve point, vector commitment to sL and sR with hiding value rho
 * T1: a curve point, Pedersen commitment to t1 with hiding value tau1
 * T2: a curve point, Pedersen commitment to t2 with hiding value tau2
 * taux: a scalar, hiding value related to T1,T2,V and t
 * mu: a scalar, hiding value related to A and S
 * L: a vector of curve points of size log2(M*N) computed in the inner product protocol
 * R: a vector of curve points of size log2(M*N) computed in the inner product protocol
 * a: a scalar computed in the inner product protocol
 * b: a scalar computed in the inner product protocol
 * t: a scalar, inner product value to be verifie
 */

export const hashToPoint = (shortFormPoint) => {
    assert(shortFormPoint && shortFormPoint.length, 'Invalid input public key to hash');
    let hex = shortFormPoint.substring(2); // ignore first two bit
    while (hex) {
        const newPoint = baseG.mul(BigInteger.fromHex(keccak256(hex)));
        if (secp256k1.isOnCurve(newPoint)) {
            return newPoint;
        }
        hex = keccak256(hex);
    }
};

const hashToScalar = data => BigInteger.fromHex(
    keccak256(data),
).mod(
    secp256k1.n,
);

/**
 * pedersen commitment for scalar amount with scalar mask
 * @param {*} mask
 * @param {*} amount
 */
const pedersenCommitment = (mask, amount) => {
    let temp = baseH.mul(
        mask,
    );
    const am = typeof amount === 'object' ? amount : toBN(amount);
    if (am.toString(16) !== '0') {
        temp = temp.add(
            baseG.mul(
                am,
            ),
        );
    }

    return temp;
};

/**
 * base*mask + aL*Gi + aR*Hi  = base*mask + <aLR,GiHi>
 * @param {*} mask
 * @param {*} amount
 */
// const pedersenVectorCommitment = (mask, base, aLR, GiHi) => {
//     let temp = base.mul(
//         mask,
//     );

//     for (let i = 0; i < aLR.length; i++) {
//         if (aLR[i] && aLR[i].toString(16) !== '0') {
//             temp = temp.add(
//                 GiHi[i].mul(
//                     aLR[i],
//                 ),
//             );
//         }
//     }

//     return temp;
// };

/**
 * TODO move to other libs for add point and calculating BigNumber
 * this func is too messy - need replace by other lib or refactoring
 * @param {*} Gi
 * @param {*} Hi
 * @param {*} a
 * @param {*} b
 */
function TwoVectorPCommitWithGens(Gi, Hi, a, b) {
    let commitment;

    for (let i = 0; i < Gi.length; i++) {
        const modA = a[i].mod(secp256k1.n);
        const modB = b[i].mod(secp256k1.n);

        if (modA.toString(16).length) {
            commitment = commitment ? commitment.add(
                Gi[i].mul(modA),
            ) : Gi[i].mul(modA);
        }

        if (modB.toString(16).length) {
            commitment = commitment ? commitment.add(
                Hi[i].mul(modB),
            ) : Hi[i].mul(modB);
        }

        // commitment = commitment ? commitment.add(
        //     Gi[i].mul(modA),
        // ).add(Hi[i].mul(modB))
        //     : Gi[i].mul(modA).add(Hi[i].mul(modB));
    }

    return commitment;
}


/**
 * Calculate inner product of two vector =
 *
 * @param {*} v1
 * @param {*} v2
 */
const innerProduct = (v1, v2) => {
    assert(v1.length === v2.length, 'Incompatible sizes of vector input');
    let sum = ZERO;
    for (let i = 0; i < v1.length; i++) {
        sum = sum.add(
            v1[i]
                .mul(
                    v2[i],
                ).mod(secp256k1.n),
        );
    }

    return sum.mod(secp256k1.n);
};

export const hadamard = (v1, v2) => {
    assert(v1.length === v2.length, 'Incompatible sizes of vector input');
    const result = [];
    for (let i = 0; i < v1.length; i++) {
        result.push(
            v1[i]
                .mul(
                    v2[i],
                ).mod(secp256k1.n),
        );
    }

    return result;
};


const vectorSub = (vector, scalar) => _.map(vector, element => element.sub(scalar));
const vectorSubVector = (vector, vector1) => _.map(vector, (element, index) => element.sub(vector1[index]));

/**
 * construct a vector from scalar x and n order
 * @param {*} x
 * @param {*} n
 */
const vectorPowers = (x, n) => {
    const res = [];
    if (n === 0) return res;

    res[0] = ONE;

    if (n === 1) return res;

    res[1] = x;
    for (let i = 2; i < n; ++i) {
        res[i] = res[i - 1].mul(x).mod(secp256k1.n);
    }

    return res;
};


const muladd = (a, b, c) => a.mul(b).add(c);

const vectorAddVector = (vector, vector2) => _.map(vector, (element, index) => element.add(vector2[index]).mod(secp256k1.n));
const vectorAdd = (vector, scalar) => _.map(vector, element => element.add(scalar).mod(secp256k1.n));

const range_proof_innerProduct_poly_coeff = (aL, sL, aR, sR, y, z) => {
    const l0 = vectorSub(aL, z);
    const l1 = sL;

    // This computes the ugly sum/concatenation from PAPER LINE 65
    const zero_twos = [];
    const zpow = vectorPowers(z, M + 2);

    for (let i = 0; i < M * N; ++i) {
        zero_twos[i] = ZERO;
        for (let j = 1; j <= M; ++j) {
            if (i >= (j - 1) * N && i < j * N) {
                assert(1 + j < zpow.length, 'invalid zpow index');
                assert(i - (j - 1) * N < twoN.length, 'invalid twoN index');
                zero_twos[i] = muladd(zpow[1 + j], twoN[i - (j - 1) * N], zero_twos[i]);
            }
        }
    }
    let r0 = vectorAdd(aR, z);
    const yMN = vectorPowers(y, M * N);

    r0 = hadamard(r0, yMN);
    r0 = vectorAddVector(r0, zero_twos);
    const r1 = hadamard(yMN, sR);

    // Polynomial construction before PAPER LINE 46

    const t1_1 = innerProduct(l0, r1);
    const t1_2 = innerProduct(l1, r0);

    let t1 = ZERO;
    t1 = t1_1.add(t1_2);
    const t2 = innerProduct(l1, r1);

    return {
        t1, t2, r0, r1, l0, l1,
    };
};

const check_commitment_innerProduct_poly_coeff = (
    t,
    taux,
    V,
    T1,
    T2, x, y, z,
) => {
    console(t,
        taux,
        V,
        T1,
        T2, x, y, z);
    throw new Error('Not implemented yet');
};

const vectorScalar = (a, x) => {
    const res = [];
    for (let i = 0; i < a.length; ++i) {
        res[i] = a[i].mul(x);
    }
    return res;
};
const range_proof_innerProduct_lhs = (l0, l1, x) => vectorAddVector(l0, vectorScalar(l1, x));

const range_proof_innerProduct_rhs = (r0, r1, x) => vectorAddVector(r0, vectorScalar(r1, x));

const range_proof_innerProduct_poly_hiding_value = (tau1, tau2, masks, x, z) => {
    let taux = tau1.mul(x);
    const xsq = x.mul(x);
    taux = tau2.mul(xsq).add(taux).mod(secp256k1.n);

    const zpow = vectorPowers(z, M + 2);
    for (let j = 1; j <= masks.length; ++j) {
        assert(j + 1 < zpow.length, 'invalid zpow index');
        taux = zpow[j + 1].mul(masks[j - 1]).add(taux).mod(secp256k1.n);
    }

    return taux;
};

let M;
const twoN = vectorPowers(BigInteger.fromHex('02'),
    toBN(N));

const inner_product_batch_verify = (
    x_ip_list, y_list, z_list, x_list, proofs,
) => {
    //   PERF_TIMER_STOP_BP(VERIFY);

    console.log(baseH, x_ip_list, y_list, z_list, x_list, proofs);
    throw new Error('Not implemented yet ');
};

export default class BulletProof {
    /**
      * Provide amounts and mask for constructing range-proof
      * @param {*} values List amounts in BigNumber (bigi)
      * @param {*} masks
      */
    static prove(values, masks) {
        assert(values.length === masks.length, 'Incompatible sizes of V and masks');

        // Compute V: a list of curve points, Pedersen commitments to v[i]
        // with hiding values masks[i]
        // Compute aL[i] the vector containing the binary representation of v[i]
        // Compute aR[i] the opposite of the complementary to one of aL[i]
        const MRPResult = {};
        let aL = [];
        let aR = [];
        // const Hi = [];
        // const Gi = [];
        const V = [];
        M = values.length; // number of proofs to aggregate

        /**
         * Besides generators H and G, two vectors of generators,Gi and Hi,
         * of size M*N (hardcoded con-stants M = 16 and N=128)
         * are needed to prove up to M aggregated proofs simultaneously.
         * very element generated is unique thanks to the use of an unique index.
         * The parameters used to form the seed are simple enough to be harmless.
         * They allow to get rid of any trusted set-up.The use of the hash function ensures there is no discrete log relation between the generators.
         */

        // simple generators for testing
        const { Hi, Gi, U } = genECPrimeGroupKey(N);

        for (let j = 0; j < M; j++) {
            if (values[j].cmp(ZERO) < 0) {
                throw new Error('Value is below range! Not proving');
            }

            if (values[j].cmp(
                MAX_2_EXPN,
            ) > 0) {
                throw new Error('Value is above range! Not proving.');
            }

            V[j] = pedersenCommitment(masks[j], values[j]); // output is a Point type
            aL[j] = bn2b(values[j], N); // convert v to n bit binary with padding if needed
            aR[j] = vectorSubVector(
                _.map(aL[j], element => toBN(element)),
                _.map(Array(N), () => ONE),
            );
        }

        MRPResult.Comms = _.map(V, v => v.encode('hex', false).slice(2));

        // flatten aL, aR and convert to BI for easier calculation
        aL = _.map(_.flatten(aL), element => toBN(element));
        aR = _.flatten(aR);

        // hamadard<aL, aR> = 0 not inner product
        assert(innerProduct(aL, aR).toString(10) === '0', 'Wrong aL, aR !!');

        // Compute A: a curve point, vector commitment to aL and aR with hiding value alpha
        const alpha = BigInteger.fromHex(randomHex());
        // const A = pedersenVectorCommitment(alpha, H, [...aL, ...aR], [...Gi, ...Hi]); // (Gi*aL + Hi*aR + H*alpha)
        const A = TwoVectorPCommitWithGens(Gi, Hi, aL, aR).add(baseH.mul(alpha));

        MRPResult.A = A.encode('hex', false).slice(2);

        // Compute S: a curve point, vector commitment to sL and sR with hiding value rho
        const sL = _.map(Array(N * M), () => BigInteger.fromHex(randomHex()));
        const sR = _.map(Array(N * M), () => BigInteger.fromHex(randomHex()));
        const rho = BigInteger.fromHex(randomHex());

        // const S = pedersenVectorCommitment(rho, H, [...sL, ...sR], [...Gi, ...Hi]); // (Gi*sL + Hi*sR + H*rho)
        const S = TwoVectorPCommitWithGens(Gi, Hi, sL, sR).add(baseH.mul(rho));
        MRPResult.S = S.encode('hex', false).slice(2);

        // V is array of Point, convert to array of buffer for ready hashing
        // and used in multi-place
        // const VinBuffer = _.map(V, vi => vi.encode('array', false));

        // Random challenges to build the inner product to prove the values of aL and aR
        // non-interactive
        // const cy = hashToScalar(
        // bconcat([
        //     // ...VinBuffer,
        //     // A.encode('array', false), // A is a point
        //     new Buffer([...A.getX().toBuffer(32), A.getY().toBuffer(32)]),
        //     // S.encode('array', false).slice(1), // S is a point
        // ]),
        // ); // y now is Big integer
        const cy = BigInteger.fromHex(keccak256(A.encode('array', false).slice(1)));

        console.log('in buffer ', cy.toBuffer());

        MRPResult.cy = cy.toString(16);

        // const cz = hashToScalar(
        //     bconcat([
        //         // ...VinBuffer,
        //         // A.encode('array', false).slice(1),
        //         S.encode('array', false).slice(1),
        //         // cy.toBuffer(),
        //     ]),
        // );

        const cz = BigInteger.fromHex(keccak256(S.encode('array', false).slice(1)));

        MRPResult.cz = cz.toString(16);

        // reconstruct the coefficients of degree 1 and of degree 2 of the
        // range proof inner product polynomial
        const {
            t1, t2, r0, r1, l0, l1,
        } = range_proof_innerProduct_poly_coeff(aL, sL, aR, sR, cy, cz);

        // Compute T1: a curve point, Pedersen commitment to t1 with hiding value tau1
        const tau1 = BigInteger.fromHex(randomHex());
        const T1 = pedersenCommitment(tau1, t1);

        MRPResult.T1 = T1.encode('hex', false).slice(2);

        // Compute T2: a curve point, Pedersen commitment to t2 with hiding value tau2
        const tau2 = BigInteger.fromHex(randomHex());
        const T2 = pedersenCommitment(tau2, t2);

        MRPResult.T2 = T2.encode('hex', false).slice(2);

        // Random challenge to prove the commitment to t1 and t2
        //  plus non-interactive
        // const cx = hashToScalar(
        //     bconcat([
        //         // ...VinBuffer,
        //         // A.encode('array', false),
        //         // S.encode('array', false),
        //         // cy.toBuffer(),
        //         // cz.toBuffer(),
        //         T1.encode('array', false).slice(1),
        //         T2.encode('array', false).slice(1),
        //     ]),
        // );
        const cx = BigInteger.fromHex(keccak256([
            ...T1.encode('array', false).slice(1),
            ...T2.encode('array', false).slice(1),
        ]));

        MRPResult.cx = cx.toString(16);

        // Compute t: a scalar, inner product value to be verified
        const l = range_proof_innerProduct_lhs(l0, l1, cx);
        const r = range_proof_innerProduct_rhs(r0, r1, cx);
        const t = innerProduct(l, r);

        MRPResult.Th = t.toString(16);

        // Compute taux: a scalar, hiding value related to x.T1, x^2.T2, z^2.V and t
        const taux = range_proof_innerProduct_poly_hiding_value(tau1, tau2, masks, cx, cz);
        MRPResult.Tau = taux.toString(16);

        // Compute mu: a scalar, hiding value related to A and x.S
        const mu = cx.mul(rho).add(alpha).mod(secp256k1.n);
        MRPResult.Mu = mu.toString(16);

        // Adapt Hi, the vector of generators
        // to apply an inner product argument of knowledge on l and r
        const Hiprime = _.map(Hi, hi => hi.mul(cy));

        // Random challenge
        // plus non-interactive
        // const x_ip = hashToScalar(bconcat([
        //     ...VinBuffer,
        //     A.encode('array', false),
        //     S.encode('array', false),
        //     cy.toBuffer(),
        //     cz.toBuffer(),
        //     T1.encode('array', false),
        //     T2.encode('array', false),
        //     cx.toBuffer(),
        //     taux.toBuffer(),
        //     mu.toBuffer(),
        //     t.toBuffer(),
        // ]));

        // // TODO
        // const Hx = baseH.mul(
        //     x_ip,
        // );

        // Compute L, R, curve points, and a, b, scalars
        // Output of the inner product argument of knowledge
        // const {
        //     L, R, a, b,
        // } = this.innerProductProve(Gi, Hiprime, Hx, l, Hiprime);
        const P = TwoVectorPCommitWithGens(Gi, Hiprime, l, r);

        MRPResult.Ipp = InnerProduct.prove(l, r, t, P, U, Gi, Hiprime);

        // For verifying in SC onley
        // TODO will be remove
        MRPResult.Ipp.L = _.map(MRPResult.Ipp.L, (point) => {
            const pointInHex = point.encode('hex', false).slice(2);
            return {
                x: pointInHex.slice(64),
                y: pointInHex.slice(-64),
            };
        });
        MRPResult.Ipp.R = _.map(MRPResult.Ipp.R, (point) => {
            const pointInHex = point.encode('hex', false).slice(2);
            return {
                x: pointInHex.slice(64),
                y: pointInHex.slice(-64),
            };
        });
        console.log(MRPResult.Ipp.A.toString(10));

        MRPResult.Ipp.A = MRPResult.Ipp.A.toString(16);
        MRPResult.Ipp.B = MRPResult.Ipp.B.toString(16);
        MRPResult.Ipp.Challenges = _.map(MRPResult.Ipp.Challenges, bi => bi.toString(16));

        console.log(JSON.stringify(MRPResult));

        return MRPResult;
    }

    static verify(proofs) {
        const Hi = [];
        const Gi = [];
        M = proofs.length; // number of proofs to aggregate
        for (let i = 0; i < M * N; ++i) {
            Hi[i] = baseH.mul(
                toBN(i * 2 + 1),
            );
            Gi[i] = baseH.mul(
                toBN(i * 2 + 2),
            );
        }

        // easy check
        for (let i = 0; i < proofs.length; i++) {
            if (!this.bulletproof_early_checks(proofs[i])) { return false; }
        }
        let x_ip_list = [];
        let x_list = [];
        let y_list = [];
        let z_list = [];
        for (let i = 0; i < proofs.length; i++) {
            const proof = proofs[i];
            // Reconstruct the challenges of Lines 49 and 55
            const VinBuffer = _.map(proof.V, vi => vi.encode('array', false));
            const y = hashToScalar(
                bconcat([
                    ...VinBuffer,
                    proof.A.encode('array', false),
                    proof.S.encode('array', false),
                ]),
            );
            y_list = y_list.push(y);
            const z = hashToScalar(
                bconcat([
                    ...VinBuffer,
                    proof.A.encode('array', false),
                    proof.S.encode('array', false),
                    y.toBuffer(),
                ]),
            );
            z_list = z_list.push(z);
            const x = hashToScalar(
                bconcat([
                    ...VinBuffer,
                    proof.A.encode('array', false),
                    proof.S.encode('array', false),
                    y.toBuffer(),
                    z.toBuffer(),
                    proof.T1.encode('array', false),
                    proof.T2.encode('array', false),
                ]),
            );
            x_list = x_list.push(x);

            // Check that the commitment to t does indeed correspond to
            // the commitments to t1 (T1) and t2 (T2) and v[i] (V[i])
            // Line 65 (or rather 72)
            if (!check_commitment_innerProduct_poly_coeff(
                proof.t,
                proof.taux,
                proof.V,
                proof.T1,
                proof.T2, x, y, z,
            )) {
                return false;
            }

            // Reconstruct the random challenge, Line 6
            const x_ip = hashToScalar(
                bconcat([
                    ...VinBuffer,
                    proof.A.encode('array', false),
                    proof.S.encode('array', false),
                    y.toBuffer(),
                    z.toBuffer(),
                    proof.T1.encode('array', false),
                    proof.T2.encode('array', false),
                    x.toBuffer(),
                    proof.taux.toBuffer(),
                    proof.mu.toBuffer(),
                    proof.t.toBuffer(),
                ]),
            );
            x_ip_list = x_ip_list.push(x_ip);
        }
        if (!inner_product_batch_verify(Gi, Hi, baseH, x_ip_list, y_list, z_list, x_list, proofs)) {
            return false;
        }

        return true;
    }
}
