/* eslint-disable camelcase */
/**
 * The bulletproof implementation bases on https://eprint.iacr.org/2017/1066.pdf
 * please refer below for denoting, we replace some denotes in the paper by our owns
 */

import ecurve from 'ecurve';
import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';

import { BigInteger, randomHex } from './crypto';
import {
    bconcat, toBN, bn2b,
} from './common';
import { baseH } from './commitment';

const secp256k1 = ecurve.getCurveByName('secp256k1');
// const hs = hmacSha256;
const baseG = secp256k1.G;

/**
 * Denote parameters
 */
// Public parameters
const G = baseG;
const H = baseH;
const N = 64; // bitsize of the elements whose range one wants to prove
// const maxM = 16; // number   of   proofs   to   aggregate
const Hi = []; // // a list of M*N generators fo the subgroup of EC
const Gi = []; // a list of M*N generators fo the subgroup of EC

// Value to commit, to hide and prove
// v: a list of M integers such that for all j, 0< v[j] < 2^N
// masks: a list of M integers such that for all j, 0 <= masks[j] < 1

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
        const newPoint = baseG.multiply(BigInteger.fromHex(keccak256(hex)));
        if (secp256k1.isOnCurve(newPoint)) {
            return newPoint;
        }
        hex = keccak256(hex);
    }
};

// export const hash_to_point = (data) => {
//     let result = '';
//     for datum in data:
//         if datum is None:
//             raise TypeError
//         result += hashlib.sha256(str(datum)).hexdigest()
//     while True:
//         result = hashlib.sha256(result).hexdigest()
//         if make_point(int(result,16)) is not None:
//             return make_point(int(result,16))*Scalar(8)
// }

const hashToScalar = data => BigInteger.fromHex(
    keccak256(data),
).mod(
    secp256k1.p,
);

// const getExponent = (base, idx) => base.multiply(
//     BigInteger.fromHex(idx),
// );

// /* Given two scalar arrays, construct a vector commitment */
// const vector_exponent = (a, b) => {
//     assert(a.length == b.length, 'Incompatible sizes of a and b');
//     assert(a.length <= maxN * maxM, 'Incompatible sizes of a and maxN');

//     const multiexp_data = [];
//     for (let i = 0; i < a.length; ++i) {
//         multiexp_data.emplace_back(a[i], Gi_p3[i]);
//         multiexp_data.emplace_back(b[i], Hi_p3[i]);
//     }
//     return multiexp(multiexp_data, 2 * a.length);
// };

/**
 * pedersen commitment for scalar amount with scalar mask
 * @param {*} mask
 * @param {*} amount
 */
const pedersenCommitment = (mask, amount) => G.multiply(
    toBN(mask),
).add(
    H.multiply(
        toBN(amount),
    ),
);

/**
 * mask is a vector instead of a scalar with scalar amount
 * (Gi*aL + Hi*aR + G*mask)
 * @param {*} mask
 * @param {*} amount
 */
const pedersenVectorCommitment = (mask, aL, aR) => {
    let temp = G.multiply(
        toBN(mask),
    );
    _.each(aL, (ali, index) => {
        temp = temp.add(
            Gi[index].multiply(
                toBN(ali),
            ),
        ).add(
            Hi[index].multiply(
                toBN(aR[index]),
            ),
        );
    });

    return temp;
};

/**
 * Calculate inner product of two vector =
 *
 * @param {*} v1
 * @param {*} v2
 */
const innerProduct = (v1, v2) => {
    assert(v1.length === v2.length, 'Incompatible sizes of vector input');
    let sum = BigInteger.ZERO;
    for (let i = 0; i < v1; i++) {
        sum = sum.add(
            toBN(v1[i])
                .mul(
                    toBN(v2[i]),
                ),
        );
    }

    return sum;
};

export const hadamard = (v1, v2) => {
    assert(v1.length === v2.length, 'Incompatible sizes of vector input');
    const result = [];
    for (let i = 0; i < v1; i++) {
        result.push(
            toBN(v1[i])
                .mul(
                    toBN(v2[i]),
                ),
        );
    }

    return result;
};

const vectorSub = (vector, scalar) => _.map(vector, (element, index) => element.sub(scalar[index]));

/**
 * construct a vector from scalar x and n order
 * @param {*} x
 * @param {*} n
 */
const vectorPowers = (x, n) => {
    const res = [];
    if (n === 0) return res;

    res[0] = BigInteger.ONE;

    if (n === 1) return res;

    res[1] = x;
    for (let i = 2; i < n; ++i) {
        res[i] = res[i - 1].mul(x);
    }

    return res;
};

const muladd = (a, b, c) => a.mul(b).add(c);

const vectorAdd = (vector, scalar) => _.map(vector, (element, index) => element.add(scalar[index]));

const range_proof_innerProduct_poly_coeff = (aL, sL, aR, sR, y, z) => {
    const l0 = vectorSub(aL, z);
    const l1 = sL;

    // This computes the ugly sum/concatenation from PAPER LINE 65
    const zero_twos = [];
    const zpow = vectorPowers(z, M + 2);

    for (let i = 0; i < M * N; ++i) {
        zero_twos[i] = BigInteger.ZERO();
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
    r0 = vectorAdd(r0, zero_twos);
    const r1 = hadamard(yMN, sR);

    // Polynomial construction before PAPER LINE 46
    const t1_1 = innerProduct(l0, r1);
    const t1_2 = innerProduct(l1, r0);
    let t1 = BigInteger.ZERO;
    t1 = t1_1.add(t1_2);
    const t2 = innerProduct(l1, r1);

    return {
        t1, t2, r0, r1, l0, l1,
    };
};

const vectorScalar = (a, x) => {
    const res = [];
    for (let i = 0; i < a.size(); ++i) {
        res[i] = a[i].mul(x);
    }
    return res;
};
const range_proof_innerProduct_lhs = (l0, l1, x) => {
    const l = l0;
    return vectorAdd(l, vectorScalar(l1, x));
};

const range_proof_innerProduct_rhs = (r0, r1, x) => {
    let r = r0;
    r = vectorAdd(r, vectorScalar(r1, x));
    return r;
};

const range_proof_innerProduct_poly_hiding_value = (tau1, tau2, masks, x, z) => {
    let taux = tau1.mul(x);
    const xsq = x.mul(x);
    taux = tau2.mul(xsq).add(taux);

    const zpow = vectorPowers(z, M + 2);
    for (let j = 1; j <= masks.length; ++j) {
        assert(j + 1 < zpow.length, 'invalid zpow index');
        taux = zpow[j + 1].mul(masks[j - 1]).add(taux);
    }

    return taux;
};

const l_r_pedersenVectorCommitment_hiding_value = (alpha, rho, x) => x.mul(rho).add(alpha);

const l_r_generators_innerProduct_adapt = (Hip, y) => _.map(Hip, hi => hi.multiply(y));

let M;
const twoN = vectorPowers(BigInteger.fromHex('02'), N);

export default class BulletProof {
    /**
      * Provide amounts and mask for constructing range-proof
      * @param {*} v List amounts in BigNumber (bigi)
      * @param {*} masks
      */
    static prove(v, masks) {
        assert(v.length === masks.length, 'Incompatible sizes of V and masks');

        // Compute V: a list of curve points, Pedersen commitments to v[i]
        // with hiding values masks[i]
        // Compute aL[i] the vector containing the binary representation of v[i]
        // Compute aR[i] the opposite of the complementary to one of aL[i]
        const aL = [];
        const aR = [];
        const V = [];
        M = masks.length; // number of proofs to aggregate

        /**
         * Besides generatorsHandG, two vectors of generators,GiandHi, of sizeM*N (hardcoded con-stantsM=16andN=64)
         * are needed to prove up toMaggregated proofs simultaneously.
         * very element generated is unique thanks to the use of an unique index.
         * The parameters usedto form theseedare simple enough to be harmless.
         * They allow to get rid of any trusted set-up.The use of the hash function ensures there is no discrete log relation between the generators.
         */
        for (let i = 0; i < M * N; ++i) {
            Hi[i] = H.multiply(
                toBN(i * 2),
            );
            Gi[i] = H.multiply(
                toBN(i * 2 + 1),
            );
        }

        for (let j = 0; j < M - 1; j++) {
            V[j] = pedersenCommitment(masks[j], v[j]); // output is a ecurve.Point type
            aL[j] = bn2b(v[j]);
            aR[j] = vectorSub(aL[j], _.map(Array(N), () => 1)); // what the heck is this, what happens if fir al[j][k] = 0
        }

        // Compute A: a curve point, vector commitment to aL and aR with hiding value alpha
        const alpha = BigInteger.fromHex(randomHex());
        const A = pedersenVectorCommitment(alpha, aL, aR); // (Gi*aL + Hi*aR + G*alpha)

        // Compute S: a curve point, vector commitment to sL and sR with hiding value rho
        const sL = _.map(Array(N), () => BigInteger.fromHex(randomHex()));
        const sR = _.map(Array(N), () => BigInteger.fromHex(randomHex()));
        const rho = BigInteger.fromHex(randomHex());
        const S = pedersenVectorCommitment(rho, sL, sR); // (Gi*sL + Hi*sR + G*rho)

        // V is array of Point so we just convert to array of buffer for ready hashing
        const VinBuffer = _.map(V, vi => vi.getEncoded(true));

        // Random challenges to build the inner product to prove the values of aL and aR
        // non-interactive

        const y = hashToScalar(
            bconcat(
                VinBuffer,
                A.getEncoded(true), // A is a point
                S.getEncoded(true), // S is a point
            ),
        ); // y now is Big integer
        const z = hashToScalar(
            bconcat(
                VinBuffer,
                A.getEncoded(true),
                S.getEncoded(true),
                y.toBuffer(),
            ),
        ); // z now is Big integer

        // reconstruct the coefficients of degree 1 and of degree 2 of the
        // range proof inner product polynomial
        const {
            t1, t2, r0, r1, l0, l1,
        } = range_proof_innerProduct_poly_coeff(aL, sL, aR, sR, y, z);

        // Compute T1: a curve point, Pedersen commitment to t1 with hiding value tau1
        const tau1 = BigInteger.fromHex(randomHex());
        const T1 = pedersenCommitment(tau1, t1);

        // Compute T2: a curve point, Pedersen commitment to t2 with hiding value tau2
        const tau2 = BigInteger.fromHex(randomHex());
        const T2 = pedersenCommitment(tau2, t2);

        // Random challenge to prove the commitment to t1 and t2
        //  plus non-interactive
        const x = hashToScalar(V, A, S, y, z, T1, T2);

        // Compute t: a scalar, inner product value to be verified
        const l = range_proof_innerProduct_lhs(l0, l1, x);
        const r = range_proof_innerProduct_rhs(r0, r1, x);
        const t = innerProduct(l, r);

        // Compute taux: a scalar, hiding value related to x.T1, x^2.T2, z^2.V and t
        const taux = range_proof_innerProduct_poly_hiding_value(tau1, tau2, masks, x, z);

        // Compute mu: a scalar, hiding value related to A and x.S
        const mu = l_r_pedersenVectorCommitment_hiding_value(alpha, rho, x);

        // Adapt Hi, the vector of generators
        // to apply an inner product argument of knowledge on l and r
        const Hiprime = l_r_generators_innerProduct_adapt(Hi, y);

        // Random challenge
        // plus non-interactive
        const x_ip = hashToScalar(bconcat([
            V, A, S, y, z, T1, T2, x, taux, mu, t,
        ]));
        const Hx = H.multiply(
            x_ip,
        );

        // Compute L, R, curve points, and a, b, scalars
        // Output of the inner product argument of knowledge
        const {
            L, R, a, b,
        } = this.innerProduct_prove(Hiprime, Hx, l, r);

        return {
            V, A, S, T1, T2, taux, mu, L, R, a, b, t,
        };
    }

    static innerProduct_prove(U, a, b) {
        // n is the size of the input vectors
        let n = M * N;
        let round = 0;
        const L = [];
        const R = [];

        while (n > 1) {
            n /= 2;
            const cL = innerProduct((a.slice(0, n), b.slice(n, 2 * n)));
            const cR = innerProduct(a.slice(n, 2 * n), b.slice(0, n));

            // Compute the intermediate commitments L[round], R[round]
            L[round] = pedersenVectorCommitment(cL, U, concat(slice(a, 0, n), slice(b, n, 2 * n)));
            R[round] = pedersenVectorCommitment(cR, U, concat(slice(a, n, 2 * n), slice(b, 0, n)));

            // Random challenge
            // plus non-interactive
            const w = hashToScalar(L[round], R[round]);

            // Shrink generator vectors
            Gi = hadamard_points(scalar_mul_vector_points(invert(w), slice(Gi, 0, n)), scalar_mul_vector_points(w, slice(Gi, n, 2 * n)));
            Hi = hadamard_points(scalar_mul_vector_points(w, slice(Hi, 0, n)), scalar_mul_vector_points(invert(w), slice(Hi, n, 2 * n)));

            // Shrink scalar vectors
            a = vectorAdd(scalar_mul_vector(w, slice(a, 0, n)), scalar_mul_vector(invert(w), slice(a, n, 2 * n)));
            b = vectorAdd(scalar_mul_vector(invert(w), slice(b, 0, n)), scalar_mul_vector(w, slice(b, n, 2 * n)));
            round++;
        }

        return {
            L,
            R,
            a: a[0],
            b: b[0],
        };
    }

    static verify(proofs) {
        // Checks that the sizes are coherent,
        // that the scalars are reduced,
        // that the points are on the right curve
        // that the points are on the right subgroup
        for (let i = 0; i < proofs.length; i++) {
            if (!bulletproof_early_checks(proof)) { return false; }
        }
        for (let i = 0; i < proofs.length; i++) {
            // Reconstruct the challenges of Lines 49 and 55
            y = hashToScalar(proof.V, proof.A, proof.S);
            y_list = y_list.append(y);
            z = hashToScalar(proof.V, proof.A, proof.S, y);
            z_list = z_list.append(z);
            x = hashToScalar(proof.V, proof.A, proof.S, y, z, proof.T1, proof.T2);
            x_list = x_list.append(x);
            // Check that the commitment to t does indeed correspond to
            // the commitments to t1 (T1) and t2 (T2) and v[i] (V[i])
            // Line 65 (or rather 72)
            if (!check_commitment_innerProduct_poly_coeff(
                proof.t,
                proof.taux,
                proof.V,
                proof.T1,
                proof.T2, x, y, z,
            )
            ) {
                return false;
            }

            // Reconstruct the random challenge, Line 6
            x_ip = hashToScalar(proof.V, proof.A, proof.S, y, z, proof.T1, proof.T2, x, proof.taux, proof.mu, proof.t);
            x_ip_list = x_ip_list.append(x_ip);
        }
        if (!innerProduct_batch_verify(Gi, Hi, H, x_ip_list, y_list, z_list, x_list, prooflist)) {
            return false;
        }

        return true;
    }
}
