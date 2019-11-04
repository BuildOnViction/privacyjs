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

import ecurve from 'ecurve';
import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';

import { BigInteger, randomHex } from './crypto';
import {
    bconcat, toBN, bn2b,
} from './common';
import { basePointH } from './constants';

const secp256k1 = ecurve.getCurveByName('secp256k1');
// const hs = hmacSha256;
const baseG = secp256k1.G;

type InnerProdArg = {
    L: Array<ecurve.Point>,
    R: Array<ecurve.Point>,
    A: BigInteger,
    B: BigInteger,

    Challenges: Array<BigInteger>,
}

/**
 * Denote parameters
 */
// Public parameters
const G = baseG;
const H = basePointH;
const N = 64; // bitsize of the elements whose range one wants to prove
// const maxM = 16; // number   of   proofs   to   aggregate

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
const pedersenCommitment = (mask, amount) => {
    let temp = G.multiply(
        mask,
    );
    const am = typeof amount === 'object' ? amount : toBN(amount);
    if (am.toString('16') !== '0') {
        temp = temp.add(
            H.multiply(
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
const pedersenVectorCommitment = (mask, base, aLR, GiHi) => {
    let temp = base.multiply(
        mask,
    );

    for (let i = 0; i < aLR.length; i++) {
        if (aLR[i] && aLR[i].toString('16') !== '0') {
            temp = temp.add(
                GiHi[i].multiply(
                    aLR[i],
                ),
            );
        }
    }

    return temp;
};

function TwoVectorPCommitWithGens(Gi, Hi, a, b) {
    let commitment;

    for (let i = 0; i < Gi.length; i++) {
        const modA = a[i].mod(secp256k1.n);
        const modB = b[i].mod(secp256k1.n);

        commitment = commitment ? commitment.add(Gi[i].multiply(modA))
            .add(Hi[i].multiply(modB)) : Gi[i].multiply(modA).add(Hi[i].multiply(modB));
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
    let sum = BigInteger.ZERO;
    for (let i = 0; i < v1.length; i++) {
        sum = sum.add(
            v1[i]
                .multiply(
                    v2[i],
                ),
        );
    }

    return sum;
};

export const hadamard = (v1, v2) => {
    assert(v1.length === v2.length, 'Incompatible sizes of vector input');
    const result = [];
    for (let i = 0; i < v1.length; i++) {
        result.push(
            v1[i]
                .multiply(
                    v2[i],
                ),
        );
    }

    return result;
};


// problem the input point is not finity
/* folds a curvepoint array using a two way scaled Hadamard product */
const hadamard_points = (points1, points2) => _.map(points1, (point, index) => point.add(
    points2[index],
));

const vectorSub = (vector, scalar) => _.map(vector, element => element.subtract(scalar));
const vectorSubVector = (vector, vector1) => _.map(vector, (element, index) => element.subtract(vector1[index]));

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
        res[i] = res[i - 1].multiply(x).mod(secp256k1.n);
    }

    return res;
};

// return Array<ecurve.Point>, Array<ecurve.Point>, ECPoint)
function GenerateNewParams(bG: Array<ecurve.Point>, bH: Array<ecurve.Point>, x: BigInteger, L: ecurve.Point, R: ecurve.Point, P: ecurve.Point) {
    const nprime = parseInt(bG.length / 2);

    const Gprime = [];
    const Hprime = [];

    const xinv = x.modInverse(secp256k1.n);

    // Gprime = xinv * G[0, n] + x*G[nprime:]
    // Hprime = x * H[0, n] + xinv*H[nprime:]

    for (let i = 0; i < nprime; i++) {
        Gprime[i] = bG[i].multiply(xinv).add(bG[i + nprime].multiply(x));
        Hprime[i] = bH[i].multiply(x).add(bH[i + nprime].multiply(xinv));
    }

    const x2 = x.multiply(x).mod(secp256k1.n);
    const xinv2 = x2.modInverse(secp256k1.n);

    const Pprime = L.multiply(x2).add(P).add(R.multiply(xinv2)); // x^2 * L + P + xinv^2 * R

    return {
        Gprime, Hprime, Pprime,
    };
}


const muladd = (a, b, c) => a.multiply(b).add(c);

const vectorAddVector = (vector, vector2) => _.map(vector, (element, index) => element.add(vector2[index]));
const vectorAdd = (vector, scalar) => _.map(vector, element => element.add(scalar));

const range_proof_innerProduct_poly_coeff = (aL, sL, aR, sR, y, z) => {
    const l0 = vectorSub(aL, z);
    const l1 = sL;

    // This computes the ugly sum/concatenation from PAPER LINE 65
    const zero_twos = [];
    const zpow = vectorPowers(z, M + 2);

    for (let i = 0; i < M * N; ++i) {
        zero_twos[i] = BigInteger.ZERO;
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

    let t1 = BigInteger.ZERO;
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
        res[i] = a[i].multiply(x);
    }
    return res;
};
const range_proof_innerProduct_lhs = (l0, l1, x) => vectorAddVector(l0, vectorScalar(l1, x));

const range_proof_innerProduct_rhs = (r0, r1, x) => vectorAddVector(r0, vectorScalar(r1, x));

const range_proof_innerProduct_poly_hiding_value = (tau1, tau2, masks, x, z) => {
    let taux = tau1.multiply(x);
    const xsq = x.multiply(x);
    taux = tau2.multiply(xsq).add(taux);

    const zpow = vectorPowers(z, M + 2);
    for (let j = 1; j <= masks.length; ++j) {
        assert(j + 1 < zpow.length, 'invalid zpow index');
        taux = zpow[j + 1].multiply(masks[j - 1]).add(taux);
    }

    return taux;
};

const l_r_pedersenVectorCommitment_hiding_value = (alpha, rho, x) => x.multiply(rho).add(alpha);

const l_r_generators_innerProduct_adapt = (Hip, y) => _.map(Hip, hi => hi.multiply(y));

let M;
const twoN = vectorPowers(BigInteger.fromHex('02'),
    toBN(N));

// the main different between those two function is the parameter type
// but the interface even the code is the same
const scalar_mul_vector_points = (scalar, points) => _.map(points, point => point.multiply(scalar));

const scalar_mul_vector = (scalar, vector) => _.map(vector, element => element.multiply(scalar));

const inner_product_batch_verify = (
    x_ip_list, y_list, z_list, x_list, proofs,
) => {
    //   PERF_TIMER_STOP_BP(VERIFY);

    console.log(H, x_ip_list, y_list, z_list, x_list, proofs);
    throw new Error('Not implemented yet ');
};

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
        let aL = [];
        let aR = [];
        const Hi = [];
        const Gi = [];
        const V = [];
        M = v.length; // number of proofs to aggregate

        // TODO get N from length of d2bn(v)
        // and N should be < 64 (maximum length)

        /**
         * Besides generators H and G, two vectors of generators,Gi and Hi,
         * of size M*N (hardcoded con-stants M = 16 and N=64)
         * are needed to prove up to M aggregated proofs simultaneously.
         * very element generated is unique thanks to the use of an unique index.
         * The parameters used to form the seed are simple enough to be harmless.
         * They allow to get rid of any trusted set-up.The use of the hash function ensures there is no discrete log relation between the generators.
         */

        for (let i = 0; i < M * N; ++i) {
            Hi[i] = H.multiply(
                toBN(i * 2 + 1),
            );
            Gi[i] = G.multiply(
                toBN(i * 2 + 2),
            );
        }

        for (let j = 0; j < M; j++) {
            V[j] = pedersenCommitment(masks[j], v[j]); // output is a ecurve.Point type
            aL[j] = bn2b(v[j], N); // convert v to n bit binary
            aR[j] = vectorSubVector(
                _.map(aL[j], element => toBN(element)),
                _.map(Array(N), () => BigInteger.ONE),
            );
        }

        // flatten aL, aR and convert to BI for easier calculation
        aL = _.map(_.flatten(aL), element => toBN(element));
        aR = _.flatten(aR);

        // hamadard<aL, aR> = 0 not inner product
        // assert(innerProduct(aL, aR).toString('10') === '0', 'Wrong aL, aR !!');

        // Compute A: a curve point, vector commitment to aL and aR with hiding value alpha
        const alpha = BigInteger.fromHex(randomHex());
        const A = pedersenVectorCommitment(alpha, H, [...aL, ...aR], [...Gi, ...Hi]); // (Gi*aL + Hi*aR + H*alpha)

        // Compute S: a curve point, vector commitment to sL and sR with hiding value rho
        const sL = _.map(Array(N * M), () => BigInteger.fromHex(randomHex()));
        const sR = _.map(Array(N * M), () => BigInteger.fromHex(randomHex()));
        const rho = BigInteger.fromHex(randomHex());
        const S = pedersenVectorCommitment(rho, H, [...sL, ...sR], [...Gi, ...Hi]); // (Gi*sL + Hi*sR + H*rho)

        // V is array of Point, convert to array of buffer for ready hashing
        // and used in multi-place
        const VinBuffer = _.map(V, vi => vi.getEncoded(true));

        // Random challenges to build the inner product to prove the values of aL and aR
        // non-interactive
        const y = hashToScalar(
            bconcat([
                ...VinBuffer,
                A.getEncoded(true), // A is a point
                S.getEncoded(true), // S is a point
            ]),
        ); // y now is Big integer
        const z = hashToScalar(
            bconcat([
                ...VinBuffer,
                A.getEncoded(true),
                S.getEncoded(true),
                y.toBuffer(),
            ]),
        ); // z now is Big integer

        let timer1 = new Date().valueOf();
        console.log('\nStart range_proof_innerProduct_poly_coeff ', timer1.valueOf());
        // reconstruct the coefficients of degree 1 and of degree 2 of the
        // range proof inner product polynomial
        const {
            t1, t2, r0, r1, l0, l1,
        } = range_proof_innerProduct_poly_coeff(aL, sL, aR, sR, y, z);

        let timer2 = new Date().valueOf();
        console.log('End range_proof_innerProduct_poly_coeff, time cost %s seconds \n', (timer2.valueOf() - timer1.valueOf()) / 1000);

        timer1 = new Date().valueOf();
        console.log('\nStart range_proof ', timer1.valueOf());
        // Compute T1: a curve point, Pedersen commitment to t1 with hiding value tau1
        const tau1 = BigInteger.fromHex(randomHex());
        const T1 = pedersenCommitment(tau1, t1);

        // Compute T2: a curve point, Pedersen commitment to t2 with hiding value tau2
        const tau2 = BigInteger.fromHex(randomHex());
        const T2 = pedersenCommitment(tau2, t2);

        // Random challenge to prove the commitment to t1 and t2
        //  plus non-interactive
        const x = hashToScalar(
            bconcat([
                ...VinBuffer,
                A.getEncoded(true),
                S.getEncoded(true),
                y.toBuffer(),
                z.toBuffer(),
                T1.getEncoded(true),
                T2.getEncoded(true),
            ]),
        );

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
            ...VinBuffer,
            A.getEncoded(true),
            S.getEncoded(true),
            y.toBuffer(),
            z.toBuffer(),
            T1.getEncoded(true),
            T2.getEncoded(true),
            x.toBuffer(),
            taux.toBuffer(),
            mu.toBuffer(),
            t.toBuffer(),
        ]));

        const Hx = H.multiply(
            x_ip,
        );

        timer2 = new Date().valueOf();
        console.log('End range_proof , time cost %s seconds \n', (timer2.valueOf() - timer1.valueOf()) / 1000);

        timer1 = new Date().valueOf();
        console.log('\nStart range_proof_prove ', timer1.valueOf());
        // Compute L, R, curve points, and a, b, scalars
        // Output of the inner product argument of knowledge
        const {
            L, R, a, b,
        } = this.innerProductProve(Gi, Hiprime, Hx, l, r);

        this.InnerProductProve(l, r, t);
        timer2 = new Date().valueOf();
        console.log('End range_proof_prove , time cost %s seconds \n', (timer2.valueOf() - timer1.valueOf()) / 1000);

        // TODO log proof size at this step
        return {
            V, A, S, T1, T2, taux, mu, L, R, a, b, t,
        };
    }


    // Perform an inner-product proof round
    // need optimize, time cost is too much
    // G,H: PointVector
    // U: Point
    // a,b: ScalarVector
    //
    // returns: G',H',U,a',b',L,R
    static innerProductProve(Gi, Hi, U, a, b) {
        // n is the size of the input vectors
        let n = M * N;
        let round = 0;
        const L = [];
        const R = [];

        try {
            while (n > 1) {
                console.log('Inner Product Prove ', n);
                n /= 2;
                const cL = innerProduct(a.slice(0, n), b.slice(n, a.length));
                const cR = innerProduct(a.slice(n, a.length), b.slice(0, n));

                // Compute the intermediate commitments L[round], R[round]
                L[round] = pedersenVectorCommitment(cL, U,
                    [...a.slice(0, n), ...b.slice(n, a.length)],
                    [...Gi.slice(n, a.length), ...Hi.slice(0, n)]);

                R[round] = pedersenVectorCommitment(cR, U,
                    [...a.slice(n, a.length), ...b.slice(0, n)],
                    [...Gi.slice(0, n), ...Hi.slice(n, a.length)]);

                // Random challenge
                // plus non-interactive
                const w = hashToScalar(bconcat([
                    ...L[round].getEncoded(true),
                    ...R[round].getEncoded(true),
                ]));

                // Shrink generator vectors
                Gi = hadamard_points(
                    scalar_mul_vector_points(BigInteger.ONE.modInverse(w), Gi.slice(0, n)),
                    scalar_mul_vector_points(w, Gi.slice(n, a.length)),
                );
                Hi = hadamard_points(
                    scalar_mul_vector_points(w, Hi.slice(0, n)),
                    scalar_mul_vector_points(BigInteger.ONE.modInverse(w), Hi.slice(n, a.length)),
                );

                // Shrink scalar vectors
                a = vectorAddVector(
                    scalar_mul_vector(w, a.slice(0, n)),
                    scalar_mul_vector(BigInteger.ONE.modInverse(w), a.slice(n, a.length)),
                );
                b = vectorAddVector(
                    scalar_mul_vector(BigInteger.ONE.modInverse(w), a.slice(0, n)),
                    scalar_mul_vector(w, b.slice(n, a.length)),
                );
                round++;
            }
        } catch (err) {
            console.log(err);
        }


        return {
            L,
            R,
            a: a[0],
            b: b[0],
        };
    }

    // Checks that the sizes are coherent,
    // that the scalars are reduced,
    // that the points are on the right curve
    // that the points are on the right subgroup
    static bulletproof_early_checks(proof) {
        return !!proof;
    }

    // // rpresult.IPP = InnerProductProve(left, right, that, P, EC.U, EC.BPG, HPrime)
    static InnerProductProve(a: Array<BigInteger>, b: Array<BigInteger>, c: BigInteger, P: ecurve.Point, U: ecurve.Point, bG : Array<ecurve.Point>, bH: Array<ecurve.Point>): InnerProdArg {
        const loglen = parseInt(Math.log2(a.length));

        const challenges = [];
        const Lvals = [];
        const Rvals = [];

        const runningProof: InnerProdArg = {
            L: Lvals,
            R: Rvals,
            A: BigInteger.ZERO,
            B: BigInteger.ZERO,
            Challenges: challenges,
        };

        // randomly generate an x value from public data
        const x = BigInteger.fromHex(keccak256(P.getEncoded(false).toString('hex'))).mod(secp256k1.n);

        runningProof.Challenges[loglen] = x;

        const Pprime = P.add(U.multiply(x.multiply(c)));
        console.log('Pprime ', Pprime.getEncoded(true).toString('hex'));

        const ux = U.multiply(_.cloneDeep(x));

        return this.InnerProductProveSub(runningProof, bG, bH, a, b, ux, Pprime);
    }

    /* Inner Product Argument
        Proves that <a,b>=c
        This is a building block for BulletProofs
    */
    static InnerProductProveSub(proof: InnerProdArg,
        bG: Array<ecurve.Point>,
        bH: Array<ecurve.Point>,
        a: Array<BigInteger>,
        b: Array<BigInteger>,
        u: ecurve.Point,
        P: ecurve.Point) {
        if (a.length === 1) {
            // Prover sends a & b
            // eslint-disable-next-line prefer-destructuring
            proof.A = a[0];
            // eslint-disable-next-line prefer-destructuring
            proof.B = b[0];
            return proof;
        }

        const curIt = parseInt(Math.log2(a.length)) - 1;

        const nprime = parseInt(a.length / 2);

        const cl = innerProduct(a.slice(0, nprime), b.slice(-nprime));
        const cr = innerProduct(a.slice(-nprime), b.slice(0, nprime));
        // L = pedersenVectorCommitment(cl, u, bG.slice(nprime, a.length), H.slice(0, nprime), a.slice(0, nprime), b.slice(nprime, a.length));
        // R = pedersenVectorCommitment(cr, u, bG.slice(0, nprime), H.slice(nprime, a.length), a.slice(nprime, a.length), b.slice(0, nprime));
        const L = TwoVectorPCommitWithGens(bG.slice(0, nprime), bH.slice(-nprime), a.slice(-nprime), b.slice(0, nprime)).add(u.multiply(cl));
        const R = TwoVectorPCommitWithGens(bG.slice(-nprime), bH.slice(0, nprime), a.slice(0, nprime), b.slice(-nprime)).add(u.multiply(cr));

        proof.L[curIt] = L;
        proof.R[curIt] = R;

        // prover sends L & R and gets a challenge
        // prover sends L & R and gets a challenge
        const w = hashToScalar(bconcat([
            ...L.getEncoded(false),
            ...R.getEncoded(false),
        ]));

        const x = w;

        proof.Challenges[curIt] = x;

        // why do i need to generate new parameter here
        const { Gprime, Hprime, Pprime } = GenerateNewParams(bG, bH, x, L, R, P);

        // fmt.Printf("Prover - Intermediate Pprime value: %s \n", Pprime)
        const xinv = x.modInverse(x, secp256k1.n);

        // or these two lines
        const aprime = vectorAddVector(
            scalar_mul_vector(x, a.slice(-nprime)),
            scalar_mul_vector(xinv, a.slice(0, nprime)),
        );

        const bprime = vectorAddVector(
            scalar_mul_vector(xinv, b.slice(-nprime)),
            scalar_mul_vector(x, b.slice(0, nprime)),
        );

        return this.InnerProductProveSub(proof, Gprime, Hprime, aprime, bprime, u, Pprime);
    }

    static InnerProductVerify(c: BigInteger, P: ecurve.Point, U: ecurve.Point, bG: Array<ecurve.Point>, bH: Array<ecurve.Point>, ipp: InnerProdArg): Boolean {
        // console.log("Verifying Inner Product Argument")
        const s1 = BigInteger.fromHex(keccak256(P.getEncoded(false).toString('hex'))).mod(secp256k1.n);
        const chal1 = s1;

        const ux = U.multiply(chal1);
        let curIt = ipp.Challenges.length - 1;

        if (ipp.Challenges[curIt].compareTo(chal1) !== 0) {
            console.log('IPVerify - Initial Challenge Failed');
            return false;
        }

        curIt -= 1;

        let Gprime = bG;
        let Hprime = bH;
        let Pprime = P.add(ux.multiply(c));// line 6 from protocol 1

        while (curIt >= 0) {
            console.log('IPVerifying to index ', curIt);
            const Lval = ipp.L[curIt];
            const Rval = ipp.R[curIt];

            // prover sends L & R and gets a challenge
            const w = hashToScalar(bconcat([
                ...Lval.getEncoded(false),
                ...Rval.getEncoded(false),
            ]));

            const chal2 = w;

            if (ipp.Challenges[curIt].compareTo(chal2) !== 0) {
                console.log('IPVerify - Challenge verification failed at index ' + curIt);
                return false;
            }

            ({ Gprime, Hprime, Pprime } = GenerateNewParams(Gprime, Hprime, chal2, Lval, Rval, Pprime));
            // Gprime = newParams.Gprime;
            // Hprime = newParams.Hprime;
            // Pprime = newParams.Pprime;

            curIt -= 1;
        }

        const ccalc = ipp.A.multiply(ipp.B).mod(secp256k1.n);

        const Pcalc1 = Gprime[0].multiply(ipp.A);
        const Pcalc2 = Hprime[0].multiply(ipp.B);
        const Pcalc3 = ux.multiply(ccalc);
        const Pcalc = Pcalc1.add(Pcalc2).add(Pcalc3);

        console.log(Pprime.getEncoded(true).toString('hex'));
        console.log(Pcalc.getEncoded(true).toString('hex'));

        if (!Pprime.equals(Pcalc)) {
            console.log('IPVerify - Final Commitment checking failed');
            return false;
        }

        return true;
    }

    static verify(proofs) {
        const Hi = [];
        const Gi = [];
        M = proofs.length; // number of proofs to aggregate
        for (let i = 0; i < M * N; ++i) {
            Hi[i] = H.multiply(
                toBN(i * 2 + 1),
            );
            Gi[i] = H.multiply(
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
            const VinBuffer = _.map(proof.V, vi => vi.getEncoded(true));
            const y = hashToScalar(
                bconcat([
                    ...VinBuffer,
                    proof.A.getEncoded(true),
                    proof.S.getEncoded(true),
                ]),
            );
            y_list = y_list.push(y);
            const z = hashToScalar(
                bconcat([
                    ...VinBuffer,
                    proof.A.getEncoded(true),
                    proof.S.getEncoded(true),
                    y.toBuffer(),
                ]),
            );
            z_list = z_list.push(z);
            const x = hashToScalar(
                bconcat([
                    ...VinBuffer,
                    proof.A.getEncoded(true),
                    proof.S.getEncoded(true),
                    y.toBuffer(),
                    z.toBuffer(),
                    proof.T1.getEncoded(true),
                    proof.T2.getEncoded(true),
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
                    proof.A.getEncoded(true),
                    proof.S.getEncoded(true),
                    y.toBuffer(),
                    z.toBuffer(),
                    proof.T1.getEncoded(true),
                    proof.T2.getEncoded(true),
                    x.toBuffer(),
                    proof.taux.toBuffer(),
                    proof.mu.toBuffer(),
                    proof.t.toBuffer(),
                ]),
            );
            x_ip_list = x_ip_list.push(x_ip);
        }
        if (!inner_product_batch_verify(Gi, Hi, H, x_ip_list, y_list, z_list, x_list, proofs)) {
            return false;
        }

        return true;
    }
}
