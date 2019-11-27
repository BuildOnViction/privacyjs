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
import toBN from 'number-to-bn';
import { BigInteger } from './constants';
import InnerProduct from './inner_product';
import { randomBI } from './crypto';

// const BigInteger.TWO() = new BigInteger('10', 2);
// const BigInteger.ZERO() = new BigInteger('0', 16);
// const ONE = new BigInteger('01', 2);

const EC = require('elliptic').ec;
// type Point = Curve.short.ShortPoint;

const secp256k1 = new EC('secp256k1');

const baseG = secp256k1.g;
const baseH = secp256k1.curve.point(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    '31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904',
);

const N = 64; // bitsize of the elements whose range one wants to prove
const MAX_2_EXPN = BigInteger.fromHex('FFFFFFFFFFFFFFFF');

/**
 * Convert a BigNumber to little-endian style with buffer
 * @param {BigInteger} bn
 * @param {number} [size]
 * @returns {String}
 */
const bn2b = (bn : BigInteger, size: ?number) : String => {
    let result = bn.toString(2);

    if (size) {
        while (result.length < (size || 2)) { result = '0' + result; }
        return result.split('').reverse();
    }
    return result.split('').reverse();
};

/**
 * Generate generator parameters base on maximum bit support
 * @param {number} n Maximum bits support
 * @returns {Gi, Hi, U}
 */
const genECPrimeGroupKey = (n: number) : Object => {
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
        Gi,
        Hi,
        U,
    };
};

const vectorSum = (y) => {
    const result = BigInteger.ZERO();

    for (let j = 0; j < y.length; j++) {
        result.iadd(
            toBN(y[j]),
        ).mod(secp256k1.n);
    }

    return result;
};


const DeltaMRP = (y, z, m) => {
    let result = BigInteger.ZERO();

    // (z-z^2)<1^n, y^n>
    const z2 = z.mul(z).mod(secp256k1.n);
    const t1 = z.sub(z2).mod(secp256k1.n);
    const t2 = t1.mul(vectorSum(y)).mod(secp256k1.n);

    // \sum_j z^3+j<1^n, 2^n>
    // <1^n, 2^n> = 2^n - 1
    const po2sum = BigInteger.TWO().pow(toBN(N)).mod(secp256k1.n).sub(BigInteger.ONE());
    let t3 = BigInteger.ZERO();

    for (let j = 0; j < m; j++) {
        const zp = z.pow(
            toBN(3 + j),
        ).mod(secp256k1.n);
        const tmp1 = zp.mul(po2sum).mod(secp256k1.n);
        t3 = t3.add(tmp1).mod(secp256k1.n);
    }

    result = t2.sub(t3).mod(secp256k1.n);

    return result;
};


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
 * TODO move to other libs for add point and calculating BigNumber
 * this func is too messy - need replace by other lib or refactoring
 * @param {*} Gi
 * @param {*} Hi
 * @param {*} a
 * @param {*} b
 */
function twoVectorPCommitWithGens(Gi, Hi, a, b) {
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
    let sum = BigInteger.ZERO();
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

const vectorSub = (vector, scalar) => _.map(vector, element => element.sub(scalar).mod(secp256k1.n));
const vectorSubVector = (vector, vector1) => _.map(vector, (element, index) => element.sub(vector1[index]).mod(secp256k1.n));

/**
 * construct a vector from scalar x and n order
 * @param {*} x
 * @param {*} n
 */
const vectorPowers = (x, n) => {
    const res = [];
    if (n === 0) return res;

    res[0] = BigInteger.ONE();

    if (n === 1) return res;

    res[1] = x;
    for (let i = 2; i < n; ++i) {
        res[i] = res[i - 1].mul(x).mod(secp256k1.n);
    }

    return res;
};


const muladd = (a, b, c) => a.mul(b).add(c).mod(secp256k1.n);

const vectorAddVector = (vector, vector2) => _.map(vector, (element, index) => element.add(vector2[index]).mod(secp256k1.n));
const vectorAdd = (vector, scalar) => _.map(vector, element => element.add(scalar).mod(secp256k1.n));

const rangeProofInnerProductPolyCoeff = (aL, sL, aR, sR, y, z) => {
    const l0 = vectorSub(aL, z);
    const l1 = sL;

    // This computes the ugly sum/concatenation from PAPER LINE 65
    const zeroTwos = [];
    const zpow = vectorPowers(z, M + 2);

    for (let i = 0; i < M * N; ++i) {
        zeroTwos[i] = BigInteger.ZERO();
        for (let j = 1; j <= M; ++j) {
            if (i >= (j - 1) * N && i < j * N) {
                assert(1 + j < zpow.length, 'invalid zpow index');
                assert(i - (j - 1) * N < twoN.length, 'invalid twoN index');
                zeroTwos[i] = muladd(zpow[1 + j], twoN[i - (j - 1) * N], zeroTwos[i]);
            }
        }
    }
    let r0 = vectorAdd(aR, z);
    const yMN = vectorPowers(y, M * N);

    r0 = hadamard(r0, yMN);
    r0 = vectorAddVector(r0, zeroTwos);
    const r1 = hadamard(yMN, sR);

    // Polynomial construction before PAPER LINE 46
    const t1P1 = innerProduct(l0, r1);
    const t1P2 = innerProduct(l1, r0);

    let t1 = BigInteger.ZERO();
    t1 = t1P1.add(t1P2).mod(secp256k1.n);
    const t2 = innerProduct(l1, r1).mod(secp256k1.n);

    return {
        t1, t2, r0, r1, l0, l1, yMN,
    };
};

const hashToScalar = (array: Array<Number>) : BigInteger => BigInteger.fromHex(keccak256(array));

const vectorScalar = (a, x) => {
    const res = [];
    for (let i = 0; i < a.length; ++i) {
        res[i] = a[i].mul(x).mod(secp256k1.n);
    }
    return res;
};
const rangeProofInnerProductLhs = (l0, l1, x) => vectorAddVector(l0, vectorScalar(l1, x));

const rangeProofInnerProductRhs = (r0, r1, x) => vectorAddVector(r0, vectorScalar(r1, x));

const rangeProofInnerProductPolyHidingValue = (tau1, tau2, masks, x, z) => {
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

export default class BulletProof {
    /**
      * Provide amounts and mask for constructing range-proof
      * @param {*} values List amounts in BigNumber (bigi)
      * @param {*} masks
      */
    static prove(values, masks) {
        assert(values.length === masks.length, 'Incompatible sizes of V and masks');

        const MRPResult = {};
        let aL = [];
        let aR = [];
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

        // TODO improve the trusted setup
        const { Hi, Gi, U } = genECPrimeGroupKey(M * N);

        for (let j = 0; j < M; j++) {
            if (values[j].cmp(BigInteger.ZERO()) < 0) {
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
                _.map(Array(N), () => BigInteger.ONE()),
            );
        }

        // MRPResult.Comms = _.map(V, v => v.encode('hex', false).slice(2));
        MRPResult.Comms = V;
        // flatten aL, aR and convert to BI for easier calculation
        aL = _.map(_.flatten(aL), element => toBN(element));
        aR = _.flatten(aR);

        // hamadard<aL, aR> = 0 not inner product
        assert(innerProduct(aL, aR).toString(10) === '0', 'Wrong aL, aR !!');

        // Compute A: a curve point, vector commitment to aL and aR with hiding value alpha
        const alpha = randomBI();
        const A = twoVectorPCommitWithGens(Gi, Hi, aL, aR).add(baseH.mul(alpha));

        // MRPResult.A = A.encode('hex', false).slice(2);
        MRPResult.A = A;

        // Compute S: a curve point, vector commitment to sL and sR with hiding value rho
        const sL = _.map(Array(N * M), () => randomBI());
        const sR = _.map(Array(N * M), () => randomBI());
        const rho = randomBI();

        const S = twoVectorPCommitWithGens(Gi, Hi, sL, sR).add(baseH.mul(rho));

        // MRPResult.S = S.encode('hex', false).slice(2);
        MRPResult.S = S;

        // V is array of Point, convert to array of buffer for ready hashing
        // and used in multi-place
        let VinBuffer = _.flatten(_.map(V, vi => vi.encode('array', false).slice(1)));

        // Random challenges to build the inner product to prove the values of aL and aR
        // non-interactive
        VinBuffer = VinBuffer.concat(
            A.encode('array', false).slice(1),
            S.encode('array', false).slice(1),
        );

        const cy = hashToScalar(
            VinBuffer,
        );

        // MRPResult.cy = cy.toString(16);
        MRPResult.cy = cy;

        VinBuffer = VinBuffer.concat(cy.toArray('be', 32));
        const cz = hashToScalar(
            VinBuffer,
        );

        // MRPResult.cz = cz.toString(16);
        MRPResult.cz = cz;

        // reconstruct the coefficients of degree 1 and of degree 2 of the
        // range proof inner product polynomial
        const {
            t1, t2, r0, r1, l0, l1, yMN,
        } = rangeProofInnerProductPolyCoeff(aL, sL, aR, sR, cy, cz);

        // Compute T1: a curve point, Pedersen commitment to t1 with hiding value tau1
        const tau1 = randomBI();
        const T1 = pedersenCommitment(tau1, t1);

        // MRPResult.T1 = T1.encode('hex', false).slice(2);
        MRPResult.T1 = T1;

        // Compute T2: a curve point, Pedersen commitment to t2 with hiding value tau2
        const tau2 = randomBI();
        const T2 = pedersenCommitment(tau2, t2);

        // MRPResult.T2 = T2.encode('hex', false).slice(2);
        MRPResult.T2 = T2;

        // Random challenge to prove the commitment to t1 and t2
        //  plus non-interactive
        VinBuffer = VinBuffer.concat(cz.toArray('be', 32), T1.encode('array', false).slice(1), T2.encode('array', false).slice(1));
        const cx = hashToScalar(
            VinBuffer,
        );

        // MRPResult.cx = cx.toString(16);
        MRPResult.cx = cx;

        // Compute t: a scalar, inner product value to be verified
        const l = rangeProofInnerProductLhs(l0, l1, cx);
        const r = rangeProofInnerProductRhs(r0, r1, cx);
        const t = innerProduct(l, r);

        // MRPResult.Th = t.toString(16);
        MRPResult.Th = t;

        // Compute taux: a scalar, hiding value related to x.T1, x^2.T2, z^2.V and t
        const taux = rangeProofInnerProductPolyHidingValue(tau1, tau2, masks, cx, cz);
        // MRPResult.Tau = taux.toString(16);
        MRPResult.Tau = taux;

        // Compute mu: a scalar, hiding value related to A and x.S
        const mu = cx.mul(rho).add(alpha).mod(secp256k1.n);
        // MRPResult.Mu = mu.toString(16);
        MRPResult.Mu = mu;

        // Adapt Hi, the vector of generators
        // to apply an inner product argument of knowledge on l and r
        const Hiprime = _.map(Hi, (hi, index) => hi.mul(
            yMN[index].invm(secp256k1.n),
        ));

        const P = twoVectorPCommitWithGens(Gi, Hiprime, l, r);

        MRPResult.Ipp = InnerProduct.prove(l, r, t, P, U, Gi, Hiprime);

        // MRPResult.Ipp.L = _.map(MRPResult.Ipp.L, (point) => {
        //     const pointInHex = point.encode('hex', false).slice(2);
        //     return {
        //         x: pointInHex.slice(0, 64),
        //         y: pointInHex.slice(-64),
        //     };
        // });
        // MRPResult.Ipp.R = _.map(MRPResult.Ipp.R, (point) => {
        //     const pointInHex = point.encode('hex', false).slice(2);
        //     return {
        //         x: pointInHex.slice(0, 64),
        //         y: pointInHex.slice(-64),
        //     };
        // });

        // MRPResult.Ipp.A = MRPResult.Ipp.A.toString(16);
        // MRPResult.Ipp.B = MRPResult.Ipp.B.toString(16);
        // MRPResult.Ipp.Challenges = _.map(MRPResult.Ipp.Challenges, bi => bi.toString(16));

        // console.log(JSON.stringify(MRPResult));
        return MRPResult;
    }

    static verify(mrp) : Boolean {
        M = mrp.Comms.length;
        let VinBuffer = _.flatten(_.map(mrp.Comms, vi => vi.encode('array', false).slice(1)));
        VinBuffer = VinBuffer.concat(
            mrp.A.encode('array', false).slice(1),
            mrp.S.encode('array', false).slice(1),
        );

        const cy = hashToScalar(
            VinBuffer,
        );

        if (cy.cmp(mrp.cy) !== 0) {
            console.log('MRPVerify - Challenge Cy failing!');
            return false;
        }

        VinBuffer = VinBuffer.concat(cy.toArray('be', 32));
        const cz = hashToScalar(
            VinBuffer,
        );

        if (cz.cmp(mrp.cz) !== 0) {
            console.log('MRPVerify - Challenge Cz failing!');
            return false;
        }

        VinBuffer = VinBuffer.concat(cz.toArray('be', 32), mrp.T1.encode('array', false).slice(1), mrp.T2.encode('array', false).slice(1));
        const cx = hashToScalar(
            VinBuffer,
        );

        if (cx.cmp(mrp.cx) !== 0) {
            console.log('RPVerify - Challenge Cx failing!');
            return false;
        }

        const yMN = vectorPowers(cy, M * N);
        const lhs = pedersenCommitment(mrp.Tau, mrp.Th);

        let commPowers; //= secp256k1.curve.zero;
        const zMN = vectorPowers(cz, M + 2);
        const z2 = cz.mul(cz).mod(secp256k1.n);

        for (let j = 0; j < M; j++) {
            if (commPowers) {
                commPowers = commPowers.add(
                    mrp.Comms[j].mul(
                        z2.mul(zMN[j]),
                    ),
                );
            } else {
                commPowers = mrp.Comms[j].mul(
                    z2.mul(zMN[j]),
                );
            }
        }

        // TODO implement my own way
        const rhs = secp256k1.g.mul(DeltaMRP(yMN, cz, M)).add(
            mrp.T1.mul(cx),
        ).add(
            mrp.T2.mul(cx.mul(cx)),
        ).add(commPowers);

        if (!lhs.encode('hex', true) === rhs.encode('hex', true)) {
            console.log('MRPVerify - Uh oh! Check line (63) of verification');
            console.log(rhs);
            console.log(lhs);
            return false;
        }

        let tmp1;
        const zneg = cz.neg().mod(secp256k1.n);

        const { Hi, Gi, U } = genECPrimeGroupKey(M * N);

        for (let i = 0; i < M * N; i++) {
            if (tmp1) {
                tmp1 = tmp1.add(Gi[i].mul(zneg));
            } else { tmp1 = Gi[i].mul(zneg); }
        }

        const powerOfTwos = vectorPowers(BigInteger.TWO(), M * N);
        let tmp2;

        // generate h'
        const HPrime = [];

        for (let i = 0; i < M * N; i++) {
            const mi = yMN[i].invm(secp256k1.n);
            HPrime[i] = Hi[i].mul(mi);
        }

        for (let j = 0; j < M; j++) {
            for (let i = 0; i < N; i++) {
                const val1 = cz.mul(yMN[j * N + i]);
                const zp = cz.pow(
                    toBN(2 + j),
                ).mod(secp256k1.n);
                const val2 = zp.mul(powerOfTwos[i]).mod(secp256k1.n);
                if (tmp2) {
                    tmp2 = tmp2.add(HPrime[j * N + i].mul(val1.add(val2)));
                } else {
                    tmp2 = HPrime[j * N + i].mul(val1.add(val2));
                }
            }
        }

        // without subtracting this value should equal muCH + l[i]G[i] + r[i]H'[i]
        // we want to make sure that the innerproduct checks out, so we subtract it
        const P = mrp.A.add(mrp.S.mul(cx)).add(tmp1).add(tmp2).add(baseH.mul(mrp.Mu).neg());

        if (!InnerProduct.verify(mrp.Th, P, U, Gi, HPrime, mrp.Ipp)) {
            console.log('MRPVerify - Uh oh! Check line (65) of verification!');
            return false;
        }

        return true;
    }
}
