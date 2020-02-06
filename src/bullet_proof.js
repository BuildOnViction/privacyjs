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
import { BigInteger, innerProduct, twoVectorPCommitWithGens } from './common';
import InnerProduct from './inner_product';
import { randomBI } from './crypto';


const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

// TODO refactoring
const baseH = secp256k1.g;
const baseG = secp256k1.curve.point(
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
        Hi[i] = baseG.mul(
            toBN(i * 2 + 1),
        );
        Gi[i] = baseH.mul(
            toBN(i * 2 + 2),
        );
    }

    const U = baseH.mul(
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
        ).umod(secp256k1.n);
    }

    return result;
};


const DeltaMRP = (y, z, m) => {
    let result = BigInteger.ZERO();

    // (z-z^2)<1^n, y^n>
    const z2 = z.mul(z).umod(secp256k1.n);
    const t1 = z.sub(z2).umod(secp256k1.n);
    const t2 = t1.mul(vectorSum(y)).umod(secp256k1.n);

    // \sum_j z^3+j<1^n, 2^n>
    // <1^n, 2^n> = 2^n - 1
    const po2sum = BigInteger.TWO().pow(toBN(N)).umod(secp256k1.n).sub(BigInteger.ONE());
    let t3 = BigInteger.ZERO();

    for (let j = 0; j < m; j++) {
        const zp = z.pow(
            toBN(3 + j),
        ).umod(secp256k1.n);
        const tmp1 = zp.mul(po2sum).umod(secp256k1.n);
        t3 = t3.add(tmp1).umod(secp256k1.n);
    }

    result = t2.sub(t3).umod(secp256k1.n);

    return result;
};


/**
 * Pedersen commitment for scalar amount with scalar mask
 * notice this is not the way the ./commitment generate
 * return H*Mask + G*Value
 * @param {BigInteger} mask
 * @param {BigInteger} amount
 * @returns {secp256k1.curve.point}
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
 * Calculate hadamard of two vector
 * return hadamard[i] = v1[i]*v2[i]
 * @param {Array<BigInteger>} v1
 * @param {Array<BigInteger>} v2
 * @returns {Array<BigInteger>}
 */

const hadamard = (v1, v2) => {
    assert(v1.length === v2.length, 'Incompatible sizes of vector input');
    const result = [];
    for (let i = 0; i < v1.length; i++) {
        result.push(
            v1[i]
                .mul(
                    v2[i],
                ).umod(secp256k1.n),
        );
    }

    return result;
};

const vectorSub = (vector, scalar) => _.map(vector, element => element.sub(scalar).umod(secp256k1.n));
const vectorSubVector = (vector, vector1) => _.map(vector, (element, index) => element.sub(vector1[index]).umod(secp256k1.n));

/**
 * Construct a vector from scalar x and n order
 * @param {BigInteger} x
 * @param {number} n vector length
 * @returns{Array<BigInteger>} [1, x, x^2, ..., x^n]
 */
const vectorPowers = (x, n) => {
    const res = [];
    if (n === 0) return res;

    res[0] = BigInteger.ONE();

    if (n === 1) return res;

    res[1] = x;
    for (let i = 2; i < n; ++i) {
        res[i] = res[i - 1].mul(x).umod(secp256k1.n);
    }

    return res;
};


const muladd = (a, b, c) => a.mul(b).add(c).umod(secp256k1.n);
const vectorAddVector = (vector, vector2) => _.map(vector, (element, index) => element.add(vector2[index]).umod(secp256k1.n));
const vectorAdd = (vector, scalar) => _.map(vector, element => element.add(scalar).umod(secp256k1.n));

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
    t1 = t1P1.add(t1P2).umod(secp256k1.n);
    const t2 = innerProduct(l1, r1).umod(secp256k1.n);

    return {
        t1, t2, r0, r1, l0, l1, yMN,
    };
};

const hashToScalar = (array: Array<Number>) : BigInteger => BigInteger.fromHex(keccak256(array));

const vectorScalar = (a, x) => {
    const res = [];
    for (let i = 0; i < a.length; ++i) {
        res[i] = a[i].mul(x).umod(secp256k1.n);
    }
    return res;
};
const rangeProofInnerProductLhs = (l0, l1, x) => vectorAddVector(l0, vectorScalar(l1, x));

const rangeProofInnerProductRhs = (r0, r1, x) => vectorAddVector(r0, vectorScalar(r1, x));

const rangeProofInnerProductPolyHidingValue = (tau1, tau2, masks, x, z) => {
    let taux = tau1.mul(x);
    const xsq = x.mul(x);
    taux = tau2.mul(xsq).add(taux).umod(secp256k1.n);

    const zpow = vectorPowers(z, M + 2);
    for (let j = 1; j <= masks.length; ++j) {
        assert(j + 1 < zpow.length, 'invalid zpow index');
        taux = zpow[j + 1].mul(masks[j - 1]).add(taux).umod(secp256k1.n);
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

        assert([1, 2, 4, 8].indexOf(M) >= 0, 'Not support inputs length (just 1, 2, 4, 8)');

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

        // MRPResult.
        MRPResult.Comms = V;
        // flatten aL, aR and convert to BI for easier calculation
        aL = _.map(_.flatten(aL), element => toBN(element));
        aR = _.flatten(aR);

        // hamadard<aL, aR> = 0 not inner product
        assert(innerProduct(aL, aR).toString(10) === '0', 'Wrong aL, aR !!');

        // Compute A: a curve point, vector commitment to aL and aR with hiding value alpha
        const alpha = randomBI();
        const A = twoVectorPCommitWithGens(Gi, Hi, aL, aR).add(baseH.mul(alpha));

        MRPResult.A = A;

        // Compute S: a curve point, vector commitment to sL and sR with hiding value rho
        const sL = _.map(Array(N * M), () => randomBI());
        const sR = _.map(Array(N * M), () => randomBI());
        const rho = randomBI();

        const S = twoVectorPCommitWithGens(Gi, Hi, sL, sR).add(baseH.mul(rho));

        MRPResult.S = S;

        // V is array of Point, convert to array of buffer for ready hashing
        // and used in multi-place
        let VinBuffer = _.flatten(_.map(V, vi => vi.encode('array', false).slice(1)));

        // Random challenges to build the inner product to prove the values of aL and aR
        // non-interactive
        VinBuffer = VinBuffer.concat(
            A.encode('array', false).slice(1),
            // S.encode('array', false).slice(1),
        );

        const cy = hashToScalar(
            VinBuffer,
        );

        MRPResult.cy = cy;

        // VinBuffer = VinBuffer.concat(cy.toArray('be', 32));
        VinBuffer = VinBuffer.concat(S.encode('array', false).slice(1));
        const cz = hashToScalar(
            VinBuffer,
        );

        MRPResult.cz = cz;

        // reconstruct the coefficients of degree 1 and of degree 2 of the
        // range proof inner product polynomial
        const {
            t1, t2, r0, r1, l0, l1, yMN,
        } = rangeProofInnerProductPolyCoeff(aL, sL, aR, sR, cy, cz);

        // Compute T1: a curve point, Pedersen commitment to t1 with hiding value tau1
        const tau1 = randomBI();
        const T1 = pedersenCommitment(tau1, t1);

        MRPResult.T1 = T1;

        // Compute T2: a curve point, Pedersen commitment to t2 with hiding value tau2
        const tau2 = randomBI();
        const T2 = pedersenCommitment(tau2, t2);

        MRPResult.T2 = T2;

        // Random challenge to prove the commitment to t1 and t2
        //  plus non-interactive
        // VinBuffer = VinBuffer.concat(cz.toArray('be', 32), T1.encode('array', false).slice(1), T2.encode('array', false).slice(1));
        VinBuffer = VinBuffer.concat(T1.encode('array', false).slice(1), T2.encode('array', false).slice(1));
        const cx = hashToScalar(
            VinBuffer,
        );

        MRPResult.cx = cx;

        // Compute t: a scalar, inner product value to be verified
        const l = rangeProofInnerProductLhs(l0, l1, cx);
        const r = rangeProofInnerProductRhs(r0, r1, cx);
        const t = innerProduct(l, r);

        MRPResult.Th = t;

        // Compute taux: a scalar, hiding value related to x.T1, x^2.T2, z^2.V and t
        const taux = rangeProofInnerProductPolyHidingValue(tau1, tau2, masks, cx, cz);

        MRPResult.Tau = taux;

        // Compute mu: a scalar, hiding value related to A and x.S
        const mu = cx.mul(rho).add(alpha).umod(secp256k1.n);

        MRPResult.Mu = mu;

        // Adapt Hi, the vector of generators
        // to apply an inner product argument of knowledge on l and r
        const Hiprime = _.map(Hi, (hi, index) => hi.mul(
            yMN[index].invm(secp256k1.n),
        ));

        const P = twoVectorPCommitWithGens(Gi, Hiprime, l, r);

        MRPResult.Ipp = InnerProduct.prove(l, r, t, P, U, Gi, Hiprime);

        return MRPResult;
    }

    /**
     * Convert to smart-contract readable format
     * @param {Object} proof
     * @returns {Object}
     */
    static proofToHex(proof) {
        const MRPResult = {
            Ipp: {},
            CommsLength: proof.Comms.length,
        };
        MRPResult.Comms = _.map(proof.Comms, v => v.encode('hex', true)).join('');
        MRPResult.A = proof.A.encode('hex', true);
        MRPResult.S = proof.S.encode('hex', true);
        MRPResult.cy = proof.cy.toString(16, 64);
        MRPResult.cz = proof.cz.toString(16, 64);
        MRPResult.T1 = proof.T1.encode('hex', true);
        MRPResult.T2 = proof.T2.encode('hex', true);
        MRPResult.cx = proof.cx.toString(16, 64);
        MRPResult.Th = proof.Th.toString(16, 64);
        MRPResult.Tau = proof.Tau.toString(16, 64);
        MRPResult.Mu = proof.Mu.toString(16, 64);
        MRPResult.Ipp.L = _.map(proof.Ipp.L, point => point.encode('hex', true)).join('');
        MRPResult.Ipp.R = _.map(proof.Ipp.R, point => point.encode('hex', true)).join('');

        MRPResult.Ipp.A = proof.Ipp.A.toString(16, 64);
        MRPResult.Ipp.B = proof.Ipp.B.toString(16, 64);
        MRPResult.Ipp.Challenges = _.map(proof.Ipp.Challenges, bi => bi.toString(16, 64)).join('');

        return MRPResult;
    }

    /**
     * Convert to smart-contract readable format
     * @param {Object} proof
     * @returns {Object}
     */
    static proofToHexFromWasm(proof) {
        const MRPResult = {
            Ipp: {},
            CommsLength: proof.Comms.length,
        };
        MRPResult.Comms = _.map(proof.Comms, v => secp256k1.curve.point(
            toBN(v.X),
            toBN(v.Y),
        ).encode('hex', true)).join('');
        MRPResult.A = secp256k1.curve.point(
            toBN(proof.A.X),
            toBN(proof.A.Y),
        ).encode('hex', true);
        MRPResult.S = secp256k1.curve.point(
            toBN(proof.S.X),
            toBN(proof.S.Y),
        ).encode('hex', true);
        MRPResult.cy = toBN(proof.Cy).toString(16, 64);
        MRPResult.cz = toBN(proof.Cz).toString(16, 64);
        MRPResult.T1 = secp256k1.curve.point(
            toBN(proof.T1.X),
            toBN(proof.T1.Y),
        ).encode('hex', true);
        MRPResult.T2 = secp256k1.curve.point(
            toBN(proof.T2.X),
            toBN(proof.T2.Y),
        ).encode('hex', true);
        MRPResult.cx = toBN(proof.Cx).toString(16, 64);
        MRPResult.Th = toBN(proof.Th).toString(16, 64);
        MRPResult.Tau = toBN(proof.Tau).toString(16, 64);
        MRPResult.Mu = toBN(proof.Mu).toString(16, 64);
        MRPResult.Ipp.L = _.map(proof.IPP.L, point => secp256k1.curve.point(
            toBN(point.X),
            toBN(point.Y),
        ).encode('hex', true)).join('');
        MRPResult.Ipp.R = _.map(proof.IPP.R, point => secp256k1.curve.point(
            toBN(point.X),
            toBN(point.Y),
        ).encode('hex', true)).join('');

        MRPResult.Ipp.A = toBN(proof.IPP.A).toString(16, 64);
        MRPResult.Ipp.B = toBN(proof.IPP.B).toString(16, 64);
        MRPResult.Ipp.Challenges = _.map(proof.IPP.Challenges, bi => toBN(bi).toString(16, 64)).join('');

        return MRPResult;
    }

    static verify(mrp) : Boolean {
        M = mrp.Comms.length;
        let VinBuffer = _.flatten(_.map(mrp.Comms, vi => vi.encode('array', false).slice(1)));
        VinBuffer = VinBuffer.concat(
            mrp.A.encode('array', false).slice(1),
            // mrp.S.encode('array', false).slice(1),
        );

        const cy = hashToScalar(
            VinBuffer,
        );

        if (cy.cmp(mrp.cy) !== 0) {
            console.log('MRPVerify - Challenge Cy failing!');
            return false;
        }

        // VinBuffer = VinBuffer.concat(cy.toArray('be', 32));
        VinBuffer = VinBuffer.concat(mrp.S.encode('array', false).slice(1));
        const cz = hashToScalar(
            VinBuffer,
        );

        if (cz.cmp(mrp.cz) !== 0) {
            console.log('MRPVerify - Challenge Cz failing!');
            return false;
        }

        // VinBuffer = VinBuffer.concat(cz.toArray('be', 32), mrp.T1.encode('array', false).slice(1), mrp.T2.encode('array', false).slice(1));
        VinBuffer = VinBuffer.concat(mrp.T1.encode('array', false).slice(1), mrp.T2.encode('array', false).slice(1));
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
        const z2 = cz.mul(cz).umod(secp256k1.n);

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
        const zneg = cz.neg().umod(secp256k1.n);

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
                ).umod(secp256k1.n);
                const val2 = zp.mul(powerOfTwos[i]).umod(secp256k1.n);
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
