/**
 * Inner product
 */

import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';
import { BigInteger } from './constants';
import {
    bconcat,
} from './common';

const ZERO = BigInteger.ZERO();
const EC = require('elliptic').ec;
const Curve = require('elliptic').curve;

const Point = Curve.short.ShortPoint;

const secp256k1 = new EC('secp256k1');

const baseG = secp256k1.g;

type InnerProdArg = {
    L: Array<Point>,
    R: Array<Point>,
    A: BigInteger,
    B: BigInteger,

    Challenges: Array<BigInteger>,
}

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
 * TODO move to other libs for add point and calculating BigNumber
 * this func is too messy - need replace by other lib or refactoring
 * @param {*} Gi
 * @param {*} Hi
 * @param {*} a
 * @param {*} b
 */
function twoVectorPCommitWithGens(Gi : Array<BigInteger>, Hi: Array<BigInteger>, a, b) {
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


// return Array<Point>, Array<Point>, ECPoint)
function GenerateNewParams(bG: Array<Point>, bH: Array<Point>, x: BigInteger, L: Point, R: Point, P: Point) {
    const nprime = parseInt(bG.length / 2);

    const Gprime = [];
    const Hprime = [];

    const xinv = x.invm(secp256k1.n);

    for (let i = 0; i < nprime; i++) {
        Gprime[i] = bG[i].mul(xinv).add(bG[i + nprime].mul(x));
        Hprime[i] = bH[i].mul(x).add(bH[i + nprime].mul(xinv));
    }

    const x2 = x.mul(x).mod(secp256k1.n);
    const xinv2 = x2.invm(secp256k1.n);

    const Pprime = L.mul(x2).add(P).add(R.mul(xinv2)); // x^2 * L + P + xinv^2 * R

    return {
        Gprime, Hprime, Pprime,
    };
}

const vectorAddVector = (vector, vector2) => _.map(vector, (element, index) => element.add(vector2[index]).mod(secp256k1.n));

const scalaMulVector = (scalar, vector) => _.map(vector, element => element.mul(scalar).mod(secp256k1.n));

export default class InnerProductProof {
    static prove(a: Array<BigInteger>, b: Array<BigInteger>, c: BigInteger, P: Point, U: Point, bG : Array<Point>, bH: Array<Point>): InnerProdArg {
        const loglen = parseInt(Math.log2(a.length));
        const Lvals = [];
        const Rvals = [];

        const runningProof: InnerProdArg = {
            L: Lvals,
            R: Rvals,
            A: ZERO,
            B: ZERO,
            Challenges: [],
        };

        // randomly generate an x value from public data
        const x = hashToScalar(bconcat([
            ...P.encode('array', false).slice(1),
        ]));
        // const x = BigInteger.fromHex(keccak256(P.encode('array', false).slice(1)));

        runningProof.Challenges[loglen] = _.cloneDeep(x);

        const Pprime = P.add(U.mul(x.mul(c)));

        const ux = U.mul(_.cloneDeep(x));

        return this.proveSub(runningProof, bG, bH, a, b, ux, Pprime);
    }

    /* Inner Product Argument
        Proves that <a,b>=c
        This is a building block for BulletProofs
    */
    static proveSub(proof: InnerProdArg,
        bG: Array<Point>,
        bH: Array<Point>,
        a: Array<BigInteger>,
        b: Array<BigInteger>,
        u: Point,
        P: Point) {
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

        console.log('A ', a.length);
        console.log('B ', b.length);

        const cl = innerProduct(a.slice(0, nprime), b.slice(nprime, b.length));
        const cr = innerProduct(a.slice(nprime, a.length), b.slice(0, nprime));

        const L = twoVectorPCommitWithGens(bG.slice(nprime, bG.length), bH.slice(0, nprime), a.slice(0, nprime), b.slice(nprime, b.length)).add(u.mul(cl));
        const R = twoVectorPCommitWithGens(bG.slice(0, nprime), bH.slice(nprime, bH.length), a.slice(nprime, a.length), b.slice(0, nprime)).add(u.mul(cr));

        proof.L[curIt] = L;
        proof.R[curIt] = R;

        // prover sends L & R and gets a challenge
        // prover sends L & R and gets a challenge
        const w = hashToScalar(bconcat([
            ...L.encode('array', false).slice(1),
            ...R.encode('array', false).slice(1),
        ]));

        const x = w;

        proof.Challenges[curIt] = x;

        // why do i need to generate new parameter here
        const { Gprime, Hprime, Pprime } = GenerateNewParams(bG, bH, x, L, R, P);
        const xinv = x.invm(secp256k1.n);

        const aprime = vectorAddVector(
            scalaMulVector(x, a.slice(0, nprime)),
            scalaMulVector(xinv, a.slice(nprime, a.length)),
        );

        const bprime = vectorAddVector(
            scalaMulVector(xinv, b.slice(0, nprime)),
            scalaMulVector(x, b.slice(nprime, b.length)),
        );

        return this.proveSub(proof, Gprime, Hprime, aprime, bprime, u, Pprime);
    }

    static verify(c: BigInteger, P: Point, U: Point, bG: Array<Point>, bH: Array<Point>, ipp: InnerProdArg): Boolean {
        // console.log("Verifying Inner Product Argument")
        const s1 = hashToScalar(bconcat([
            ...P.encode('array', false).slice(1),
        ]));

        // const s1 = BigInteger.fromHex(keccak256(P.encode('array', false).slice(1)));
        const chal1 = s1;

        const ux = U.mul(chal1);
        let curIt = ipp.Challenges.length - 1;

        if (ipp.Challenges[curIt].cmp(chal1) !== 0) {
            console.log('IPVerify - Initial Challenge Failed');
            return false;
        }

        curIt -= 1;

        let Gprime = bG;
        let Hprime = bH;
        let Pprime = P.add(ux.mul(c));// line 6 from protocol 1

        while (curIt >= 0) {
            const Lval = ipp.L[curIt];
            const Rval = ipp.R[curIt];

            // prover sends L & R and gets a challenge
            const w = hashToScalar(bconcat([
                ...Lval.encode('array', false).slice(1),
                ...Rval.encode('array', false).slice(1),
            ]));

            const chal2 = w;

            if (ipp.Challenges[curIt].cmp(chal2) !== 0) {
                console.log('IPVerify - Challenge verification failed at index ' + curIt);
                return false;
            }

            ({ Gprime, Hprime, Pprime } = GenerateNewParams(Gprime, Hprime, chal2, Lval, Rval, Pprime));

            curIt -= 1;
        }

        // why this
        const ccalc = ipp.A.mul(ipp.B).mod(secp256k1.n);

        const Pcalc1 = Gprime[0].mul(ipp.A);
        const Pcalc2 = Hprime[0].mul(ipp.B);
        const Pcalc3 = ux.mul(ccalc);
        const Pcalc = Pcalc1.add(Pcalc2).add(Pcalc3);

        if (!Pprime.eq(Pcalc)) {
            console.log('IPVerify - Final Commitment checking failed');
            return false;
        }

        return true;
    }
}
