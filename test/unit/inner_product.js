import chai from 'chai';
import * as _ from 'lodash';
import BigInteger from 'bn.js';
import toBN from 'number-to-bn';
import { randomHex } from '../../src/crypto';
import InnerProduct from '../../src/inner_product';

const EllipicCurve = require('elliptic').ec;

// Create and initialize EC context
// (better do it once and reuse it)
const secp256k1 = new EllipicCurve('secp256k1');

// const hs = hmacSha256;
const baseG = secp256k1.g;
const baseH = secp256k1.curve.point(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    '31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904',
);

const ZERO = new BigInteger('0', 16);
const ONE = new BigInteger('01', 2);

chai.should();

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

function TwoVectorPCommitWithGens(G, H, a, b) {
    let commitment;

    for (let i = 0; i < G.length; i++) {
        const modA = a[i].mod(secp256k1.n);
        const modB = b[i].mod(secp256k1.n);

        commitment = commitment ? commitment.add(G[i].mul(modA))
            .add(H[i].mul(modB)) : G[i].mul(modA).add(H[i].mul(modB));
    }

    return commitment;
}

const innerProduct = (v1, v2) => {
    let sum = ZERO;
    for (let i = 0; i < v1.length; i++) {
        sum = sum.add(
            v1[i]
                .mul(
                    v2[i],
                ),
        );
    }

    return sum;
};

describe('#unittest #inner_product', () => {
    it('Should gen/verify correctly 1', (done) => {
        const EC = genECPrimeGroupKey(1);
        const a = _.map(Array(1), () => ONE);
        const b = _.map(Array(1), () => ONE);

        // a[0] = ONE;
        // b[0] = ONE;

        const c = innerProduct(a, b);

        const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

        const ipp = InnerProduct.prove(a, b, c, P, EC.U, EC.Gi, EC.Hi);

        // EC = genECPrimeGroupKey(64);
        if (InnerProduct.verify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
            done();
        } else {
            done(new Error('Verifying failed !!!'));
        }
    });

    it('Should gen/verify correctly 2b', (done) => {
        const EC = genECPrimeGroupKey(2);
        const a = _.map(Array(2), () => ONE);
        const b = _.map(Array(2), () => ONE);

        // a[0] = ONE;
        // b[0] = ONE;

        const c = innerProduct(a, b);

        const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

        const ipp = InnerProduct.prove(a, b, c, P, EC.U, EC.Gi, EC.Hi);

        // EC = genECPrimeGroupKey(64);
        if (InnerProduct.verify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
            done();
        } else {
            done(new Error('Verifying failed !!!'));
        }
    });

    it('Should gen/verify correctly 8b', (done) => {
        const EC = genECPrimeGroupKey(8);
        const a = _.map(Array(8), () => new BigInteger(
            randomHex(), 16,
        ));
        const b = _.map(Array(8), () => new BigInteger(
            randomHex(), 16,
        ));

        // a[0] = ONE;
        // b[0] = ONE;

        const c = innerProduct(a, b);

        const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

        const ipp = InnerProduct.prove(a, b, c, P, EC.U, EC.Gi, EC.Hi);

        // EC = genECPrimeGroupKey(10);
        if (InnerProduct.verify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
            done();
        } else {
            done(new Error('Verifying failed !!!'));
        }
    });

    it('Should gen/verify correctly 64b', (done) => {
        const EC = genECPrimeGroupKey(64);
        const a = _.map(Array(64), () => new BigInteger(
            randomHex(), 16,
        ).mod(secp256k1.n));
        const b = _.map(Array(64), () => new BigInteger(
            randomHex(), 16,
        ).mod(secp256k1.n));

        // a[0] = ONE;
        // b[0] = ONE;

        const c = innerProduct(a, b);

        const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

        const ipp = InnerProduct.prove(a, b, c, P, EC.U, EC.Gi, EC.Hi);

        // EC = genECPrimeGroupKey(64);
        if (InnerProduct.verify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
            done();
        } else {
            done(new Error('Verifying failed !!!'));
        }
    });

    it('Should gen/verify correctly 128b', (done) => {
        const EC = genECPrimeGroupKey(128);
        const a = _.map(Array(128), () => new BigInteger(
            randomHex(), 16,
        ).mod(secp256k1.n));
        const b = _.map(Array(128), () => new BigInteger(
            randomHex(), 16,
        ).mod(secp256k1.n));

        // a[0] = ONE;
        // b[0] = ONE;

        const c = innerProduct(a, b);

        const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

        const ipp = InnerProduct.prove(a, b, c, P, EC.U, EC.Gi, EC.Hi);

        // EC = genECPrimeGroupKey(128);
        if (InnerProduct.verify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
            done();
        } else {
            done(new Error('Verifying failed !!!'));
        }
    });
});
