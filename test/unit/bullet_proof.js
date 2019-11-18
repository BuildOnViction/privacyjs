
import chai from 'chai';
import ecurve from 'ecurve';
import * as _ from 'lodash';
import { genECPrimeGroupKey, hexToNumberString } from '../../src/common';
import { BigInteger, randomHex } from '../../src/crypto';
import BulletProof from '../../src/bullet_proof';

const secp256k1 = ecurve.getCurveByName('secp256k1');
const { expect } = chai;
chai.should();


function TwoVectorPCommitWithGens(G, H, a, b) {
    let commitment;

    for (let i = 0; i < G.length; i++) {
        const modA = a[i].mod(secp256k1.n);
        const modB = b[i].mod(secp256k1.n);

        commitment = commitment ? commitment.add(G[i].multiply(modA))
            .add(H[i].multiply(modB)) : G[i].multiply(modA).add(H[i].multiply(modB));
    }

    return commitment;
}

const innerProduct = (v1, v2) => {
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

describe('#unittest #bulletproof', () => {
    it('Should gen/verify correctly 1', (done) => {
        const EC = genECPrimeGroupKey(1);
        const a = _.map(Array(1), () => BigInteger.ONE);
        const b = _.map(Array(1), () => BigInteger.ONE);

        // a[0] = BigInteger.ONE;
        // b[0] = BigInteger.ONE;

        const c = innerProduct(a, b);

        const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

        const ipp = BulletProof.InnerProductProve(a, b, c, P, EC.U, EC.Gi, EC.Hi);

        // EC = genECPrimeGroupKey(64);
        if (BulletProof.InnerProductVerify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
            done();
        } else {
            done(new Error('Verifying failed !!!'));
        }
    });

    it('Should gen/verify correctly 2b', (done) => {
        const EC = genECPrimeGroupKey(2);
        const a = _.map(Array(2), () => BigInteger.ONE);
        const b = _.map(Array(2), () => BigInteger.ONE);

        // a[0] = BigInteger.ONE;
        // b[0] = BigInteger.ONE;

        const c = innerProduct(a, b);

        console.log('c ', hexToNumberString(c.toHex()));

        const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

        const ipp = BulletProof.InnerProductProve(a, b, c, P, EC.U, EC.Gi, EC.Hi);

        // EC = genECPrimeGroupKey(64);
        if (BulletProof.InnerProductVerify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
            done();
        } else {
            done(new Error('Verifying failed !!!'));
        }
    });

    // it('Should gen/verify correctly 8b', (done) => {
    //     const EC = genECPrimeGroupKey(8);
    //     const a = _.map(Array(8), () => BigInteger.fromHex(
    //         randomHex(),
    //     ));
    //     const b = _.map(Array(8), () => BigInteger.fromHex(
    //         randomHex(),
    //     ));

    //     // a[0] = BigInteger.ONE;
    //     // b[0] = BigInteger.ONE;

    //     const c = innerProduct(a, b);

    //     const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

    //     const ipp = BulletProof.InnerProductProve(a, b, c, P, EC.U, EC.Gi, EC.Hi);

    //     // EC = genECPrimeGroupKey(10);
    //     if (BulletProof.InnerProductVerify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
    //         done();
    //     } else {
    //         done(new Error('Verifying failed !!!'));
    //     }
    // });

    // it('Should gen/verify correctly 64b', (done) => {
    //     const EC = genECPrimeGroupKey(64);
    //     const a = _.map(Array(64), () => BigInteger.fromHex(
    //         randomHex(),
    //     ).mod(secp256k1.n));
    //     const b = _.map(Array(64), () => BigInteger.fromHex(
    //         randomHex(),
    //     ).mod(secp256k1.n));

    //     // a[0] = BigInteger.ONE;
    //     // b[0] = BigInteger.ONE;

    //     const c = innerProduct(a, b);

    //     const P = TwoVectorPCommitWithGens(EC.Gi, EC.Hi, a, b);

    //     const ipp = BulletProof.InnerProductProve(a, b, c, P, EC.U, EC.Gi, EC.Hi);

    //     // EC = genECPrimeGroupKey(64);
    //     if (BulletProof.InnerProductVerify(c, P, EC.U, EC.Gi, EC.Hi, ipp)) {
    //         done();
    //     } else {
    //         done(new Error('Verifying failed !!!'));
    //     }
    // });
});


// function TestInnerProductProveLen2(t *testing.T) {
//  fmt.Println("TestInnerProductProve2")
//  EC = NewECPrimeGroupKey(2)
//  a = make([]*big.Int, 2)
//  b = make([]*big.Int, 2)

//  a[0] = big.NewInt(2)
//  a[1] = big.NewInt(3)

//  b[0] = big.NewInt(2)
//  b[1] = big.NewInt(3)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//  }
// }

// function TestInnerProductProveLen4(t *testing.T) {
//  fmt.Println("TestInnerProductProve4")
//  EC = NewECPrimeGroupKey(4)
//  a = make([]*big.Int, 4)
//  b = make([]*big.Int, 4)

//  a[0] = big.NewInt(1)
//  a[1] = big.NewInt(1)
//  a[2] = big.NewInt(1)
//  a[3] = big.NewInt(1)

//  b[0] = big.NewInt(1)
//  b[1] = big.NewInt(1)
//  b[2] = big.NewInt(1)
//  b[3] = big.NewInt(1)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//  }
// }

// function TestInnerProductProveLen8(t *testing.T) {
//  fmt.Println("TestInnerProductProve8")
//  EC = NewECPrimeGroupKey(8)
//  a = make([]*big.Int, 8)
//  b = make([]*big.Int, 8)

//  a[0] = big.NewInt(1)
//  a[1] = big.NewInt(1)
//  a[2] = big.NewInt(1)
//  a[3] = big.NewInt(1)
//  a[4] = big.NewInt(1)
//  a[5] = big.NewInt(1)
//  a[6] = big.NewInt(1)
//  a[7] = big.NewInt(1)

//  b[0] = big.NewInt(2)
//  b[1] = big.NewInt(2)
//  b[2] = big.NewInt(2)
//  b[3] = big.NewInt(2)
//  b[4] = big.NewInt(2)
//  b[5] = big.NewInt(2)
//  b[6] = big.NewInt(2)
//  b[7] = big.NewInt(2)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//  }
// }

// function TestInnerProductProveLen64Rand(t *testing.T) {
//  fmt.Println("TestInnerProductProveLen64Rand")
//  EC = NewECPrimeGroupKey(64)
//  a = RandVector(64)
//  b = RandVector(64)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//    fmt.Printf("Values Used: \n\ta = %s\n\tb = %s\n", a, b)
//  }

// }

// function TestInnerProductVerifyFastLen1(t *testing.T) {
//  fmt.Println("TestInnerProductProve1")
//  EC = NewECPrimeGroupKey(1)
//  a = make([]*big.Int, 1)
//  b = make([]*big.Int, 1)

//  a[0] = big.NewInt(2)

//  b[0] = big.NewInt(2)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//  }
// }

// function TestInnerProductVerifyFastLen2(t *testing.T) {
//  fmt.Println("TestInnerProductProve2")
//  EC = NewECPrimeGroupKey(2)
//  a = make([]*big.Int, 2)
//  b = make([]*big.Int, 2)

//  a[0] = big.NewInt(2)
//  a[1] = big.NewInt(3)

//  b[0] = big.NewInt(2)
//  b[1] = big.NewInt(3)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//  }
// }

// function TestInnerProductVerifyFastLen4(t *testing.T) {
//  fmt.Println("TestInnerProductProve4")
//  EC = NewECPrimeGroupKey(4)
//  a = make([]*big.Int, 4)
//  b = make([]*big.Int, 4)

//  a[0] = big.NewInt(1)
//  a[1] = big.NewInt(1)
//  a[2] = big.NewInt(1)
//  a[3] = big.NewInt(1)

//  b[0] = big.NewInt(1)
//  b[1] = big.NewInt(1)
//  b[2] = big.NewInt(1)
//  b[3] = big.NewInt(1)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//  }
// }

// function TestInnerProductVerifyFastLen8(t *testing.T) {
//  fmt.Println("TestInnerProductProve8")
//  EC = NewECPrimeGroupKey(8)
//  a = make([]*big.Int, 8)
//  b = make([]*big.Int, 8)

//  a[0] = big.NewInt(1)
//  a[1] = big.NewInt(1)
//  a[2] = big.NewInt(1)
//  a[3] = big.NewInt(1)
//  a[4] = big.NewInt(1)
//  a[5] = big.NewInt(1)
//  a[6] = big.NewInt(1)
//  a[7] = big.NewInt(1)

//  b[0] = big.NewInt(2)
//  b[1] = big.NewInt(2)
//  b[2] = big.NewInt(2)
//  b[3] = big.NewInt(2)
//  b[4] = big.NewInt(2)
//  b[5] = big.NewInt(2)
//  b[6] = big.NewInt(2)
//  b[7] = big.NewInt(2)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//  }
// }

// function TestInnerProductVerifyFastLen64Rand(t *testing.T) {
//  fmt.Println("TestInnerProductProveLen64Rand")
//  EC = NewECPrimeGroupKey(64)
//  a = RandVector(64)
//  b = RandVector(64)

//  c = InnerProduct(a, b)

//  P = TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

//  ipp = InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

//  if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
//    fmt.Println("Inner Product Proof correct")
//  } else {
//    t.Error("Inner Product Proof incorrect")
//    fmt.Printf("Values Used: \n\ta = %s\n\tb = %s\n", a, b)
//  }

// }
