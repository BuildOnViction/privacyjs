
import chai from 'chai';
import * as _ from 'lodash';
import { BigInteger } from '../../src/constants';
import BulletProof from '../../src/bullet_proof';
import { randomHex, randomBI } from '../../src/crypto';

const { expect } = chai;
chai.should();
// import { basePointH as baseH } from './constants';

// TODO move to one place
// BigInteger.fromHex = hexstring => new BigInteger(hexstring, 16);

describe('#unittest #bulletproof', () => {
    describe('#mrprove', () => {
        it('should able to prove and verify for zero', (done) => {
            const result = BulletProof.prove([
                BigInteger.fromHex('00'),
            ], [
                randomBI(),
            ]);

            expect(BulletProof.verify(result)).to.equal(true);
            done();
        });

        it('should able to prove and verify for max 64 bit', (done) => {
            const result = BulletProof.prove([
                BigInteger.fromHex('FFFFFFFFFFFFFFFF'),
            ], [
                randomBI(),
            ]);

            expect(BulletProof.verify(result)).to.equal(true);
            done();
        });

        it('should able to prove and verify for 2 - 64 bits', (done) => {
            const result = BulletProof.prove([
                BigInteger.fromHex('FFFFFFFFFFFFFFFF'),
                BigInteger.fromHex('FFFFFFFFFFFFFFFF'),
            ], [
                randomBI(),
                randomBI(),
            ]);

            expect(BulletProof.verify(result)).to.equal(true);
            done();
        });

        it('should able to prove and verify for random', (done) => {
            const result = BulletProof.prove([
                BigInteger.fromHex(randomHex(64)),
            ], [
                randomBI(),
            ]);

            expect(BulletProof.verify(result)).to.equal(true);
            done();
        });

        it('should able to prove and verify for 2 random', (done) => {
            const result = BulletProof.prove([
                BigInteger.fromHex(randomHex(64)),
                BigInteger.fromHex(randomHex(64)),
            ], [
                randomBI(),
                randomBI(),
            ]);

            expect(BulletProof.verify(result)).to.equal(true);
            done();
        });

        // it('should able to prove and verify for multiple random', (done) => {
        //     const result = BulletProof.prove([
        //         BigInteger.fromHex(randomHex(64)),
        //         BigInteger.fromHex(randomHex(64)),
        //         BigInteger.fromHex(randomHex(64)),
        //     ], [
        //         randomBI(),
        //         randomBI(),
        //         randomBI(),
        //     ]);

        //     expect(BulletProof.verify(result)).to.equal(true);
        //     done();
        // });


        it('should not able to prove for random > 64 bits', (done) => {
            try {
                BulletProof.prove([
                    BigInteger.fromHex(randomHex(128)),
                ], [
                    randomBI(),
                ]);
                done(new Error('Wrong prover'));
            } catch (ex) {
                done();
            }
        });

        it('should not able to prove for multiply random > 64 bits', (done) => {
            try {
                BulletProof.prove([
                    BigInteger.fromHex(randomHex(128)),
                    BigInteger.fromHex(randomHex(128)),
                ], [
                    randomBI(),
                    randomBI(),
                ]);
                done(new Error('Wrong prover'));
            } catch (ex) {
                done();
            }
        });
    });
});
