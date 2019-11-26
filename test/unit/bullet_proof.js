
import chai from 'chai';
import * as _ from 'lodash';
import BigInteger from 'bn.js';
import BulletProof from '../../src/bullet_proof';

const { expect } = chai;
chai.should();
// import { basePointH as baseH } from './constants';

// TODO move to one place
BigInteger.fromHex = hexstring => new BigInteger(hexstring, 16);

describe('#unittest #bulletproof', () => {
    describe('#mrprove', () => {
        it('should able to prove and verify for zero', (done) => {
            const result = BulletProof.prove([
                BigInteger.fromHex('50000'),
            ], [
                BigInteger.fromHex(
                    '636FD3B1F731A590EDD4D2CCF863E37E68D54E3542F4A29ACFD1D5CF0CCDD5A5',
                ),
            ]);
            expect(result.V).not.to.equal(null);
            expect(BulletProof.verify(result)).to.equal(true);
            done();
        });

        // it('should able to prove and verify for max 64 bits', (done) => {
        //     done(new Error('not implemented yet'));
        // });

        // it('should able to prove and verify for random', (done) => {
        //     done(new Error('not implemented yet'));
        // });

        // it('should able to prove and verify for multiple random', (done) => {
        //     done(new Error('not implemented yet'));
        // });

        // it('should able to prove and verify for multiple splitting', (done) => {
        //     done(new Error('not implemented yet'));
        // });

        // it('should able to prove and verify for aggregated', (done) => {
        //     done(new Error('not implemented yet'));
        // });
    });
});
