// see https://docs.rs/ark-algebra-intro/latest/ark_algebra_intro/

#[cfg(test)]
mod tests {
    use ark_bls12_381::{
        Bls12_381, Fq as F, Fq2 as F2, Fr as ScalarField, G1Affine, G1Projective as G1, G2Affine,
        G2Projective as G2,
    };
    use ark_ec::{pairing::Pairing, Group};
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{One, UniformRand, Zero};
    use std::ops::Mul;

    #[test]
    fn test_ff() {
        let mut rng = ark_std::rand::thread_rng();
        let a = F2::rand(&mut rng);
        let b = F2::rand(&mut rng);
        let c = a + b;
        let d = a - b;
        assert_eq!(c + d, a.double());

        let e = c * d;
        assert_eq!(e, a.square() - b.square());

        assert_eq!(a.inverse().unwrap() * a, F2::one());
    }

    #[test]
    fn test_prime_field() {
        let mut rng = ark_std::rand::thread_rng();
        let a = F::rand(&mut rng);
        let modulus = <F as PrimeField>::MODULUS;
        assert_eq!(a.pow(&modulus), a);

        let one: num_bigint::BigUint = F::one().into();
        assert_eq!(one, num_bigint::BigUint::one());

        let n = F::from_le_bytes_mod_order(&modulus.to_bytes_le());
        assert_eq!(n, F::zero());
    }

    #[test]
    fn test_elliptic_curve() {
        let mut rng = ark_std::rand::thread_rng();
        let a = G1::rand(&mut rng);
        let b = G1::rand(&mut rng);
        let c = a + b;
        let d = a - b;
        assert_eq!(c + d, a.double());
        let e = -a;
        assert_eq!(e + a, G1::zero());

        let scalar = ScalarField::rand(&mut rng);
        let e = c.mul(&scalar);
        let f = e.mul(&scalar.inverse().unwrap());
        assert_eq!(f, c);
    }

    #[test]
    fn test_pairing() {
        let mut rng = ark_std::rand::thread_rng();
        // Let's sample uniformly random field elements:
        let a: G1Affine = G1::rand(&mut rng).into();
        let b: G2Affine = G2::rand(&mut rng).into();
        let c = Bls12_381::pairing(a, b);
        let c_ml = Bls12_381::miller_loop(a, b);
        let c_fe = Bls12_381::final_exponentiation(c_ml).unwrap();
        assert_eq!(c, c_fe);
    }

    #[test]
    fn test_serialization() {
        let mut rng = ark_std::rand::thread_rng();
        // Let's sample uniformly random field elements:
        let a: G1Affine = G1::rand(&mut rng).into();
        let mut uncompressed_bytes: Vec<u8> = Vec::new();
        a.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
        let a_uncompressed = G1Affine::deserialize_uncompressed(&*uncompressed_bytes).unwrap();
        assert_eq!(a_uncompressed, a);
        println!("{:?}", uncompressed_bytes);
    }
}
