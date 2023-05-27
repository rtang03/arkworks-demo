mod constraints;

#[cfg(test)]
mod tests {
    use super::constraints::Multipler;
    use ark_bls12_381::Bls12_381;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;

    // see https://stackoverflow.com/questions/71048413/rng-getting-randomness-from-operating-system-vs-crypto-rngs
    use rand::{rngs::StdRng, SeedableRng};

    pub type ConstraintF = ark_bls12_381::Fr;

    #[test]
    fn test_mul() {
        let mut rng: StdRng = StdRng::from_entropy();
        let init_circuit = Multipler::<ConstraintF>::new_empty();
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(init_circuit, &mut rng).unwrap();

        let circuit = Multipler::<ConstraintF> {
            output: Some(ConstraintF::from(33)),
            input1: Some(ConstraintF::from(3)),
            input2: Some(ConstraintF::from(11)),
        };
        let public_input = [circuit.output.unwrap()];
        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();
        let valid_proof = Groth16::<Bls12_381>::verify(&vk, &public_input, &proof).unwrap();
        assert!(valid_proof);
    }
}
