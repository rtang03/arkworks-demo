extern crate test;

mod constraints;

#[cfg(test)]
mod tests {
    use super::constraints::Multipler;
    use super::test::Bencher;
    use ark_bls12_381::Bls12_381;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    // see https://stackoverflow.com/questions/71048413/rng-getting-randomness-from-operating-system-vs-crypto-rngs
    use rand::{rngs::StdRng, SeedableRng};
    // For benchmarking
    use std::time::{Duration, Instant};

    pub type ConstraintF = ark_bls12_381::Fr;

    #[test]
    fn test_mul() {
        let mut total_setup = Duration::new(0, 0);
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);
        let mut rng: StdRng = StdRng::from_entropy();
        let init_circuit = Multipler::<ConstraintF>::new_empty();

        let start = Instant::now();
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(init_circuit, &mut rng).unwrap();

        total_setup += start.elapsed();

        let circuit = Multipler::<ConstraintF> {
            output: Some(ConstraintF::from(33)),
            input1: Some(ConstraintF::from(3)),
            input2: Some(ConstraintF::from(11)),
        };
        let public_input = [circuit.output.unwrap()];

        let start = Instant::now();
        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();

        total_proving += start.elapsed();

        let start = Instant::now();

        let valid_proof = Groth16::<Bls12_381>::verify(&vk, &public_input, &proof).unwrap();
        total_verifying += start.elapsed();

        println!("Setup time: {:?} seconds", total_setup);
        println!("Proving time: {:?} seconds", total_proving);
        println!("Verifying time: {:?} seconds", total_verifying);

        assert!(valid_proof);
    }

    #[bench]
    fn test_mul_performance(_b: &mut Bencher) {
        // let mut rng: StdRng = StdRng::from_entropy();
        // let init_circuit = Multipler::<ConstraintF>::new_empty();
        // _b.iter(|| {
        //     let (pk, vk) =
        //         Groth16::<Bls12_381>::circuit_specific_setup(init_circuit.clone(), &mut rng)
        //             .unwrap();
        //     let circuit = Multipler::<ConstraintF> {
        //         output: Some(ConstraintF::from(33)),
        //         input1: Some(ConstraintF::from(3)),
        //         input2: Some(ConstraintF::from(11)),
        //     };
        //     let public_input = [circuit.output.unwrap()];
        //     let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();
        //     let valid_proof = Groth16::<Bls12_381>::verify(&vk, &public_input, &proof).unwrap();
        //     assert!(valid_proof);
        // });
    }
}
