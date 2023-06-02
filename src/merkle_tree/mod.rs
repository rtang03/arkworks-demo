pub mod constraints;
pub mod test_utils;

#[cfg(test)]
mod bytes_mt_tests {
    use ark_crypto_primitives::{
        crh::{pedersen, CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{ByteDigestConverter, Config, MerkleTree},
        to_uncompressed_bytes,
    };
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::BigInteger256;
    use ark_serialize::CanonicalSerialize;
    use ark_std::{borrow::Borrow, test_rng, UniformRand};

    #[derive(Clone)]
    pub struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type LeafH = pedersen::CRH<JubJub, Window4x256>;
    type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x256>;

    #[derive(Clone)]
    pub struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type Leaf = [u8];
        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }

    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Pedersen only takes bytes as leaf, so we use `ToBytes` trait.
    fn merkle_tree_test<L: CanonicalSerialize>(leaves: &[L], update_query: &[(usize, L)]) -> () {
        let mut rng = test_rng();
        let mut leaves: Vec<_> = leaves
            .iter()
            .map(|leaf| to_uncompressed_bytes!(leaf).unwrap())
            .collect();
        let leaf_crh_params: pedersen::Parameters<
            ark_ec::twisted_edwards::Projective<ark_ed_on_bls12_381::JubjubConfig>,
        > = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params: pedersen::Parameters<
            ark_ec::twisted_edwards::Projective<ark_ed_on_bls12_381::JubjubConfig>,
        > = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
        let mut tree: MerkleTree<JubJubMerkleTreeParams> = JubJubMerkleTree::new(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();
        let mut root: ark_ec::twisted_edwards::Affine<ark_ed_on_bls12_381::JubjubConfig> =
            tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof: ark_crypto_primitives::merkle_tree::Path<JubJubMerkleTreeParams> =
                tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap())
        }

        // test merkle tree update functionality
        for (i, v) in update_query {
            let v: Vec<u8> = to_uncompressed_bytes!(v).unwrap();
            tree.update(*i, &v).unwrap();
            leaves[*i] = v.clone();
        }

        // update root
        root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof: ark_crypto_primitives::merkle_tree::Path<JubJubMerkleTreeParams> =
                tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap())
        }
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();

        let mut leaves = Vec::new();
        for _ in 0..2u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }

        merkle_tree_test(
            &leaves,
            &vec![
                (0, BigInteger256::rand(&mut rng)),
                (1, BigInteger256::rand(&mut rng)),
            ],
        );

        let mut leaves = Vec::new();
        for _ in 0..4u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(&leaves, &vec![(3, BigInteger256::rand(&mut rng))]);
        let mut leaves: Vec<ark_ff::BigInt<4>> = Vec::new();
        for _ in 0..128u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, BigInteger256::rand(&mut rng)),
                (3, BigInteger256::rand(&mut rng)),
                (5, BigInteger256::rand(&mut rng)),
                (111, BigInteger256::rand(&mut rng)),
                (127, BigInteger256::rand(&mut rng)),
            ],
        );
    }
}

#[cfg(test)]
mod field_mt_tests {
    use super::test_utils::poseidon_parameters;
    use ark_crypto_primitives::{
        crh::{poseidon, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    };
    use ark_std::{test_rng, vec::Vec, One, UniformRand};

    type F = ark_ed_on_bls12_381::Fr;
    type H = poseidon::CRH<F>;
    type TwoToOneH = poseidon::TwoToOneCRH<F>;

    struct FieldMTConfig;
    impl Config for FieldMTConfig {
        type Leaf = [F];
        type LeafDigest = F;
        type LeafInnerDigestConverter = IdentityDigestConverter<F>;
        type InnerDigest = F;
        type LeafHash = H;
        type TwoToOneHash = TwoToOneH;
    }

    type FieldMT = MerkleTree<FieldMTConfig>;

    fn merkle_tree_test(leaves: &[Vec<F>], update_query: &[(usize, Vec<F>)]) -> () {
        let mut leaves: Vec<
            Vec<ark_ff::Fp<ark_ff::MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4>>,
        > = leaves.to_vec();
        let leaf_crh_params: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<
            ark_ff::Fp<ark_ff::MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4>,
        > = poseidon_parameters();
        let two_to_one_params: <poseidon::TwoToOneCRH<
            ark_ff::Fp<ark_ff::MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4>,
        > as TwoToOneCRHScheme>::Parameters = leaf_crh_params.clone();

        let mut tree: MerkleTree<FieldMTConfig> = FieldMT::new(
            &leaf_crh_params,
            &two_to_one_params,
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();

        // same type as InnerDigest
        let mut root: ark_ff::Fp<ark_ff::MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4> =
            tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        {
            // wrong root should lead to error but do not panic
            let wrong_root = root + F::one();
            let proof: ark_crypto_primitives::merkle_tree::Path<FieldMTConfig> =
                tree.generate_proof(0).unwrap();
            assert!(!proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &wrong_root,
                    leaves[0].as_slice()
                )
                .unwrap());
        }

        // test merkle tree update functionality
        for (i, v) in update_query {
            tree.update(*i, v).unwrap();
            leaves[*i] = v.to_vec();
        }

        // update the root
        root = tree.root();

        // verify again
        for (i, leaf) in leaves.iter().enumerate() {
            let proof: ark_crypto_primitives::merkle_tree::Path<FieldMTConfig> =
                tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap())
        }
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();
        let mut rand_leaves = || (0..3).map(|_| F::rand(&mut rng)).collect();

        // note: Vec<Vec<F>> is required to avoid type inference errors in preivous statement
        let mut leaves: Vec<Vec<F>> = Vec::new();
        for _ in 0..128u8 {
            leaves.push(rand_leaves())
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, rand_leaves()),
                (3, rand_leaves()),
                (5, rand_leaves()),
                (111, rand_leaves()),
                (127, rand_leaves()),
            ],
        )
    }
}
