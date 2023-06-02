#[cfg(test)]
mod byte_mt_tests {
    use ark_crypto_primitives::{
        crh::{pedersen, CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
        merkle_tree::{
            constraints::{BytesVarDigestConverter, ConfigGadget, PathVar},
            ByteDigestConverter, Config, MerkleTree,
        },
    };
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::vec::Vec;

    #[derive(Clone)]
    pub struct Window4x25;
    impl pedersen::Window for Window4x25 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }
    type LeafH = pedersen::CRH<JubJub, Window4x25>;
    type LeafHG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x25>;
    type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x25>;
    type CompressHG = pedersen::constraints::TwoToOneCRHGadget<JubJub, EdwardsVar, Window4x25>;
    type LeafVar<ConstraintF> = [UInt8<ConstraintF>];
    type ConstraintF = Fq;

    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type Leaf = [u8];
        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }

    struct JubJubMerkleTreeParamsVar;
    impl ConfigGadget<JubJubMerkleTreeParams, ConstraintF> for JubJubMerkleTreeParamsVar {
        type Leaf = LeafVar<ConstraintF>;
        type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, ConstraintF>>::OutputVar;
        type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
        type InnerDigest =
            <CompressHG as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar;
        type LeafHash = LeafHG;
        type TwoToOneHash = CompressHG;
    }

    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Generate a merkle tree, its constraints, and test its constraints
    fn merkle_tree_test(
        leaves: &[Vec<u8>],
        use_bad_root: bool,
        update_query: Option<(usize, Vec<u8>)>,
    ) -> () {
        let mut rng = ark_std::test_rng();

        // step 1: given rng, prepare leaf_crh_params
        let leaf_crh_params: pedersen::Parameters<
            ark_ec::twisted_edwards::Projective<ark_ed_on_bls12_381::JubjubConfig>,
        > = <LeafH as CRHScheme>::setup(&mut rng).unwrap();

        // step 2: given rng, prepare two_to_one_crh_params
        let two_to_one_crh_params: pedersen::Parameters<
            ark_ec::twisted_edwards::Projective<ark_ed_on_bls12_381::JubjubConfig>,
        > = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // step 3: new tree
        let mut tree: MerkleTree<JubJubMerkleTreeParams> = JubJubMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            leaves.iter().map(|v: &Vec<u8>| v.as_slice()),
        )
        .unwrap();

        // same type as InnerDigest
        let root: ark_ec::twisted_edwards::Affine<ark_ed_on_bls12_381::JubjubConfig> = tree.root();

        // step 4: for each leaf node
        for (i, leaf) in leaves.iter().enumerate() {
            println!("=== leaf {} / {:?} ===", i, leaf);

            // step 4a: new reference to Constraint System
            let cs: ConstraintSystemRef<_> = ConstraintSystem::<_>::new_ref();

            // step 4b: create proof for leaf
            let proof: ark_crypto_primitives::merkle_tree::Path<JubJubMerkleTreeParams> =
                tree.generate_proof(i).unwrap();

            assert!(proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_crh_params,
                    &root,
                    leaf.as_slice()
                )
                .unwrap());

            // step 4c: allocate Merkle Tree root -> witness (public)
            let root = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "new_digest"),
                || {
                    if use_bad_root {
                        Ok(<LeafH as CRHScheme>::Output::default())
                    } else {
                        Ok(root)
                    }
                },
            )
            .unwrap();

            let constraints_from_digest: usize = cs.num_constraints();
            println!("contraints from digest: {}", constraints_from_digest);

            // step 4d: allocate Parameters for leaf CRH gadget -> leaf parameter (constant)
            let leaf_crh_params_var =
                <LeafHG as CRHSchemeGadget<LeafH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "leaf_crh_parameter"),
                    &leaf_crh_params,
                )
                .unwrap();

            // step 4e: allocate Parameters for twoToOne CRH gadget -> twoToOne parameter var (constant)
            let two_to_one_crh_params_var =
                <CompressHG as TwoToOneCRHSchemeGadget<CompressH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                    &two_to_one_crh_params,
                )
                .unwrap();

            let constraints_from_params: usize = cs.num_constraints() - constraints_from_digest;
            println!(
                "constraints from leaf and twoToOne parameters: {}",
                constraints_from_params
            );

            // step 4f: allocate Leaf -> leaf value (private input)
            let leaf_g: Vec<UInt8<ark_ff::Fp<ark_ff::MontBackend<ark_bls12_381::FrConfig, 4>, 4>>> =
                UInt8::new_input_vec(cs.clone(), leaf).unwrap();

            let constraints_from_leaf =
                cs.num_constraints() - constraints_from_params - constraints_from_digest;
            println!("constraints from leaf: {}", constraints_from_leaf);

            // step 4g: allocate Merkle Tree Path -> PathVar (public input)
            let cw: PathVar<JubJubMerkleTreeParams, Fq, JubJubMerkleTreeParamsVar> =
                PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&proof)).unwrap();

            let constraints_from_path = cs.num_constraints()
                - constraints_from_params
                - constraints_from_digest
                - constraints_from_leaf;
            println!("constraints from path: {}", constraints_from_path);

            assert!(cs.is_satisfied().unwrap());
            assert!(cw
                .verify_membership(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &root,   // public input
                    &leaf_g  // private input
                )
                .unwrap()
                .value() // BooleanVar
                .unwrap());

            let setup_constraints = constraints_from_leaf
                + constraints_from_digest
                + constraints_from_params
                + constraints_from_path;
            println!(
                "number of constraints: {}",
                cs.num_constraints() - setup_constraints
            );
            assert!(
                cs.is_satisfied().unwrap(),
                "verification constraints not satisfied"
            );
        }

        //check update
        if let Some(update_query) = update_query {
            // step 5: new reference
            let cs = ConstraintSystem::<Fq>::new_ref();

            let constraints_before_update: usize = cs.num_constraints();
            println!(
                "=== update query at pos {} / {:?} ===",
                update_query.0, &update_query.1
            );
            println!("contraints before update: {}", constraints_before_update);

            // step 6a: allocate Parameters for leaf CRH gadget -> leaf parameter (constant)
            // (same as step 4d above)
            let leaf_crh_params_var =
                <LeafHG as CRHSchemeGadget<LeafH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "leaf_crh_parameter"),
                    &leaf_crh_params, // reuse previous one
                )
                .unwrap();

            // step 6b: allocate parameters for twoToOne CRH gadget -> twoToOne parameter (constant)
            // (same as step 4e above)
            let two_to_one_crh_params_var =
                <CompressHG as TwoToOneCRHSchemeGadget<CompressH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                    &two_to_one_crh_params, // reuse previous one
                )
                .unwrap();

            let constraints_from_params: usize = cs.num_constraints() - constraints_before_update;
            println!(
                "constraints from leaf and twoToOne parameters: {}",
                constraints_from_params
            );

            // step 6c: allocate old leaf and new leaf
            // (see step 4f above)
            let old_leaf_var: Vec<UInt8<_>> =
                UInt8::new_input_vec(ark_relations::ns!(cs, "old_leaf"), &leaves[update_query.0])
                    .unwrap();

            let constraints_from_new_leaf =
                cs.num_constraints() - constraints_from_params - constraints_before_update;
            println!("constraints from new_leaf: {}", constraints_from_new_leaf);

            let new_leaf_var: Vec<UInt8<_>> =
                UInt8::new_input_vec(ark_relations::ns!(cs, "new_leaf"), &update_query.1).unwrap();

            let constraints_from_old_leaf = cs.num_constraints()
                - constraints_from_params
                - constraints_before_update
                - constraints_from_new_leaf;
            println!("constraints from old_leaf: {}", constraints_from_old_leaf);

            // suppose the verifier already knows old root, new root, old leaf, new leaf, and the original path (so they are public)
            let old_root: ark_ec::twisted_edwards::Affine<ark_ed_on_bls12_381::JubjubConfig> =
                tree.root();

            // step 6d: allocate old root (private input)
            let old_root_var = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_input(
                ark_relations::ns!(cs, "old_root"),
                || Ok(old_root),
            )
            .unwrap();

            let constraints_from_old_root = cs.num_constraints()
                - constraints_from_params
                - constraints_before_update
                - constraints_from_new_leaf
                - constraints_from_old_leaf;
            println!("constraints from old_root: {}", constraints_from_old_root);

            let old_path = tree.generate_proof(update_query.0).unwrap();

            // step 6e: allocate old_path (private input)
            let old_path_var: PathVar<JubJubMerkleTreeParams, Fq, JubJubMerkleTreeParamsVar> =
                PathVar::new_input(ark_relations::ns!(cs, "old_path"), || Ok(old_path)).unwrap();

            let constraints_from_old_path = cs.num_constraints()
                - constraints_from_params
                - constraints_before_update
                - constraints_from_new_leaf
                - constraints_from_old_leaf
                - constraints_from_old_root;
            println!("constraints from old_path: {}", constraints_from_old_path);

            let new_root: ark_ec::twisted_edwards::Affine<ark_ed_on_bls12_381::JubjubConfig> = {
                tree.update(update_query.0, &update_query.1).unwrap();
                tree.root()
            };

            // step 6f: allocate new_root (private input)
            let new_root_var = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_input(
                ark_relations::ns!(cs, "new_root"),
                || Ok(new_root),
            )
            .unwrap();

            let constraints_from_new_root = cs.num_constraints()
                - constraints_from_params
                - constraints_before_update
                - constraints_from_new_leaf
                - constraints_from_old_leaf
                - constraints_from_old_root
                - constraints_from_old_path;
            println!("constraints from new_root: {}", constraints_from_new_root);

            // verifier need to get a proof (the witness) to show the known new root is correct
            assert!(old_path_var
                .update_and_check(
                    &leaf_crh_params_var,       // constant
                    &two_to_one_crh_params_var, // constant
                    &old_root_var,              // private
                    &new_root_var,              // private
                    &old_leaf_var,              // private
                    &new_leaf_var,              // private
                )
                .unwrap()
                .value()
                .unwrap());
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn good_root_test() {
        let mut leaves: Vec<Vec<u8>> = Vec::new();
        for i in 0..4u8 {
            let input: Vec<u8> = vec![i; 30];
            leaves.push(input);
        }
        merkle_tree_test(&leaves, false, Some((3usize, vec![7u8; 30])));
    }
}

#[cfg(test)]
mod field_mt_tests {
    use ark_crypto_primitives::{
        crh::{poseidon, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
        merkle_tree::{
            constraints::{ConfigGadget, PathVar},
            Config, IdentityDigestConverter, MerkleTree,
        },
    };
    use ark_ff::{MontBackend, One};
    use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar, uint32::UInt32, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand};

    use crate::merkle_tree::test_utils::poseidon_parameters;

    type F = ark_ed_on_bls12_381::Fr;
    type H = poseidon::CRH<F>;
    type HG = poseidon::constraints::CRHGadget<F>;
    type TwoToOneH = poseidon::TwoToOneCRH<F>;
    type TwoToOneHG = poseidon::constraints::TwoToOneCRHGadget<F>;

    type LeafVar = [FpVar<F>];

    struct FieldMTConfig;
    impl Config for FieldMTConfig {
        type Leaf = [F];
        type LeafDigest = F;
        type LeafInnerDigestConverter = IdentityDigestConverter<F>;
        type InnerDigest = F;
        type LeafHash = H;
        type TwoToOneHash = TwoToOneH;
    }

    struct FieldMTConfigVar;
    impl ConfigGadget<FieldMTConfig, F> for FieldMTConfigVar {
        type Leaf = LeafVar;
        type LeafDigest = FpVar<F>;
        type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
        type InnerDigest = FpVar<F>;
        type LeafHash = HG;
        type TwoToOneHash = TwoToOneHG;
    }

    type FieldMT = MerkleTree<FieldMTConfig>;

    fn merkle_tree_test(
        leaves: &[Vec<F>],
        use_bad_root: bool,
        update_query: Option<(usize, Vec<F>)>,
    ) {
        // step 1: prepare leaf_crh_params
        let leaf_crh_params: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<
            ark_ff::Fp<ark_ff::MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4>,
        > = poseidon_parameters();

        // step 2: prepare two_to_one_crh_params
        let two_to_one_params: <poseidon::TwoToOneCRH<
            ark_ff::Fp<ark_ff::MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4>,
        > as TwoToOneCRHScheme>::Parameters = leaf_crh_params.clone();

        // step 3: new tree
        let mut tree: MerkleTree<FieldMTConfig> = FieldMT::new(
            &leaf_crh_params,
            &two_to_one_params,
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();

        let root: ark_ff::Fp<ark_ff::MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4> =
            tree.root();

        // step 4: for each leaf node
        for (i, leaf) in leaves.iter().enumerate() {
            // step 4a: new reference to Constraint System
            let cs = ConstraintSystem::<F>::new_ref();

            // step 4b: create proof for leaf
            let proof: ark_crypto_primitives::merkle_tree::Path<FieldMTConfig> =
                tree.generate_proof(i).unwrap();

            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());

            // step 4c: allocate Merkle Tree root -> witness (public)
            let root = FpVar::new_witness(cs.clone(), || {
                if use_bad_root {
                    Ok(root + F::one())
                } else {
                    Ok(root)
                }
            })
            .unwrap();

            let constraints_from_digest = cs.num_constraints();
            println!("constraints from digest: {}", constraints_from_digest);

            // step 4d: allocate Parameters for leaf CRH gadget -> leaf parameter (constant)
            let leaf_crh_params_var = <HG as CRHSchemeGadget<H, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_params"),
                &leaf_crh_params,
            )
            .unwrap();

            // step 4e: allocate Parameters for twoToOne CRH gadget -> twoToOne parameter var (constant)
            let two_to_one_crh_params_var =
                <TwoToOneHG as TwoToOneCRHSchemeGadget<TwoToOneH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_params"),
                    &two_to_one_params,
                )
                .unwrap();

            let constraints_from_params = cs.num_constraints() - constraints_from_digest;
            println!("constraints from parameters: {}", constraints_from_params);

            // step 4f: allocate Leaf -> leaf value (private input)
            let leaf_g: Vec<_> = leaf
                .iter()
                .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)).unwrap())
                .collect();

            let constraints_from_leaf =
                cs.num_constraints() - constraints_from_params - constraints_from_digest;
            println!("constraints from leaf: {}", constraints_from_leaf);

            // step 4g: allocate Merkle Tree Path -> PathVar (public input)
            let mut cw: PathVar<
                FieldMTConfig,
                ark_ff::Fp<MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4>,
                FieldMTConfigVar,
            > = PathVar::<FieldMTConfig, F, FieldMTConfigVar>::new_witness(
                ark_relations::ns!(cs, "new_witness"),
                || Ok(&proof),
            )
            .unwrap();

            let constraints_from_path = cs.num_constraints()
                - constraints_from_params
                - constraints_from_digest
                - constraints_from_leaf;
            println!("constraints from path: {}", constraints_from_path);
            assert!(cs.is_satisfied().unwrap());

            // try replace the path index
            let leaf_pos: Vec<ark_r1cs_std::prelude::Boolean<F>> =
                UInt32::new_witness(cs.clone(), || Ok(i as u32))
                    .unwrap()
                    .to_bits_le();
            cw.set_leaf_position(leaf_pos.clone());

            // check if get_leaf_position is correct
            let expected_leaf_pos: Vec<bool> = leaf_pos.value().unwrap();
            let mut actual_leaf_pos = cw.get_leaf_position().value().unwrap();
            actual_leaf_pos.extend((0..(32 - actual_leaf_pos.len())).map(|_| false));
            assert_eq!(expected_leaf_pos, actual_leaf_pos);

            assert!(cw
                .verify_membership(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &root,
                    &leaf_g
                )
                .unwrap()
                .value()
                .unwrap());

            let setup_constraints = constraints_from_leaf
                + constraints_from_digest
                + constraints_from_params
                + constraints_from_path;

            println!(
                "number of constraints for verification: {}",
                cs.num_constraints() - setup_constraints
            );

            assert!(
                cs.is_satisfied().unwrap(),
                "verification constraints not satisfied"
            );
        }

        // check update

        if let Some(update_query) = update_query {
            let cs = ConstraintSystem::<F>::new_ref();
            // allocate parameters for CRH
            let leaf_crh_params_var = <HG as CRHSchemeGadget<H, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_params"),
                &leaf_crh_params,
            )
            .unwrap();

            let two_to_one_crh_params_var =
                <TwoToOneHG as TwoToOneCRHSchemeGadget<TwoToOneH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_params"),
                    &leaf_crh_params,
                )
                .unwrap();

            let old_leaf_var: Vec<_> = leaves[update_query.0]
                .iter()
                .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)).unwrap())
                .collect();
            let new_leaf_var: Vec<_> = update_query
                .1
                .iter()
                .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)).unwrap())
                .collect();

            let old_root = tree.root();
            let old_root_var = FpVar::new_input(cs.clone(), || Ok(old_root)).unwrap();

            let old_path = tree.generate_proof(update_query.0).unwrap();
            let old_path_var = PathVar::<FieldMTConfig, F, FieldMTConfigVar>::new_input(
                ark_relations::ns!(cs, "old_path"),
                || Ok(old_path),
            )
            .unwrap();
            let new_root = {
                tree.update(update_query.0, update_query.1.as_slice())
                    .unwrap();
                tree.root()
            };
            let new_root_var = FpVar::new_witness(cs.clone(), || Ok(new_root)).unwrap();

            assert!(old_path_var
                .update_and_check(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &old_root_var,
                    &new_root_var,
                    &old_leaf_var,
                    &new_leaf_var
                )
                .unwrap()
                .value()
                .unwrap());

            assert!(cs.is_satisfied().unwrap())
        }
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();
        let mut rand_leaves = || (0..2).map(|_| F::rand(&mut rng)).collect();

        let mut leaves: Vec<Vec<_>> = Vec::new();
        for _ in 0..128u8 {
            leaves.push(rand_leaves())
        }

        merkle_tree_test(&leaves, false, Some((3, rand_leaves())))
    }
}
