use super::common::*;
use ark_crypto_primitives::{
    crh::{pedersen, CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    merkle_tree::constraints::PathVar,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq, JubjubConfig};
use ark_r1cs_std::{prelude::*, uint8::UInt8};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result},
};

/// The R1CS equivalent of the the Merkle tree root.
pub type RootVar =
    <pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x25> as CRHSchemeGadget<
        LeafH,
        ConstraintF,
    >>::OutputVar;

/// The R1CS equivalent of the the Merkle tree path.
pub type SimplePathVar = PathVar<JubJubMerkleTreeParams, Fq, JubJubMerkleTreeParamsVar>;

pub struct MerkleTreeVerification {
    pub leaf_crh_params: <LeafH as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <CompressH as TwoToOneCRHScheme>::Parameters,

    // public input
    // pub root: <CompressH as TwoToOneCRHScheme>::Output,
    pub root: <LeafH as CRHScheme>::Output,
    pub leaf: Vec<u8>,

    // private witness
    pub authentication_path: Option<SimplePath>,
}

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> Result<()> {
        // allocate public input
        let root = <RootVar as AllocVar<
            <pedersen::CRH<
                ark_ec::twisted_edwards::Projective<JubjubConfig>,
                Window4x25,
            > as CRHScheme>::Output,
            ConstraintF,
        >>::new_input(ns!(cs, "root_var"), || Ok(&self.root))?;

        let leaf_g = UInt8::new_input_vec(cs.clone(), &self.leaf)?;

        let leaf_crh_params_var =
            <<LeafHG as CRHSchemeGadget<LeafH, _>>::ParametersVar as AllocVar<<pedersen::CRH<
                ark_ec::twisted_edwards::Projective<JubjubConfig>,
                Window4x25,
            > as CRHScheme>::Parameters, ConstraintF>>::new_constant(
                ns!(cs, "leaf_crh_parameter"),
                &self.leaf_crh_params,
            )?;

        let two_to_one_crh_params_var =
            <<CompressHG as TwoToOneCRHSchemeGadget<CompressH, _>>::ParametersVar as AllocVar<<pedersen::CRH<
                ark_ec::twisted_edwards::Projective<JubjubConfig>,
                Window4x25,
            > as CRHScheme>::Parameters, ConstraintF>>::new_constant(
                ns!(cs, "two_to_one_crh_parameter"),
                &self.two_to_one_crh_params,
            )?;

        let path = <SimplePathVar as AllocVar<SimplePath, ConstraintF>>::new_witness(
            ns!(cs, "path_var"),
            || Ok(self.authentication_path.as_ref().unwrap()),
        )?;

        let is_member: Boolean<ConstraintF> = path.verify_membership(
            &leaf_crh_params_var,
            &two_to_one_crh_params_var,
            &root,
            &leaf_g,
        )?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

// Run this test via `cargo test --release merkle_tree_constraints_correctness`.
#[test]
fn merkle_tree_constraints_correctness() {
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::r1cs::{ConstraintLayer, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

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
    let mut leaves = Vec::new();

    for i in 0..4u8 {
        let input: Vec<u8> = vec![i; 30];
        leaves.push(input);
    }

    let tree = JubJubMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        leaves.iter().map(|v: &Vec<u8>| v.as_slice()), // the i-th entry is the i-th leaf.
    )
    .unwrap();

    let proof = tree.generate_proof(1).unwrap();

    let root = tree.root();

    let circuit = MerkleTreeVerification {
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf: leaves[1].clone(),

        // witness
        authentication_path: Some(proof),
    };

    // Todo: revisit it later
    // First, some boilerplat that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    if !is_satisfied {
        // If it isn't, find out the offending constraint.
        println!("{:?}", cs.which_is_unsatisfied());
    }
    assert!(is_satisfied);
}

// Run this test via `cargo test --release merkle_tree_constraints_soundness`.
// This tests that a given invalid authentication path will fail.
#[test]
fn merkle_tree_constraints_soundness() {
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::r1cs::{ConstraintLayer, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
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
    let mut leaves = Vec::new();
    let mut leaves2 = Vec::new();

    for i in 0..4u8 {
        let input: Vec<u8> = vec![i; 30];
        leaves.push(input);
        let input2: Vec<u8> = vec![i + 5; 30];
        leaves2.push(input2);
    }

    let tree = JubJubMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        leaves.iter().map(|v: &Vec<u8>| v.as_slice()), // the i-th entry is the i-th leaf.
    )
    .unwrap();

    let second_tree = JubJubMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        leaves2.iter().map(|v: &Vec<u8>| v.as_slice()), // the i-th entry is the i-th leaf.
    )
    .unwrap();

    let proof = tree.generate_proof(1).unwrap();

    // But, let's get the root we want to verify against:
    let wrong_root = second_tree.root();

    let circuit = MerkleTreeVerification {
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root: wrong_root,
        leaf: leaves[1].clone(),

        // witness
        authentication_path: Some(proof),
    };

    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the constraint system!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    // We expect this to fail!
    assert!(!is_satisfied);
}
