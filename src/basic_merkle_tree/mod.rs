pub mod common;
pub mod constraints;

use common::*;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::{
        crh::{pedersen, CRHScheme, TwoToOneCRHScheme},
        merkle_tree::MerkleTree,
    };

    #[test]
    fn test_simple_merkle_tree() {
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
        let mut leaves: Vec<Vec<u8>> = Vec::new();
        for i in 0..4u8 {
            let input: Vec<u8> = vec![i; 30];
            leaves.push(input);
        }
        let tree: MerkleTree<JubJubMerkleTreeParams> = JubJubMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            leaves.iter().map(|v| v.as_slice()), // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 3rd item.
        let proof = tree.generate_proof(2).unwrap();
        let root = tree.root();
        let result = proof
            .verify(&leaf_crh_params, &two_to_one_crh_params, &root, vec![2; 30])
            .unwrap();
        assert!(result);
    }
}
