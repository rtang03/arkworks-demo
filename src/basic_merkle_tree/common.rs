use ark_crypto_primitives::{
    crh::{pedersen, CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    merkle_tree::{
        constraints::{BytesVarDigestConverter, ConfigGadget},
        ByteDigestConverter, Config, MerkleTree, Path,
    },
};
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar, EdwardsProjective as JubJub, Fq,
};
use ark_r1cs_std::prelude::*;

#[derive(Clone)]
pub struct Window4x25;
impl pedersen::Window for Window4x25 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

pub type LeafH = pedersen::CRH<JubJub, Window4x25>;
pub type LeafHG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x25>;
pub type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x25>;
pub type CompressHG = pedersen::constraints::TwoToOneCRHGadget<JubJub, EdwardsVar, Window4x25>;
pub type LeafVar<ConstraintF> = [UInt8<ConstraintF>];
pub type ConstraintF = Fq;

pub struct JubJubMerkleTreeParams;
impl Config for JubJubMerkleTreeParams {
    type Leaf = [u8];
    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}

pub struct JubJubMerkleTreeParamsVar;
impl ConfigGadget<JubJubMerkleTreeParams, ConstraintF> for JubJubMerkleTreeParamsVar {
    type Leaf = LeafVar<ConstraintF>;
    type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, ConstraintF>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
    type InnerDigest = <CompressHG as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar;
    type LeafHash = LeafHG;
    type TwoToOneHash = CompressHG;
}

pub type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

pub type Root = <CompressH as TwoToOneCRHScheme>::Output;

pub type SimplePath = Path<JubJubMerkleTreeParams>;
