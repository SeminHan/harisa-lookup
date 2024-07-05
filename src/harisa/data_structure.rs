use crate::{
    cc_snark::data_structure::{Proof, ProvingKey, VerifyingKey},
    linker::Linker,
};
use ark_ec::pairing::Pairing;
use num_bigint::BigInt;

#[derive(Default, Debug, PartialEq)]
pub struct HarisaPP<E: Pairing, LNK: Linker<E>> {
    pub arithm_ek: ProvingKey<E>,
    pub arithm_vk: VerifyingKey<E>,
    pub arithm_lnk_pp: LNK::PP,
    pub arithm_lnk_ek: LNK::EK,
    pub arithm_lnk_vk: LNK::VK,

    // %%%%%%%%%%%%%%%%%%%%%%%%%%% Remove Bound Circuit %%%%%%%%%%%%%%%%%%%%%%%%%%%
    pub bound_ek: ProvingKey<E>,
    pub bound_vk: VerifyingKey<E>,
    pub bound_lnk_pp: LNK::PP,
    pub bound_lnk_ek: LNK::EK,
    pub bound_lnk_vk: LNK::VK,

    pub g: BigInt,
    pub mod_n: BigInt,
    pub ck: Vec<E::G1Affine>,
}

impl<E: Pairing, LNK: Linker<E>> Clone for HarisaPP<E, LNK> {
    fn clone(&self) -> Self {
        Self {
            arithm_ek: self.arithm_ek.clone(),
            arithm_vk: self.arithm_vk.clone(),
            arithm_lnk_pp: self.arithm_lnk_pp.clone(),
            arithm_lnk_ek: self.arithm_lnk_ek.clone(),
            arithm_lnk_vk: self.arithm_lnk_vk.clone(),

            // // %%%%%%%%%%%%%%%%%%%%%%%%%%% Remove Bound Circuit %%%%%%%%%%%%%%%%%%%%%%%%%%%
            bound_ek: self.bound_ek.clone(),
            bound_vk: self.bound_vk.clone(),
            bound_lnk_pp: self.bound_lnk_pp.clone(),
            bound_lnk_ek: self.bound_lnk_ek.clone(),
            bound_lnk_vk: self.bound_lnk_vk.clone(),

            g: self.g.clone(),
            mod_n: self.mod_n.clone(),
            ck: self.ck.clone(),
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct HarisaProof<E: Pairing, LNK: Linker<E>> {
    pub cm_u: E::G1Affine,
    pub cm_sr: E::G1Affine,

    pub w_hat: BigInt,
    pub r: BigInt,
    pub q: BigInt,
    pub k: BigInt,

    pub arithm_prf: Proof<E>,
    pub arithm_lnk_prf: LNK::Proof,
    pub arithm_lnk_cm_aux: LNK::CM,
    pub arithm_lnk_cm: E::G1Affine,

    // %%%%%%%%%%%%%%%%%%%%%%%%%%% Remove Bound Circuit %%%%%%%%%%%%%%%%%%%%%%%%%%%
    // pub bound_prf: Proof<E>,
    // pub bound_lnk_prf: LNK::Proof,
    // pub bound_lnk_cm_aux: LNK::CM,
    // pub bound_lnk_cm: E::G1Affine,
}
