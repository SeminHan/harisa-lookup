use crate::cc_snark::CcGroth16;
use crate::harisa::constants::*;
use crate::harisa::hash_to_prime::{hash_to_prime, round_keys_contants_to_vec};
use crate::ConstraintF;

use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::SynthesisError;
use ark_std::One;
use core::ops::{AddAssign, MulAssign};
use num_bigint::BigInt;
use std::str::FromStr;

use super::prepare_verifying_key;
use super::r1cs_to_qap::R1CSToQAP;
use super::{
    data_structure::{HarisaPP, HarisaProof},
    harisa::Harisa,
};

impl<E: Pairing, QAP: R1CSToQAP> Harisa<E, QAP> {
    pub fn harisa_verify(
        pp: HarisaPP<E>,
        accum: BigInt,
        // cm_u: E::G1Affine,
        proof: HarisaProof<E>,
    ) -> Result<bool, SynthesisError>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        // pstar
        let mut p_star = BigInt::one();

        let mut p = Vec::new();

        for i in 0..ODD_PRIME.len() {
            let p_i = BigInt::from(ODD_PRIME[i]);
            p.push(p_i.clone());
            p_star *= p_i;
        }

        let accum_hat = accum.clone().modpow(&p_star, &pp.mod_n.clone());

        // hash h
        let constants = round_keys_contants_to_vec::<E::ScalarField>(&MIMC_7_91_BN254_ROUND_KEYS);
        let mut h = hash_to_prime(accum.clone(), proof.w_hat.clone(), &constants);
        h = hash_to_prime(h, proof.r.clone(), &constants);

        // 1. acc_hat = acc^{h * prod_pi} + R
        let acc_hat = (accum_hat.modpow(&h, &pp.mod_n.clone()) * proof.r) % pp.mod_n.clone();

        let l = hash_to_prime(proof.w_hat.clone(), acc_hat.clone(), &constants);
        println!("k : {:?}", proof.k.clone());
        println!("l : {:?}", l.clone());
        assert!(proof.k.clone() >= BigInt::from(0), "[PoKE] Wrong range (k, smaller than 0)");
        assert!(proof.k.clone() < l.clone(), "[PoKE] Wrong range (k, larger than l)");

        // PoKE verify
        assert_eq!(
            (proof.q.modpow(&l.clone(), &pp.mod_n.clone())
                * (proof.w_hat.modpow(&proof.k, &pp.mod_n.clone())))
                % pp.mod_n,
            acc_hat,
            "[PoKE] Verification Failed"
        );

        let arithm_pvk = prepare_verifying_key(&pp.arithm_vk.clone());
        let arithm_verify = start_timer!(|| "cparithm::verify");
        let arithm_result =
            CcGroth16::<E, QAP>::verify_proof(&arithm_pvk, &proof.arithm_prf, &[]).unwrap();
        end_timer!(arithm_verify);

        let bound_pvk = prepare_verifying_key(&pp.bound_vk.clone());
        let bound_verify = start_timer!(|| "cpbound::verify");
        let bound_result =
            CcGroth16::<E, QAP>::verify_proof(&bound_pvk, &proof.bound_prf, &[]).unwrap();
        end_timer!(bound_verify);

        assert_eq!(arithm_result, true, "[Arithm] Verification Failed");
        assert_eq!(bound_result, true, "[Bound] Verification Failed");

        Ok(true)
    }
}
