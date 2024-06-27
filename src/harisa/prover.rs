use std::str::FromStr;

use super::{
    arithm::ArithmCircuit,
    bound::BoundCircuit,
    constants::{MIMC_7_91_BN254_ROUND_KEYS, RSA_2048},
    data_structure::{HarisaPP, HarisaProof},
    harisa::Harisa,
    hash_to_prime::{gen_bigint_range, hash_to_prime, round_keys_contants_to_vec},
    precompute::*,
    r1cs_to_qap::LibsnarkReduction,
    type_conversion::*,
};
use crate::{
    cc_snark::{
        data_structure::{Proof, ProvingKey},
        r1cs_to_qap::R1CSToQAP,
        CcGroth16,
    },
    harisa::constants::ODD_PRIME,
};

use ark_crypto_primitives::snark::*;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError,
};
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    One, UniformRand, Zero,
};
use itertools::Itertools;
use num_bigint::BigInt;

impl<E: Pairing, QAP: R1CSToQAP> Harisa<E, QAP> {
    fn generate_cc_proof<C, R>(
        pk: &ProvingKey<E>,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        R: Rng + RngCore + CryptoRng,
    {
        let cc_snark_prover_time = start_timer!(|| "ccGroth::Prover");

        let cc_prf = CcGroth16::<E, QAP>::prove(&pk, circuit, rng).unwrap();

        end_timer!(cc_snark_prover_time);

        Ok(cc_prf)
    }

    pub fn generate_harisa_proof<R: RngCore + CryptoRng + Rng>(
        pp: HarisaPP<E>,
        accum: BigInt,
        w: BigInt,
        u: Vec<BigInt>,
        rng: &mut R,
    ) -> Result<HarisaProof<E>, SynthesisError>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        // pstar
        let mut p_star = BigInt::one();
        p_star = ODD_PRIME.iter().product();

        // let mut p = Vec::new();

        // for i in 0..ODD_PRIME.len() {
        //     let p_i = BigInt::from(ODD_PRIME[i]);
        //     p.push(p_i.clone());
        //     p_star *= p_i;
        // }

        let accum_hat = accum.clone().modpow(&p_star.clone(), &pp.mod_n.clone());

        // ustar
        let mut u_star = BigInt::one();
        for u_i in u.clone() {
            u_star *= u_i;
        }

        // sample b
        let b_rng = rand::thread_rng();

        let (mut s, mut s_bar) = (BigInt::one(), BigInt::one());

        for i in 0..ODD_PRIME.len() {
            let num = rng.gen_range(0..=1);
            if num == 1 {
                s *= BigInt::from(ODD_PRIME[i]);
            } 
            else {
                s_bar *= BigInt::from(ODD_PRIME[i]);
            }
        };


        // let b_rand = E::ScalarField::rand(rng);
        // let mut b_bits = b_rand.into_bigint().to_bits_le();
        // b_bits.truncate(u.clone().into_iter().len());

        // for _ in b_bits.len()..p.len() {
        //     b_bits.push(false);
        // }

        // b_bits.reverse();

        // // calculate s, s_bar
        // let (mut s, mut s_bar) = (BigInt::one(), BigInt::one());

        // for (p_i, b_bits_i) in p.clone().iter().zip(b_bits.clone().into_iter()) {
        //     match b_bits_i {
        //         false => s_bar *= p_i,
        //         true => s *= p_i,
        //     };
        // }

        assert_eq!(
            p_star.clone(),
            s.clone() * s_bar.clone(),
            "Product Sampling Failed"
        );

        // println!("s: {:?}", s.clone());
        // println!("sbar :{:?}", s_bar.clone());

        // calculate w_hat
        let w_hat = w.modpow(&s_bar, &pp.mod_n.clone());

        // sample r
        let r_rand = gen_bigint_range(rng, &BigInt::from(2), &(pp.mod_n.clone() - 1));

        // calculate R
        let r = w_hat.clone().modpow(&r_rand.clone(), &pp.mod_n.clone());

        // hash h = H_prime(h, r, &constants)
        let constants = round_keys_contants_to_vec::<E::ScalarField>(&MIMC_7_91_BN254_ROUND_KEYS);

        let mut h = hash_to_prime(accum, w_hat.clone(), &constants);
        h = hash_to_prime(h, r.clone(), &constants);

        // calculate k
        let k = r_rand.clone() + u_star.clone() * s.clone() * h.clone();

        // PoKE => prf1
        let large_b =
            (accum_hat.modpow(&h.clone(), &pp.mod_n.clone()) * r.clone()) % pp.mod_n.clone();

        let l = hash_to_prime(w_hat.clone(), large_b.clone(), &constants);

        let quot = k.clone() / l.clone();
        let rem = k.clone() - (quot.clone() * l.clone());
        // let rem = k.clone() % l.clone();
        let q = w_hat.clone().modpow(&quot.clone(), &pp.mod_n.clone());

        assert_eq!(
            quot.clone() * l.clone() + rem.clone(),
            k.clone(),
            "Exponentiation Failed"
        );

        // %%%%%%%%%%%% NON-POKE DEBUG %%%%%%%%%%%%%%%%%

        let w_k = w_hat.clone().modpow(&k.clone(), &pp.mod_n.clone());
        
        assert_eq!(
            w_k.clone(),
            large_b.clone(),
            "Non-Poke verification is failed."
        );

        let ql = (q.clone().modpow(&l.clone(), &pp.mod_n.clone()));
        let w_hat_rem = (w_hat.clone().modpow(&l.clone(), &pp.mod_n.clone()));
        

        let lhs = (ql * w_hat_rem) % pp.mod_n.clone();

        assert_eq!(
            lhs.clone(),
            (q.clone().modpow(&l.clone(), &pp.mod_n.clone())
            * w_hat.clone().modpow(&rem, &pp.mod_n.clone()))
            % pp.mod_n.clone(),
            "Q^l W^k Failed"
        );

        // assert_eq!(
        //     lhs.clone(),
        //     large_b.clone(),
        //     "PoKE Proof Generation Failed."
        // );

        let mut circuit_u = Vec::new();

        for u_i in u.clone() {
            circuit_u.push(bigint_to_fr(u_i));
        }

        let circuit_h = bigint_to_fr(h);
        let circuit_l = bigint_to_fr(l);
        let circuit_k = bigint_to_fr(k);
        let circuit_s = bigint_to_fr(s);
        let circuit_r = bigint_to_fr(r_rand);

        let arithm_circuit = ArithmCircuit::<E::ScalarField>::new(
            circuit_h,
            circuit_l,
            circuit_k,
            circuit_u.clone(),
            circuit_s,
            circuit_r,
        );
        let bound_circuit =
            BoundCircuit::<E::ScalarField>::new(E::ScalarField::one(), circuit_u.clone());

        // arithm => prf2
        let arithm_prf =
            Self::generate_cc_proof(&pp.arithm_ek.clone(), arithm_circuit, rng).unwrap();

        // bound => prf3
        let bound_prf = Self::generate_cc_proof(&pp.bound_ek.clone(), bound_circuit, rng).unwrap();

        Ok(HarisaProof {
            w_hat,
            r,
            q,
            k: rem,
            arithm_prf,
            bound_prf,
        })
    }

    pub fn generate_harisa_opt_proof<R: RngCore + CryptoRng + Rng>(
        pp: HarisaPP<E>,
        tree: Vec<BigInt>,
        accum: BigInt,
        u: Vec<BigInt>,
        rng: &mut R,
    ) -> Result<HarisaProof<E>, SynthesisError>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        let mut w: Vec<BigInt> = Vec::new();

        let u_len = u.len();

        for i in 0..u_len {
            w.push(tree[i].clone());
        }

        assert_eq!(
            w[0].clone().modpow(&u[0].clone(), &pp.mod_n.clone()),
            w[1].clone().modpow(&u[1].clone(), &pp.mod_n.clone()),
        );

        let mut u_vec = u.clone();

        let mut w_len = u_len;

        while w_len > 1 {
            w_len >>= 1;

            for i in 0..w_len {
                (w[i], u_vec[i]) = assemble(
                    pp.mod_n.clone(),
                    u_vec[2 * i].clone(),
                    u_vec[2 * i + 1].clone(),
                    w[2 * i].clone(),
                    w[2 * i + 1].clone(),
                );
            }
            w.truncate(w_len);
            u_vec.truncate(w_len);
        }

        let w_u = w.first().unwrap();

        let proof = Self::generate_harisa_proof(pp, accum, w_u.clone(), u, rng).unwrap();

        Ok(proof)
    }
}
