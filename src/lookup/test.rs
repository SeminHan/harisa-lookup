use std::str::FromStr;

use crate::{
    harisa::{
        arithm::ArithmCircuit, bound::BoundCircuit, harisa::Harisa, type_conversion::bigint_to_fr,
        hash_to_prime::primality_test
    },
    linker::snark::LinkSnark,
    lookup::{
        constants::PRIME, copy_this_or_that::CTTCircuit, lookup::HarisaPlus,
        well_transformed::WTCircuit,
    },
};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::{test_rng, One, Zero,
    rand::{Rng, RngCore, SeedableRng}
};
use num_bigint::BigInt;
// use rand_core::{RngCore, SeedableRng};
use rand::thread_rng;

fn rand_setgen(n: usize, low: u32, high: u32) -> Vec<BigInt> {
    let mut rand_set: Vec<BigInt> = Vec::new();
    let base_2: i32 = 2;
    let mut rng = thread_rng();

    for i in 0..n { 
        let mut tmp_elem = BigInt::from(rng.gen_range(base_2.pow(low)..base_2.pow(high)));
        if primality_test(&tmp_elem, 10) {
            tmp_elem <<= 1;
        }
        rand_set.push(tmp_elem);
    }

    rand_set
}

fn lookup_setgen(n: usize, set: Vec<BigInt>) -> (Vec<BigInt>, Vec<BigInt>) {
    use crate::harisa::hash_to_prime::hash_to_prime;
    use rand::thread_rng;
    let base_2: i32 = 2;
    let expo = 11;

    let mut z_prime: Vec<BigInt> = Vec::new();
    let mut z_len = BigInt::from(base_2.pow(expo));
    
    let mut prime_table: Vec<BigInt> = Vec::new();

    for f in set {
        let mut tmp_z = BigInt::from(1627);
        let mut tmp_f = f.clone() * z_len.clone() + tmp_z.clone();
       
        while !(primality_test(&tmp_f.clone(), 10) 
        && primality_test(&tmp_z.clone(), 10)
        && !prime_table.contains(&tmp_f.clone())
        && !z_prime.contains(&tmp_z.clone())
        ) {
            tmp_z += BigInt::one();
            tmp_f += BigInt::one();
        }
        prime_table.push(tmp_f.clone());
        z_prime.push(tmp_z.clone());
    }

    (prime_table, z_prime)
}

fn test_lookup<E: Pairing>(l_size: usize)
where
    <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
{
    let mut set_hat = Vec::new();
    for p_i in PRIME.clone() {
        set_hat.push(BigInt::from(p_i));
    }

    let (mut set, mut z) = (Vec::new(), Vec::new());

    for s_i in set_hat.clone() {
        // 2^14 = 16384
        let f_i = s_i.clone() / 2_i128.pow(14);
        let z_i = s_i % 2_i128.pow(14);

        set.push(f_i);
        z.push(z_i);
    }

    let mut f_hat = Vec::new();
    let mut f = Vec::new();
    let mut z_f = Vec::new();
    for i in 0..l_size {
        f_hat.push(set_hat[i].clone());
        f.push(set[i].clone());
        z_f.push(z[i].clone());
    }

    // lookup
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let arithm_circuit = ArithmCircuit::<E::ScalarField>::mock(2 * l_size);
    let bound_circuit = BoundCircuit::<E::ScalarField>::mock(2 * l_size);
    let ctt_circuit = CTTCircuit::<E::ScalarField>::mock(2 * l_size, 2 * l_size);
    let wt_circuit = WTCircuit::<E::ScalarField>::mock(l_size, l_size, l_size);

    let mut binding = set_hat.clone();
    let mut sorted_set: Vec<BigInt> = binding.drain(..l_size).collect();

    sorted_set = [sorted_set, z.clone(), binding].concat();

    let (pp, tree) =
        HarisaPlus::<E, Harisa<E, LinkSnark<E>>, LinkSnark<E>>::generate_lookup_parameters(
            sorted_set.clone(),
            ctt_circuit,
            wt_circuit,
            arithm_circuit,
            bound_circuit,
            &mut rng,
        )
        .unwrap();

    let accum = tree[0].clone().modpow(&sorted_set[0], &pp.m_pp.mod_n);

    let mut circuit_set_hat: Vec<E::ScalarField> = Vec::new();
    let mut circuit_set: Vec<E::ScalarField> = Vec::new();
    let mut circuit_z: Vec<E::ScalarField> = Vec::new();
    let mut circuit_f_hat: Vec<E::ScalarField> = Vec::new();
    let mut circuit_f: Vec<E::ScalarField> = Vec::new();
    let mut circuit_z_f: Vec<E::ScalarField> = Vec::new();

    for s_hat_i in set.clone() {
        circuit_set_hat.push(bigint_to_fr(s_hat_i));
    }

    for s_i in set.clone() {
        circuit_set.push(bigint_to_fr(s_i));
    }

    for z_i in z.clone() {
        circuit_z.push(bigint_to_fr(z_i));
    }

    for f_hat_i in f_hat.clone() {
        circuit_f_hat.push(bigint_to_fr(f_hat_i));
    }

    for i in 0..f_hat.clone().len() {
        circuit_f.push(circuit_set[i]);
    }

    for i in 0..f_hat.clone().len() {
        circuit_z_f.push(circuit_z[i]);
    }

    let ctt_elem = [circuit_f_hat.clone(), circuit_z_f.clone()].concat();

    let ctt_circuit = CTTCircuit::<E::ScalarField>::new(ctt_elem.clone(), ctt_elem.clone());

    let wt_circuit = WTCircuit::<E::ScalarField>::new(
        circuit_f_hat.clone(),
        circuit_f.clone(),
        circuit_z_f.clone(),
    );

    let proof = HarisaPlus::<E, Harisa<E, LinkSnark<E>>, LinkSnark<E>>::generate_lookup_proof(
        pp.clone(),
        accum.clone(),
        tree,
        f_hat,
        f,
        z_f,
        ctt_circuit,
        wt_circuit,
        &mut rng,
    )
    .unwrap();

    assert!(
        HarisaPlus::<E, Harisa<E, LinkSnark<E>>, LinkSnark<E>>::verify_lookup(
            pp,
            accum,
            proof.cm_f_hat,
            proof.cm_f,
            proof.cm_z,
            proof
        )
        .unwrap(),
        "[Harisa+] Verify Failed"
    );
}

const SET_SIZE: usize = 16;

#[test]
fn test_lookup_bn254() {
    use ark_bn254::{Bn254, Fr as F};

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    test_lookup::<Bn254>(SET_SIZE);
}

#[test]
fn test_lookup_gen() {
    let mut table = Vec::new();
    let mut prime_table = Vec::new();
    let mut z_table = Vec::new();
    
    let set_size = 10;
    let low = 8;
    let high = 16;
    table = rand_setgen(set_size.clone(), low.clone(), high.clone());
    
    (prime_table, z_table) = lookup_setgen(set_size.clone(), table.clone());

    // %%%%%%%%%%%%%%%%%%%%%%%% For Debug %%%%%%%%%%%%%%%%%%%%%%%%
    // for i in 0..set_size.clone() { 
    //     println!("f_{:?}: {:?}", i, prime_table[i].clone());
    //     println!("z_{:?}: {:?}", i, z_table[i].clone());
    //     assert_eq!(
    //         primality_test(&prime_table[i].clone(), 10),
    //         true,
    //         "table [{:}] is not a prime element: {:}", i, prime_table[i]
    //     );
    //     assert_eq!(
    //         primality_test(&z_table[i].clone(), 10),
    //         true,
    //         "z_{:} is not a prime element: {:}", i, z_table[i]
    //     );
    // }
}

// cargo test -r --package harisa-rs --features "parallel print-trace" --lib -- lookup::test::test_lookup_bn254 --exact --show-output
