use std::marker::PhantomData;

use crate::linker::{
    matrix::{scalar_vector_mult, SparseLinAlgebra, SparseMatrix},
    // relation_generator::generate_cp_relation,
    relation_generator::*,
    Linker,
};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, One, UniformRand, Zero};
use std::ops::{AddAssign, Mul};

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PP<
    G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
    G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
> {
    pub l: usize, // # of rows
    pub t: usize, // # of cols
    pub g1: G1,
    pub g2: G2,
}

impl<
        G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
        G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
    > PP<G1, G2>
{
    pub fn new(l: usize, t: usize, g1: &G1, g2: &G2) -> PP<G1, G2> {
        PP {
            l,
            t,
            g1: g1.clone(),
            g2: g2.clone(),
        }
    }
}

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EK<G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize> {
    pub p: Vec<G1>,
}

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VK<G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize> {
    pub c: Vec<G2>,
    pub a: G2,
}

fn vec_to_g2<E: Pairing>(
    pp: &PP<E::G1Affine, E::G2Affine>,
    v: &Vec<E::ScalarField>,
) -> Vec<E::G2Affine> {
    v.iter()
        .map(|x| (pp.g2 * x).into_affine())
        .collect::<Vec<_>>()
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct LinkSnark<E: Pairing> {
    _curve: PhantomData<E>,
}

impl<E: Pairing> Linker<E> for LinkSnark<E> {
    type Instance = Vec<E::G1Affine>;
    type Witness = Vec<E::ScalarField>;

    type CM = PhantomData<E>;
    type EK = EK<E::G1Affine>;
    type VK = VK<E::G2Affine>;

    type CRS = SparseMatrix<E::G1Affine>;
    type PP = PP<E::G1Affine, E::G2Affine>;
    type Proof = E::G1Affine;

    fn setup<R: Rng>(
        num: usize,
        ck: Vec<E::G1Affine>,
        snark_ck: Vec<E::G1Affine>,
        rng: &mut R,
    ) -> (Self::PP, Self::CRS) {
        let g1 = E::G1::rand(rng).into_affine();
        let g2 = E::G2::rand(rng).into_affine();

        let link_crs = generate_cp_arithm_relation::<E>(num, ck, snark_ck);

        let l = link_crs.nr;
        let t = link_crs.nc;

        let mut link_pp = PP::<E::G1Affine, E::G2Affine> { l, t, g1, g2 };
        (link_pp, link_crs)
    }

    fn keygen<R: Rng>(pp: &Self::PP, crs: Self::CRS, rng: &mut R) -> (Self::EK, Self::VK) {
        // Create an empty vector to hold k values
        let mut k = Vec::with_capacity(pp.l);
        // Generate random k values and append them to the k vector
        for _ in 0..pp.l {
            k.push(E::ScalarField::rand(rng));
        }

        // Generate a random scalar field value a
        let a = E::ScalarField::rand(rng);
        // Calculate the vector p as the result of multiplying the sparse matrix m with k
        let p = SparseLinAlgebra::<E>::sparse_vector_matrix_mult(&k, &crs, pp.t);
        // Calculate the vector c as the result of multiplying a with each element in k
        let c = scalar_vector_mult::<E>(&a, &k, pp.l);
        // Create an EK struct with the calculated vector p
        let ek = EK::<E::G1Affine> { p };
        // Convert the vector c to G2 and create a VK struct with the converted vector c and the value (pp.g2 * a)
        let vk = VK::<E::G2Affine> {
            c: vec_to_g2::<E>(pp, &c),
            a: (pp.g2 * a).into_affine(),
        };
        // Return the EK and VK structs as a tuple
        (ek, vk)
    }

    fn prove<R: Rng>(
        pp: &Self::PP,
        ek: &Self::EK,
        witness: Self::Witness,
        rng: &mut R,
    ) -> (Self::Proof, Self::CM) {
        (
            Self::inner_product(ek.p.clone(), witness.to_vec()),
            PhantomData,
        )
    }

    fn verify(pp: &Self::PP, vk: &Self::VK, instance: &Self::Instance, prf: &Self::Proof) -> bool {
        assert_eq!(pp.l, instance.len());
        let mut g1 = vec![];
        let mut g2 = vec![];
        for i in 0..instance.len() {
            g1.push(E::G1Prepared::from(instance[i]));
            g2.push(E::G2Prepared::from(vk.c[i]));
        }
        g1.push(E::G1Prepared::from(*prf));
        g2.push(E::G2Prepared::from(-vk.a.into_group()));
        E::TargetField::one() == E::multi_pairing(g1.into_iter(), g2.into_iter()).0
    }
}

impl<E: Pairing> LinkSnark<E> {
    fn inner_product(w: Vec<E::G1Affine>, v: Vec<E::ScalarField>) -> E::G1Affine {
        // Take two slices of `ScalarField` and `G1Affine` elements and compute their inner product
        assert_eq!(v.len(), w.len());
        let mut res: E::G1 = E::G1::zero(); // Initialize a variable to hold the result of the inner product
        for i in 0..v.len() {
            let tmp = w[i].mul(v[i]); // Multiply the i-th element of `v` and `w` and store it in a temporary variable
            res.add_assign(&tmp); // Add the result of the multiplication to `res`
        }
        res.into_affine() // Convert `res` to an affine point and return it
    }

    pub fn generate_witness(
        r: Vec<E::ScalarField>,
        u: Vec<E::ScalarField>,
        snark_witness: Vec<E::ScalarField>,
    ) -> <LinkSnark<E> as Linker<E>>::Witness {
        let witness = generate_cp_arithm_witness::<E>(r, u, snark_witness).unwrap();

        witness
    }

    pub fn generate_instance(
        cm: Vec<E::G1Affine>,
        snark_cm: E::G1Affine,
        aux_cm: <LinkSnark<E> as Linker<E>>::CM,
    ) -> <LinkSnark<E> as Linker<E>>::Instance {
        let instance = generate_cp_arithm_instance::<E>(cm, snark_cm).unwrap();

        instance
    }
}
