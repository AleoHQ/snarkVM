// Copyright (C) 2019-2021 Aleo Systems Inc.
// This file is part of the snarkVM library.

// The snarkVM library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkVM library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkVM library. If not, see <https://www.gnu.org/licenses/>.

//
// Acknowledgements
//
// This implementation of Poseidon is entirely from Fractal's implementation
// ([COS20]: https://eprint.iacr.org/2019/1076) with small syntax changes.
//

use snarkvm_fields::PrimeField;
use snarkvm_gadgets::{
    algorithms::crypto_hash::{CryptographicSpongeVar, PoseidonSpongeGadget},
    fields::FpGadget,
    traits::alloc::AllocGadget,
};
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};

use crate::fiat_shamir::{fiat_shamir_poseidon_sponge::PoseidonSponge, traits::AlgebraicSpongeVar};
use snarkvm_algorithms::crypto_hash::PoseidonDefaultParametersField;

#[derive(Clone)]
/// the gadget for Poseidon sponge
pub struct PoseidonSpongeVar<F: PrimeField + PoseidonDefaultParametersField> {
    /// The actual sponge
    pub sponge_var: PoseidonSpongeGadget<F>,
}

impl<F: PrimeField + PoseidonDefaultParametersField> AlgebraicSpongeVar<F, PoseidonSponge<F>> for PoseidonSpongeVar<F> {
    fn new<CS: ConstraintSystem<F>>(mut cs: CS) -> Self {
        let params = F::get_default_poseidon_parameters(6, false).unwrap();
        let sponge_var = PoseidonSpongeGadget::<F>::new(cs.ns(|| "alloc sponge"), &params);
        Self { sponge_var }
    }

    fn constant<CS: ConstraintSystem<F>>(mut cs: CS, pfs: &PoseidonSponge<F>) -> Self {
        let params = F::get_default_poseidon_parameters(6, false).unwrap();
        let mut sponge_var = PoseidonSpongeGadget::<F>::new(cs.ns(|| "alloc sponge"), &params);

        for (i, state_elem) in pfs.sponge.state.iter().enumerate() {
            sponge_var.state[i] =
                FpGadget::<F>::alloc_constant(cs.ns(|| format!("alloc_elems_{}", i)), || Ok((*state_elem).clone()))
                    .unwrap();
        }
        sponge_var.mode = pfs.sponge.mode.clone();

        Self { sponge_var }
    }

    fn absorb<CS: ConstraintSystem<F>>(&mut self, mut cs: CS, elems: &[FpGadget<F>]) -> Result<(), SynthesisError> {
        self.sponge_var.absorb(cs.ns(|| "absorb"), elems.iter())
    }

    fn squeeze<CS: ConstraintSystem<F>>(&mut self, mut cs: CS, num: usize) -> Result<Vec<FpGadget<F>>, SynthesisError> {
        self.sponge_var.squeeze_field_elements(cs.ns(|| "squeeze"), num)
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    use snarkvm_curves::bls12_377::Fq;
    use snarkvm_gadgets::traits::eq::EqGadget;
    use snarkvm_r1cs::TestConstraintSystem;
    use snarkvm_utilities::rand::UniformRand;

    use crate::fiat_shamir::traits::AlgebraicSponge;

    use super::*;

    type Sponge = PoseidonSponge<Fq>;
    type SpongeVar = PoseidonSpongeVar<Fq>;

    const MAX_ELEMENTS: usize = 100;
    const ITERATIONS: usize = 100;

    #[test]
    fn test_poseidon_sponge_constant() {
        let mut rng = ChaChaRng::seed_from_u64(123456789u64);

        for i in 0..ITERATIONS {
            let mut cs = TestConstraintSystem::<Fq>::new();

            // Create a new algebraic sponge.
            let mut sponge = Sponge::new();

            // Generate random elements to absorb.
            let num_elements: usize = rng.gen_range(0..MAX_ELEMENTS);
            let elements: Vec<_> = (0..num_elements).map(|_| Fq::rand(&mut rng)).collect();

            // Absorb the random elements.
            sponge.absorb(&elements);

            // Alloc the sponge gadget from a given sponge.
            let mut sponge_gadget = SpongeVar::constant(cs.ns(|| format!("poseidon_sponge_constant_{}", i)), &sponge);

            // Squeeze the elements from the sponge and sponge gadget.
            let sponge_squeeze = sponge.squeeze(num_elements);
            let sponge_gadget_squeeze = sponge_gadget
                .squeeze(cs.ns(|| format!("squeeze_{}", i)), num_elements)
                .unwrap();

            // Check that the squeeze results are equivalent.
            for (j, (gadget, element)) in sponge_gadget_squeeze.iter().zip(sponge_squeeze).enumerate() {
                // Allocate the field gadget from the base element.
                let alloc_element =
                    FpGadget::alloc(cs.ns(|| format!("alloc_field_{}_{}", i, j)), || Ok(element)).unwrap();

                // Check that the elements are equivalent.
                gadget
                    .enforce_equal(cs.ns(|| format!("enforce_equal_element_{}_{}", i, j)), &alloc_element)
                    .unwrap();
            }
        }
    }

    #[test]
    fn test_poseidon_sponge_squeeze() {
        let mut rng = ChaChaRng::seed_from_u64(123456789u64);

        for i in 0..ITERATIONS {
            let mut cs = TestConstraintSystem::<Fq>::new();

            // Create a new algebraic sponge.
            let mut sponge = Sponge::new();

            // Alloc the sponge gadget from a given sponge.
            let mut sponge_gadget = SpongeVar::new(cs.ns(|| format!("new_poseidon_sponge_{}", i)));

            // Generate random elements to absorb.
            let num_elements: usize = rng.gen_range(0..MAX_ELEMENTS);
            let elements: Vec<_> = (0..num_elements).map(|_| Fq::rand(&mut rng)).collect();

            let mut element_gadgets = vec![];
            for (j, element) in elements.iter().enumerate() {
                // Allocate the field gadget from the base element.
                let alloc_element =
                    FpGadget::alloc(cs.ns(|| format!("native_alloc_field_{}_{}", i, j)), || Ok(element)).unwrap();

                element_gadgets.push(alloc_element);
            }

            // Absorb the random elements.
            sponge.absorb(&elements);
            sponge_gadget
                .absorb(cs.ns(|| format!("absorb_{}", i)), &element_gadgets)
                .unwrap();

            // Squeeze the elements from the sponge and sponge gadget.
            let sponge_squeeze = sponge.squeeze(num_elements);
            let sponge_gadget_squeeze = sponge_gadget
                .squeeze(cs.ns(|| format!("squeeze_{}", i)), num_elements)
                .unwrap();

            // Check that the squeeze results are equivalent.
            for (j, (gadget, element)) in sponge_gadget_squeeze.iter().zip(sponge_squeeze).enumerate() {
                // Allocate the field gadget from the base element.
                let alloc_element =
                    FpGadget::alloc(cs.ns(|| format!("squeeze_alloc_field_{}_{}", i, j)), || Ok(element)).unwrap();

                // Check that the elements are equivalent.
                gadget
                    .enforce_equal(cs.ns(|| format!("enforce_equal_element_{}_{}", i, j)), &alloc_element)
                    .unwrap();
            }
        }
    }
}
