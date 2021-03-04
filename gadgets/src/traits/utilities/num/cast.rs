use snarkvm_r1cs::errors::SynthesisError;

use crate::utilities::{boolean::Boolean, int::*, num::Number, uint::*};

pub trait ReinterpretCastGadget: Number {
    fn reinterpret_cast<Target: Number>(&self) -> Result<Target, SynthesisError> {
        let bits = self.to_bits_le();
        if Target::SIZE <= Self::SIZE {
            Ok(Target::from_bits_le(&bits[0..Target::SIZE]))
        } else {
            let mut bits = bits;
            if Self::SIGNED {
                let last_bit = bits[bits.len() - 1].clone();
                for _ in Self::SIZE..Target::SIZE {
                    bits.push(last_bit.clone());
                }
            } else {
                for _ in Self::SIZE..Target::SIZE {
                    bits.push(Boolean::Constant(false));
                }
            }
            Ok(Target::from_bits_le(&bits[0..Target::SIZE]))
        }
    }
}

macro_rules! add_reinterpret_cast_impl {
    ($($gadget: ident),*) => ($(
        impl ReinterpretCastGadget for $gadget {}
    )*)
}

add_reinterpret_cast_impl!(
    UInt8, UInt16, UInt32, UInt64, UInt128, Int8, Int16, Int32, Int64, Int128
);

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm_r1cs::{ConstraintSystem, Fr, TestConstraintSystem};

    use crate::utilities::alloc::AllocGadget;

    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    macro_rules! test_reinterpret_cast_impl {
        ($name: ident, $from_type: ty, $from_type_rust: ty, $to_type: ty, $to_type_rust: ty) => {
            #[test]
            fn $name() {
                let mut rng = XorShiftRng::seed_from_u64(116752139u64);

                for _ in 0..100 {
                    let mut cs = TestConstraintSystem::<Fr>::new();

                    let from_value: $from_type_rust = rng.gen();

                    let to_value = from_value as $to_type_rust;

                    let from_const_bit = <$from_type>::constant(from_value);
                    let from_alloc_bit = <$from_type>::alloc(cs.ns(|| "from bit"), || Ok(from_value)).unwrap();

                    let to_const_bit: $to_type = from_const_bit.reinterpret_cast().unwrap();
                    let to_alloc_bit: $to_type = from_alloc_bit.reinterpret_cast().unwrap();

                    assert!(cs.is_satisfied());

                    assert_eq!(to_const_bit.const_value(), Some(to_value));
                    assert_eq!(to_alloc_bit.value(), Some(to_value));
                }
            }
        };
    }

    test_reinterpret_cast_impl!(test_u8_to_u16_cast, UInt8, u8, UInt16, u16);

    test_reinterpret_cast_impl!(test_u8_to_u128_cast, UInt8, u8, UInt128, u128);

    test_reinterpret_cast_impl!(test_u16_to_u8_cast, UInt16, u16, UInt8, u8);

    test_reinterpret_cast_impl!(test_u128_to_u8_cast, UInt128, u128, UInt8, u8);

    test_reinterpret_cast_impl!(test_i8_to_i16_cast, Int8, i8, Int16, i16);

    test_reinterpret_cast_impl!(test_i8_to_i128_cast, Int8, i8, Int128, i128);

    test_reinterpret_cast_impl!(test_i16_to_i8_cast, Int16, i16, Int8, i8);

    test_reinterpret_cast_impl!(test_i128_to_i8_cast, Int128, i128, Int8, i8);

    test_reinterpret_cast_impl!(test_u8_to_i16_cast, UInt8, u8, Int16, i16);

    test_reinterpret_cast_impl!(test_u8_to_i128_cast, UInt8, u8, Int128, i128);

    test_reinterpret_cast_impl!(test_u16_to_i8_cast, UInt16, u16, Int8, i8);

    test_reinterpret_cast_impl!(test_u128_to_i8_cast, UInt128, u128, Int8, i8);

    test_reinterpret_cast_impl!(test_i8_to_u16_cast, Int8, i8, UInt16, u16);

    test_reinterpret_cast_impl!(test_i8_to_u128_cast, Int8, i8, UInt128, u128);

    test_reinterpret_cast_impl!(test_i16_to_u8_cast, Int16, i16, UInt8, u8);

    test_reinterpret_cast_impl!(test_i128_to_u8_cast, Int128, i128, UInt8, u8);
}
