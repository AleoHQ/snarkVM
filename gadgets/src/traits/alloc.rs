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

use snarkvm_fields::Field;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use std::borrow::Borrow;

pub trait AllocBytesGadget<V: ?Sized, F: Field>: Sized
where
    V: Into<Option<Vec<u8>>>,
{
    fn alloc_bytes<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError>;

    fn alloc_bytes_checked<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        Self::alloc_bytes(cs, f)
    }

    fn alloc_input_bytes<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError>;

    fn alloc_input_bytes_checked<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        Self::alloc_input_bytes(cs, f)
    }
}

// TODO (howardwu): Split this into 3 traits for the constant, public, and private.
pub trait AllocGadget<V: ?Sized, F: Field>: Sized {
    fn alloc_constant<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        _cs: CS,
        _f: Fn,
    ) -> Result<Self, SynthesisError> {
        unimplemented!()
    }

    // TODO (howardwu): Rename to `alloc_private`.
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError>;

    // TODO (howardwu): Rename to `alloc_private_checked`.
    fn alloc_checked<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        Self::alloc(cs, f)
    }

    // TODO (howardwu): Rename to `alloc_public`.
    fn alloc_input<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError>;

    // TODO (howardwu): Rename to `alloc_public_checked`.
    fn alloc_input_checked<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<V>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        Self::alloc_input(cs, f)
    }
}

impl<I, F: Field, A: AllocGadget<I, F>> AllocGadget<[I], F> for Vec<A> {
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<[I]>, CS: ConstraintSystem<F>>(
        mut cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        let f = f()?;
        let mut vec = Vec::with_capacity(f.borrow().len());
        for (i, value) in f.borrow().iter().enumerate() {
            vec.push(A::alloc(&mut cs.ns(|| format!("alloc_{}", i)), || Ok(value))?);
        }
        Ok(vec)
    }

    fn alloc_checked<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<[I]>, CS: ConstraintSystem<F>>(
        mut cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        let f = f()?;
        let mut vec = Vec::with_capacity(f.borrow().len());
        for (i, value) in f.borrow().iter().enumerate() {
            vec.push(A::alloc_checked(&mut cs.ns(|| format!("alloc_checked_{}", i)), || {
                Ok(value)
            })?);
        }
        Ok(vec)
    }

    fn alloc_input<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<[I]>, CS: ConstraintSystem<F>>(
        mut cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        let f = f()?;
        let mut vec = Vec::with_capacity(f.borrow().len());
        for (i, value) in f.borrow().iter().enumerate() {
            vec.push(A::alloc_input(&mut cs.ns(|| format!("alloc_input_{}", i)), || {
                Ok(value)
            })?);
        }
        Ok(vec)
    }

    fn alloc_input_checked<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<[I]>, CS: ConstraintSystem<F>>(
        mut cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        let f = f()?;
        let mut vec = Vec::with_capacity(f.borrow().len());
        for (i, value) in f.borrow().iter().enumerate() {
            vec.push(A::alloc_input_checked(
                &mut cs.ns(|| format!("alloc_input_checked_{}", i)),
                || Ok(value),
            )?);
        }
        Ok(vec)
    }
}
