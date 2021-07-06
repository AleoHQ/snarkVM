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

use crate::{errors::SynthesisError, Index, LinearCombination, Namespace, Variable};
use snarkvm_fields::Field;

use std::marker::PhantomData;

/// Computations are expressed in terms of rank-1 constraint systems (R1CS).
/// The `generate_constraints` method is called to generate constraints for
/// both CRS generation and for proving.
pub trait ConstraintSynthesizer<F: Field> {
    /// Drives generation of new constraints inside `CS`.
    fn generate_constraints<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Result<(), SynthesisError>;
}

/// Defines the parameter to optimize for a `ConstraintSystem`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum OptimizationGoal {
    /// Make no attempt to optimize.
    None,
    /// Minimize the number of constraints.
    Constraints,
    /// Minimize the total weight of the constraints (the number of nonzero
    /// entries across all constraints).
    Weight,
}

impl Default for OptimizationGoal {
    fn default() -> Self {
        Self::Constraints
    }
}

/// Represents a constraint system which can have new variables
/// allocated and constrains between them formed.
pub trait ConstraintSystem<F: Field>: Sized {
    /// Represents the type of the "root" of this constraint system
    /// so that nested namespaces can minimize indirection.
    type Root: ConstraintSystem<F>;

    /// Return the "one" input variable
    fn one() -> Variable {
        Variable::new_unchecked(Index::Public(0))
    }

    /// Allocate a private variable in the constraint system. The provided
    /// function is used to determine the assignment of the variable. The
    /// given `annotation` function is invoked in testing contexts in order
    /// to derive a unique name for this variable in the current namespace.
    fn alloc<FN, A, AR>(&mut self, annotation: A, f: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>;

    /// Allocate a public variable in the constraint system. The provided
    /// function is used to determine the assignment of the variable.
    fn alloc_input<FN, A, AR>(&mut self, annotation: A, f: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>;

    /// Enforce that `A` * `B` = `C`. The `annotation` function is invoked in
    /// testing contexts in order to derive a unique name for the constraint
    /// in the current namespace.
    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: AsRef<str>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>;

    /// Create a new (sub)namespace and enter into it. Not intended
    /// for downstream use; use `namespace` instead.
    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: AsRef<str>,
        N: FnOnce() -> NR;

    /// Exit out of the existing namespace. Not intended for
    /// downstream use; use `namespace` instead.
    fn pop_namespace(&mut self);

    /// Gets the "root" constraint system, bypassing the namespacing.
    /// Not intended for downstream use; use `namespace` instead.
    fn get_root(&mut self) -> &mut Self::Root;

    /// Begin a namespace for this constraint system.
    fn ns<NR, N>(&mut self, name_fn: N) -> Namespace<'_, F, Self::Root>
    where
        NR: AsRef<str>,
        N: FnOnce() -> NR,
    {
        self.get_root().push_namespace(name_fn);

        Namespace(self.get_root(), PhantomData)
    }

    /// Output the number of constraints in the system.
    fn num_constraints(&self) -> usize;

    /// Output the number of public input variables to the system.
    fn num_public_variables(&self) -> usize;

    /// Output the number of private input variables to the system.
    fn num_private_variables(&self) -> usize;

    /// Check whether this constraint system aims to optimize weight,
    /// number of constraints, or neither.
    fn optimization_goal(&self) -> OptimizationGoal;

    /// Specify whether this constraint system should aim to optimize weight,
    /// number of constraints, or neither.
    fn set_optimization_goal(&mut self, goal: OptimizationGoal);
}

/// Convenience implementation of ConstraintSystem<F> for mutable references to
/// constraint systems.
impl<F: Field, CS: ConstraintSystem<F>> ConstraintSystem<F> for &mut CS {
    type Root = CS::Root;

    #[inline]
    fn one() -> Variable {
        CS::one()
    }

    #[inline]
    fn alloc<FN, A, AR>(&mut self, annotation: A, f: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        (**self).alloc(annotation, f)
    }

    #[inline]
    fn alloc_input<FN, A, AR>(&mut self, annotation: A, f: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        (**self).alloc_input(annotation, f)
    }

    #[inline]
    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: AsRef<str>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        (**self).enforce(annotation, a, b, c)
    }

    #[inline]
    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: AsRef<str>,
        N: FnOnce() -> NR,
    {
        (**self).push_namespace(name_fn)
    }

    #[inline]
    fn pop_namespace(&mut self) {
        (**self).pop_namespace()
    }

    #[inline]
    fn get_root(&mut self) -> &mut Self::Root {
        (**self).get_root()
    }

    #[inline]
    fn num_constraints(&self) -> usize {
        (**self).num_constraints()
    }

    #[inline]
    fn num_public_variables(&self) -> usize {
        (**self).num_public_variables()
    }

    #[inline]
    fn num_private_variables(&self) -> usize {
        (**self).num_private_variables()
    }

    #[inline]
    fn optimization_goal(&self) -> OptimizationGoal {
        (**self).optimization_goal()
    }

    #[inline]
    fn set_optimization_goal(&mut self, goal: OptimizationGoal) {
        (**self).set_optimization_goal(goal)
    }
}
