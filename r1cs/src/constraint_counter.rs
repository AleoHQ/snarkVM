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

use crate::{errors::SynthesisError, ConstraintSystem, Index, LinearCombination, OptimizationGoal, Variable};
use snarkvm_fields::Field;

/// Constraint counter for testing purposes.
#[derive(Default)]
pub struct ConstraintCounter {
    pub num_public_variables: usize,
    pub num_private_variables: usize,
    pub num_constraints: usize,
    pub optimization_goal: OptimizationGoal,
}

impl<ConstraintF: Field> ConstraintSystem<ConstraintF> for ConstraintCounter {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<ConstraintF, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        let var = Variable::new_unchecked(Index::Private(self.num_private_variables));
        self.num_private_variables += 1;
        Ok(var)
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<ConstraintF, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        let var = Variable::new_unchecked(Index::Public(self.num_public_variables));
        self.num_public_variables += 1;

        Ok(var)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, _: LA, _: LB, _: LC)
    where
        A: FnOnce() -> AR,
        AR: AsRef<str>,
        LA: FnOnce(LinearCombination<ConstraintF>) -> LinearCombination<ConstraintF>,
        LB: FnOnce(LinearCombination<ConstraintF>) -> LinearCombination<ConstraintF>,
        LC: FnOnce(LinearCombination<ConstraintF>) -> LinearCombination<ConstraintF>,
    {
        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: AsRef<str>,
        N: FnOnce() -> NR,
    {
    }

    fn pop_namespace(&mut self) {}

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    fn num_public_variables(&self) -> usize {
        self.num_public_variables
    }

    fn num_private_variables(&self) -> usize {
        self.num_private_variables
    }

    #[inline]
    fn optimization_goal(&self) -> OptimizationGoal {
        self.optimization_goal.clone()
    }

    #[inline]
    fn set_optimization_goal(&mut self, goal: OptimizationGoal) {
        // `set_optimization_type` should only be executed before any constraint or value is created.
        assert_eq!(self.num_public_variables, 1);
        assert_eq!(self.num_private_variables, 0);
        assert_eq!(self.num_constraints, 0);

        self.optimization_goal = goal;
    }
}
