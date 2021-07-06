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

use crate::ahp::matrices::make_matrices_square;
use snarkvm_fields::Field;
use snarkvm_r1cs::{
    errors::SynthesisError,
    ConstraintSystem,
    Index as VarIndex,
    LinearCombination,
    OptimizationGoal,
    Variable,
};

pub(crate) struct ProverConstraintSystem<F: Field> {
    pub(crate) public_variables: Vec<F>,
    pub(crate) private_variables: Vec<F>,
    pub(crate) num_public_variables: usize,
    pub(crate) num_private_variables: usize,
    pub(crate) num_constraints: usize,
    pub(crate) optimization_goal: OptimizationGoal,
}

impl<F: Field> ProverConstraintSystem<F> {
    pub(crate) fn new() -> Self {
        Self {
            public_variables: vec![F::one()],
            private_variables: Vec::new(),
            num_public_variables: 1usize,
            num_private_variables: 0usize,
            num_constraints: 0usize,
            optimization_goal: OptimizationGoal::Constraints,
        }
    }

    /// Formats the public input according to the requirements of the constraint
    /// system
    pub(crate) fn format_public_input(public_input: &[F]) -> Vec<F> {
        let mut input = vec![F::one()];
        input.extend_from_slice(public_input);
        input
    }

    /// Takes in a previously formatted public input and removes the formatting
    /// imposed by the constraint system.
    pub(crate) fn unformat_public_input(input: &[F]) -> Vec<F> {
        input[1..].to_vec()
    }

    pub(crate) fn make_matrices_square(&mut self) {
        let num_variables = self.num_public_variables + self.num_private_variables;
        make_matrices_square(self, num_variables);
        assert_eq!(
            self.num_public_variables + self.num_private_variables,
            self.num_constraints,
            "padding failed!"
        );
    }
}

impl<F: Field> ConstraintSystem<F> for ProverConstraintSystem<F> {
    type Root = Self;

    #[inline]
    fn alloc<Fn, A, AR>(&mut self, _: A, f: Fn) -> Result<Variable, SynthesisError>
    where
        Fn: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        let index = self.num_private_variables;
        self.num_private_variables += 1;

        self.private_variables.push(f()?);
        Ok(Variable::new_unchecked(VarIndex::Private(index)))
    }

    #[inline]
    fn alloc_input<Fn, A, AR>(&mut self, _: A, f: Fn) -> Result<Variable, SynthesisError>
    where
        Fn: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        let index = self.num_public_variables;
        self.num_public_variables += 1;

        self.public_variables.push(f()?);
        Ok(Variable::new_unchecked(VarIndex::Public(index)))
    }

    #[inline]
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, _: LA, _: LB, _: LC)
    where
        A: FnOnce() -> AR,
        AR: AsRef<str>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: AsRef<str>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

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

    fn optimization_goal(&self) -> OptimizationGoal {
        self.optimization_goal.clone()
    }

    fn set_optimization_goal(&mut self, goal: OptimizationGoal) {
        // `set_optimization_type` should only be executed before any constraint or value is created.
        assert_eq!(self.num_public_variables, 1);
        assert_eq!(self.num_private_variables, 0);
        assert_eq!(self.num_constraints, 0);

        self.optimization_goal = goal;
    }
}
