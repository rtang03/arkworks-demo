use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

pub struct Multipler<F: Field> {
    pub output: Option<F>,
    pub input1: Option<F>,
    pub input2: Option<F>,
}

impl<F: Field> Multipler<F> {
    pub fn new_empty() -> Self {
        Self {
            output: None,
            input1: None,
            input2: None,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for Multipler<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // let i1 = Input1Var::new_witness(ark_relations::ns!(cs, "Input1"), || {
        //     self.input1.ok_or(SynthesisError::AssignmentMissing)
        // });
        // public
        let output_var =
            cs.new_input_variable(|| self.output.ok_or(SynthesisError::AssignmentMissing))?;
        // witness is private
        let input1_var =
            cs.new_witness_variable(|| self.input1.ok_or(SynthesisError::AssignmentMissing))?;
        let input2_var =
            cs.new_witness_variable(|| self.input2.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + input1_var, lc!() + input2_var, lc!() + output_var)?;
        Ok(())
    }
}
