use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::prelude::{Circuit, Error, StandardComposer};

pub struct AdditionCircuit<F: PrimeField> {
    a: F,
    b: F,
    pub c: F,
}

impl<F, P> Circuit<F, P> for AdditionCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let var_a = composer.add_input(self.a);
        let var_b = composer.add_input(self.b);
        // add a gate for the addition
        let var_zero = composer.zero_var();
        // Make first constraint a + b = c (as public input)
        composer.arithmetic_gate(|gate| {
            gate.witness(var_a, var_b, Some(var_zero))
                .add(F::one(), F::one())
                .pi(-self.c)
        });
        composer.check_circuit_satisfied();
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 3
    }
}

#[ignore]
#[test]
fn test_circuit_example() {
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::{test_rng, UniformRand};
    use plonk_core::circuit::{verify_proof, VerifierData};

    let mut rng = test_rng();
    let a = F::rand(&mut rng);
    let b = F::rand(&mut rng);
    let c = a + b;

    // Circuit
    let mut circuit = AdditionCircuit::<F> { a, b, c };
    // Setup
    let setup = PC::setup(
        Circuit::<F, P>::padded_circuit_size(&circuit),
        None,
        &mut rng,
    )
    .unwrap();
    // Prover and verifier key
    let (pk, vk) = Circuit::<F, P>::compile::<PC>(&mut circuit, &setup).unwrap();
    // Proof computation
    let (proof, public_inputs) =
        Circuit::<F, P>::gen_proof::<PC>(&mut circuit, &setup, pk, b"Test").unwrap();
    // Proof verification
    let verifier_data = VerifierData::new(vk, public_inputs);
    verify_proof::<F, P, PC>(
        &setup,
        verifier_data.key,
        &proof,
        &verifier_data.pi,
        b"Test",
    )
    .unwrap();
}

#[ignore]
#[test]
fn test_app_creation() {
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::doc_examples::validity_predicate::TrivialValidityPredicate;
    use crate::note::Note;
    use crate::app::App;
    use crate::vp_description::ValidityPredicateDescription;
    use ark_std::test_rng;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    let mut vp = TrivialValidityPredicate::<CP>::new(input_notes, output_notes);

    let vp_setup = CP::get_pc_setup_params(vp.padded_circuit_size());
    let desc_vp = ValidityPredicateDescription::from_vp(&mut vp, vp_setup).unwrap();

    let tok = App::<CP>::new(desc_vp);

    let _tok_addr = tok.address().unwrap();
}

///////////////////////////////////////////////////////////////////////

#[ignore]
#[test]
fn test_user_creation() {
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::doc_examples::validity_predicate::TrivialValidityPredicate;
    use crate::note::Note;
    use crate::user::NullifierDerivingKey;
    use crate::user::User;
    use crate::vp_description::ValidityPredicateDescription;
    use ark_std::test_rng;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    let mut vp = TrivialValidityPredicate::<CP>::new(input_notes, output_notes);

    let vp_setup = CP::get_pc_setup_params(vp.padded_circuit_size());

    let desc_vp_send = ValidityPredicateDescription::from_vp(&mut vp, vp_setup).unwrap();
    let desc_vp_recv = desc_vp_send.clone();

    let alice = User::<CP>::new(
        desc_vp_send,
        desc_vp_recv,
        NullifierDerivingKey::<Fr>::rand(&mut rng),
    );
    let _alice_addr = alice.address().unwrap();
}

#[ignore]
#[test]
fn test_note_creation() {
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::doc_examples::validity_predicate::TrivialValidityPredicate;
    use crate::note::Note;
    use crate::nullifier::Nullifier;
    use crate::app::App;
    use crate::user::NullifierDerivingKey;
    use crate::user::User;
    use crate::vp_description::ValidityPredicateDescription;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    let mut vp = TrivialValidityPredicate::<CP>::new(input_notes, output_notes);

    let vp_setup = CP::get_pc_setup_params(vp.padded_circuit_size());

    // app and user
    let desc_vp_app = ValidityPredicateDescription::from_vp(&mut vp, vp_setup).unwrap();
    let desc_vp_send = desc_vp_app.clone();
    let desc_vp_recv = desc_vp_send.clone();

    let tok = App::<CP>::new(desc_vp_app);
    let alice = User::<CP>::new(
        desc_vp_send,
        desc_vp_recv,
        NullifierDerivingKey::<Fr>::rand(&mut rng),
    );
    // note
    let nf = Nullifier::<CP>::new(Fr::rand(&mut rng));
    let note = Note::<CP>::new(alice, tok, 12, nf, Fr::rand(&mut rng), Fr::rand(&mut rng));

    let _note_commitment = note.commitment();
}
