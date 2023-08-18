use crate::{
    circuit::vp_circuit::{
        VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
        ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, RandomSeed},
    proof::Proof,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::pallas;
use rand::{rngs::OsRng, RngCore};

pub mod cascade_intent;
mod field_addition;
pub mod or_relation_intent;
pub mod partial_fulfillment_intent;
pub mod receiver_vp;
pub mod signature_verification;
pub mod token;

lazy_static! {
    pub static ref TRIVIAL_VP_VK: ValidityPredicateVerifyingKey =
        TrivialValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_TRIVIAL_VP_VK: pallas::Base = TRIVIAL_VP_VK.get_compressed();
}

// TrivialValidityPredicateCircuit with empty custom constraints.
#[derive(Clone, Debug, Default)]
pub struct TrivialValidityPredicateCircuit {
    pub owned_note_pub_id: pallas::Base,
    pub input_notes: [Note; NUM_NOTE],
    pub output_notes: [Note; NUM_NOTE],
}

impl TrivialValidityPredicateCircuit {
    pub fn new(
        owned_note_pub_id: pallas::Base,
        input_notes: [Note; NUM_NOTE],
        output_notes: [Note; NUM_NOTE],
    ) -> Self {
        Self {
            owned_note_pub_id,
            input_notes,
            output_notes,
        }
    }
}

impl ValidityPredicateCircuit for TrivialValidityPredicateCircuit {
    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ValidityPredicatePublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let padding = ValidityPredicatePublicInputs::get_public_input_padding(
            public_inputs.len(),
            &RandomSeed::random(&mut rng),
        );
        public_inputs.extend(padding);
        public_inputs.into()
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

vp_circuit_impl!(TrivialValidityPredicateCircuit);

#[cfg(test)]
pub mod tests {
    use super::TrivialValidityPredicateCircuit;
    use crate::{
        constant::NUM_NOTE,
        note::tests::{random_input_note, random_output_note},
    };
    use ff::Field;
    use pasta_curves::pallas;
    use rand::RngCore;
    pub fn random_trivial_vp_circuit<R: RngCore>(mut rng: R) -> TrivialValidityPredicateCircuit {
        let owned_note_pub_id = pallas::Base::random(&mut rng);
        let input_notes = [(); NUM_NOTE].map(|_| random_input_note(&mut rng));
        let output_notes = input_notes
            .iter()
            .map(|input| random_output_note(&mut rng, input.get_nf().unwrap()))
            .collect::<Vec<_>>();
        TrivialValidityPredicateCircuit::new(
            owned_note_pub_id,
            input_notes,
            output_notes.try_into().unwrap(),
        )
    }

    #[test]
    fn test_halo2_trivial_vp_circuit() {
        use crate::circuit::vp_circuit::ValidityPredicateCircuit;
        use halo2_proofs::dev::MockProver;
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let circuit = random_trivial_vp_circuit(&mut rng);
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover =
            MockProver::<pallas::Base>::run(12, &circuit, vec![public_inputs.to_vec()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
