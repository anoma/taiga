use crate::{
    circuit::{
        note_circuit::NoteConfig,
        vp_circuit::{
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::Note,
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
use rand::rngs::OsRng;
use rand::RngCore;

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

#[derive(Clone, Debug)]
pub struct DummyValidityPredicateConfig {
    note_conifg: NoteConfig,
}

impl ValidityPredicateConfig for DummyValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);
        Self { note_conifg }
    }
}

impl TrivialValidityPredicateCircuit {
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let owned_note_pub_id = pallas::Base::zero();
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        Self {
            owned_note_pub_id,
            input_notes,
            output_notes,
        }
    }
}

impl ValidityPredicateInfo for TrivialValidityPredicateCircuit {
    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        self.get_note_instances()
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

impl ValidityPredicateCircuit for TrivialValidityPredicateCircuit {
    type VPConfig = DummyValidityPredicateConfig;
}

vp_circuit_impl!(TrivialValidityPredicateCircuit);

#[test]
fn test_halo2_dummy_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = TrivialValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
