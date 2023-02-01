use crate::{
    circuit::{
        note_circuit::NoteConfig,
        vp_circuit::{
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo,
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
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

mod field_addition;

// TrivialValidityPredicateCircuit with empty custom constraints.
#[derive(Clone, Debug, Default)]
pub struct TrivialValidityPredicateCircuit {
    pub spend_notes: [Note; NUM_NOTE],
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
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        Self {
            spend_notes,
            output_notes,
        }
    }
}

impl ValidityPredicateInfo for TrivialValidityPredicateCircuit {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        self.get_note_instances()
    }

    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        let pk = keygen_pk(params, vk.clone(), self).expect("keygen_pk should not fail");
        let instance = self.get_instances();
        let proof = Proof::create(&pk, &params, self.clone(), &[&instance], &mut rng).unwrap();
        VPVerifyingInfo {
            vk,
            proof,
            instance,
        }
    }

    fn get_vp_description(&self) -> ValidityPredicateVerifyingKey {
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        ValidityPredicateVerifyingKey::from_vk(vk)
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
