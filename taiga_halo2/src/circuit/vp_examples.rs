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
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas;
use rand::RngCore;

mod field_addition;

// DummyValidityPredicateCircuit with empty custom constraints.
#[derive(Clone, Debug, Default)]
pub struct DummyValidityPredicateCircuit {
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
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

impl DummyValidityPredicateCircuit {
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        Self {
            spend_notes,
            output_notes,
        }
    }
}

impl ValidityPredicateInfo for DummyValidityPredicateCircuit {
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
        use halo2_proofs::{
            plonk::{create_proof, keygen_pk, keygen_vk},
            transcript::Blake2bWrite,
        };
        use pasta_curves::vesta;
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        let pk = keygen_pk(params, vk.clone(), self).expect("keygen_pk should not fail");
        let instance = self.get_instances();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        create_proof(
            params,
            &pk,
            &[self.clone()],
            &[&[&instance]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();
        VPVerifyingInfo {
            param_size: 12,
            vk,
            proof,
            instance,
        }
    }
}

impl ValidityPredicateCircuit for DummyValidityPredicateCircuit {
    type VPConfig = DummyValidityPredicateConfig;
}

vp_circuit_impl!(DummyValidityPredicateCircuit);

#[test]
fn test_halo2_dummy_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = DummyValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
