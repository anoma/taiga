use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{self, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas;

extern crate taiga_halo2;
use taiga_halo2::{
    circuit::{
        integrity::{OutputNoteVar, SpendNoteVar},
        note_circuit::NoteConfig,
        vp_circuit::{
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::Note,
    proof::Proof,
    vp_circuit_impl,
    vp_vk::ValidityPredicateVerifyingKey,
};

use rand::rngs::OsRng;

// Different tokens can use the same token application VP but different `app_data` to distinguish the type of token. We can encode “ETH”, “BTC” or other property of the token into `app_data` to make the application type unique.

#[derive(Clone, Debug, Default)]
pub struct UserVP {
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
}

#[derive(Clone, Debug)]
pub struct UserVPConfig {
    note_config: NoteConfig,
}

impl ValidityPredicateConfig for UserVPConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_config.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_config = Self::configure_note(meta);
        Self { note_config }
    }
}

impl UserVP {
    pub fn new(spend_notes: [Note; NUM_NOTE], output_notes: [Note; NUM_NOTE]) -> Self {
        Self {
            spend_notes,
            output_notes,
        }
    }
}

impl ValidityPredicateCircuit for UserVP {
    type VPConfig = UserVPConfig;

    fn custom_constraints(
        &self,
        _config: Self::VPConfig,
        _layouter: impl Layouter<pallas::Base>,
        _spend_note_variables: &[SpendNoteVar],
        _output_note_variables: &[OutputNoteVar],
    ) -> Result<(), plonk::Error> {
        Ok(())
    }
}

impl ValidityPredicateInfo for UserVP {
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

vp_circuit_impl!(UserVP);