// Token VP:

// - [X] Check tx is balanced
//      This is already done in basic constraints
// - [] Shield/unshield tokens
// - [] Token-type swap; mint/burn new/old token

// Define the token type
// How to encode the data to value base?
// Make the type of the value base unique
// How to spend the note and how to create the note?
// In previous versions, we have sendvp and receivevp and encode those into the `sub_app_data`
// The spendvp is more important. For now, everyone can receive the notes
// The sendvp needs to check signature check

// Define note application
// Use empty send vp
// Apply signature check


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

// For example, assuming we have a general token application VP, different tokens can use the same token application VP but different vp_data to distinguish the type of token. We can encode “ETH”, “BTC” or other property of the token into vp_data to make the token value-base unique.

#[derive(Clone, Debug, Default)]
pub struct TokenVP {
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
}

#[derive(Clone, Debug)]
pub struct TokenVPConfig {
    note_config: NoteConfig,
}

impl ValidityPredicateConfig for TokenVPConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_config.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_config = Self::configure_note(meta);
        Self {
            note_config,
        }
    }
}

impl TokenVP {
    pub fn new(
        spend_notes: [Note; NUM_NOTE],
        output_notes: [Note; NUM_NOTE],
    ) -> Self {
        Self {
            spend_notes,
            output_notes,
        }
    }
}

impl ValidityPredicateCircuit for TokenVP {
    type VPConfig = TokenVPConfig;

    fn custom_constraints(
        &self,
        config: Self::VPConfig,
        layouter: impl Layouter<pallas::Base>,
        _spend_note_variables: &[SpendNoteVar],
        _output_note_variables: &[OutputNoteVar],
    ) -> Result<(), plonk::Error> {
        Ok(())
    }
}

impl ValidityPredicateInfo for TokenVP {
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

vp_circuit_impl!(TokenVP);


// From the spend_notes and output_notes, we can test the balance
// Isn't this what basic_constrains is doing?

// How do we input all of the previous transactions?

#[cfg(test)]
mod tests {
    use super::*;

    use taiga_halo2::{
        circuit::gadgets::{
            assign_free_advice, assign_free_instance, AddChip, AddConfig, AddInstructions, MulChip,
            MulConfig, MulInstructions, SubChip, SubConfig, SubInstructions,
        },
        constant::NUM_NOTE,
        note::Note,
        nullifier::{Nullifier, NullifierKeyCom},
        vp_vk::ValidityPredicateVerifyingKey,
        
    };

    use ff::Field;
    use pasta_curves::pallas;

    use halo2_proofs::{
        plonk::{self, ProvingKey, VerifyingKey},
        poly::commitment::Params,
    };

    #[test]
    fn test_vp() {
        
        let mut rng = OsRng;
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));

        const K: u32 = 13;
        let params = Params::new(K);
        let vp = TokenVP::new(input_notes, output_notes);

        let vk = plonk::keygen_vk(&params, &vp).unwrap();


        let vp_desc = ValidityPredicateVerifyingKey::from_vk(vk);

        let app_data = pallas::Base::zero();
        let app_data_dynamic = pallas::Base::zero();

        let value: u64 = 0;
        let nk_com = NullifierKeyCom::default();
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        Note::new(
            vp_desc,
            app_data,
            app_data_dynamic,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            true,
            vec![],
        );
    }
}
