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
        Self { note_config }
    }
}

impl TokenVP {
    pub fn new(spend_notes: [Note; NUM_NOTE], output_notes: [Note; NUM_NOTE]) -> Self {
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
        _config: Self::VPConfig,
        _layouter: impl Layouter<pallas::Base>,
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
    use halo2_gadgets::poseidon::primitives as poseidon;
    use taiga_halo2::{
        circuit::{
            gadgets::{
                assign_free_advice, assign_free_instance, AddChip, AddConfig, AddInstructions,
                MulChip, MulConfig, MulInstructions, SubChip, SubConfig, SubInstructions,
            },
            vp_examples::TrivialValidityPredicateCircuit,
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
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    fn calculate_hash<T: Hash + ?Sized>(t: &T) -> pallas::Base {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        let i = s.finish();
        poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<1>, 3, 2>::init()
            .hash([pallas::Base::from(i)])
    }

    #[test]
    fn test_vp() {
        let mut rng = OsRng;
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));

        let vp = TokenVP::new(input_notes, output_notes);

        const K: u32 = 13;
        let params = Params::new(K);
        let vk = plonk::keygen_vk(&params, &vp).unwrap();

        let vp_desc = ValidityPredicateVerifyingKey::from_vk(vk);

        let currency = "XAN";
        let app_data = calculate_hash(currency);
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

    fn create_token_notes() -> (Note, Note) {
        let mut rng = OsRng;

        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));

        let token_vp = TokenVP::new(input_notes, output_notes);

        const K: u32 = 13;
        let params = Params::new(K);
        let vk = plonk::keygen_vk(&params, &token_vp).unwrap();
        let app_vk = ValidityPredicateVerifyingKey::from_vk(vk);
        let currency = "XAN";
        let app_data = calculate_hash(currency);
        let value = 5000u64;
        let is_merkle_checked = true;
        let spend_note = {
            let app_data_dynamic = pallas::Base::zero();
            let rho = Nullifier::new(pallas::Base::random(&mut rng));
            let nk_com = NullifierKeyCom::rand(&mut rng);
            let rcm = pallas::Scalar::random(&mut rng);
            let psi = pallas::Base::random(&mut rng);
            Note::new(
                app_vk.clone(),
                app_data,
                app_data_dynamic,
                value,
                nk_com,
                rho,
                psi,
                rcm,
                is_merkle_checked,
                vec![0u8; 32],
            )
        };
        let output_note = {
            let app_data_dynamic = pallas::Base::zero();
            let nk_com = NullifierKeyCom::rand(&mut rng);
            let rcm = pallas::Scalar::random(&mut rng);
            let psi = pallas::Base::random(&mut rng);
            let rho = spend_note.get_nf().unwrap();
            Note::new(
                app_vk,
                app_data,
                app_data_dynamic,
                value,
                nk_com,
                rho,
                psi,
                rcm,
                is_merkle_checked,
                vec![0u8; 32],
            )
        };

        (spend_note, output_note)
    }

    fn create_dummy_notes() -> (Note, Note) {
        let mut rng = OsRng;
        let trivial_vp_circuit = TrivialValidityPredicateCircuit::default();
        let app_vk = trivial_vp_circuit.get_vp_description();

        let app_data = pallas::Base::zero();
        let value = 5000u64;
        let is_merkle_checked = true;

        let spend_note = {
            let app_data_dynamic = pallas::Base::zero();
            let rho = Nullifier::new(pallas::Base::random(&mut rng));
            let nk_com = NullifierKeyCom::rand(&mut rng);
            let rcm = pallas::Scalar::random(&mut rng);
            let psi = pallas::Base::random(&mut rng);
            Note::new(
                app_vk.clone(),
                app_data,
                app_data_dynamic,
                value,
                nk_com,
                rho,
                psi,
                rcm,
                is_merkle_checked,
                vec![0u8; 32],
            )
        };

        let output_note = {
            let app_data_dynamic = pallas::Base::zero();
            let nk_com = NullifierKeyCom::rand(&mut rng);
            let rcm = pallas::Scalar::random(&mut rng);
            let psi = pallas::Base::random(&mut rng);
            let rho = spend_note.get_nf().unwrap();
            Note::new(
                app_vk,
                app_data,
                app_data_dynamic,
                value,
                nk_com,
                rho,
                psi,
                rcm,
                is_merkle_checked,
                vec![0u8; 32],
            )
        };
        (spend_note, output_note)
    }
    #[test]
    fn test_transaction_creation() {
        use taiga_halo2::{
            circuit::vp_examples::TrivialValidityPredicateCircuit,
            constant::TAIGA_COMMITMENT_TREE_DEPTH,
            merkle_tree::MerklePath,
            note::{Note, OutputNoteInfo, SpendNoteInfo},
            nullifier::{Nullifier, NullifierKeyCom},
            transaction::{PartialTransaction, Transaction},
        };

        let mut rng = OsRng;

        let (spend_note_1, output_note_1) = create_token_notes();
        let (spend_note_2, output_note_2) = create_dummy_notes();

        let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let token_vp_circuit = TokenVP {
            spend_notes: [spend_note_1.clone(), spend_note_2.clone()],
            output_notes: [output_note_1.clone(), output_note_2.clone()],
        };

        let trivial_vp_circuit = TrivialValidityPredicateCircuit {
            spend_notes: [spend_note_1.clone(), spend_note_2.clone()],
            output_notes: [output_note_1.clone(), output_note_2.clone()],
        };
        let trivial_app_vp_proving_info = Box::new(trivial_vp_circuit.clone());
        let token_app_vp_proving_info = Box::new(token_vp_circuit.clone());
        let trivial_app_logic: Box<dyn ValidityPredicateInfo> = Box::new(trivial_vp_circuit);
        let token_app_logic: Box<dyn ValidityPredicateInfo> = Box::new(token_vp_circuit);
        let trivial_app_logic_vp_proving_info = vec![trivial_app_logic];
        let token_app_logic_vp_proving_info = vec![token_app_logic];
        let spend_note_info_1 = SpendNoteInfo::new(
            spend_note_1,
            merkle_path.clone(),
            token_app_vp_proving_info.clone(),
            token_app_logic_vp_proving_info.clone(),
        );
        // The following notes use empty logic vps and use app_data_dynamic with pallas::Base::zero() by default.
        let app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>> = vec![];
        let spend_note_info_2 = SpendNoteInfo::new(
            spend_note_2,
            merkle_path,
            trivial_app_vp_proving_info.clone(),
            trivial_app_logic_vp_proving_info.clone(),
        );
        let output_note_info_1 = OutputNoteInfo::new(
            output_note_1,
            token_app_vp_proving_info.clone(),
            token_app_logic_vp_proving_info.clone(),
        );
        let output_note_info_2 = OutputNoteInfo::new(
            output_note_2,
            trivial_app_vp_proving_info,
            trivial_app_logic_vp_proving_info,
        );

        // Create partial tx
        let (ptx, rcv) = PartialTransaction::build(
            [spend_note_info_1, spend_note_info_2],
            [output_note_info_1, output_note_info_2],
            &mut rng,
        );

        // Create tx
        let mut tx = Transaction::build(vec![ptx], vec![rcv]);
        tx.binding_sign(rng);
        tx.execute().unwrap();
    }
}
