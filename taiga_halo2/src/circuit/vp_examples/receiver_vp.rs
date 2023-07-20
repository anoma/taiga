use crate::{
    circuit::{
        gadgets::{
            add::AddChip, assign_free_advice, poseidon_hash::poseidon_hash_gadget,
            target_note_variable::get_owned_note_variable,
        },
        note_encryption_circuit::note_encryption_gadget,
        vp_circuit::{
            BasicValidityPredicateVariables, GeneralVerificationValidityPredicateConfig,
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
        vp_examples::signature_verification::COMPRESSED_TOKEN_AUTH_VK,
    },
    constant::{GENERATOR, NUM_NOTE, SETUP_PARAMS_MAP, VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX},
    note::Note,
    note_encryption::{NoteCipher, SecretKey},
    nullifier::{Nullifier, NullifierKeyContainer},
    proof::Proof,
    utils::mod_r_p,
    vp_vk::ValidityPredicateVerifyingKey,
};
use ff::PrimeField;
use group::Group;
use group::{cofactor::CofactorCurveAffine, Curve};
use halo2_gadgets::ecc::{chip::EccChip, NonIdentityPoint};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::pallas;
use rand::rngs::OsRng;
const CIPHER_LEN: usize = 9;

lazy_static! {
    pub static ref RECEIVER_VK: ValidityPredicateVerifyingKey =
        ReceiverValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_RECEIVER_VK: pallas::Base = RECEIVER_VK.get_compressed();
}

// ReceiverValidityPredicateCircuit is used in the token vp as dynamic vp and contains the note encryption constraints.
#[derive(Clone, Debug)]
pub struct ReceiverValidityPredicateCircuit {
    pub owned_note_pub_id: pallas::Base,
    pub input_notes: [Note; NUM_NOTE],
    pub output_notes: [Note; NUM_NOTE],
    pub vp_vk: pallas::Base,
    pub nonce: pallas::Base,
    pub sk: pallas::Base,
    pub rcv_pk: pallas::Point,
    pub auth_vp_vk: pallas::Base,
}

impl Default for ReceiverValidityPredicateCircuit {
    fn default() -> Self {
        Self {
            owned_note_pub_id: pallas::Base::zero(),
            input_notes: [(); NUM_NOTE].map(|_| Note::default()),
            output_notes: [(); NUM_NOTE].map(|_| Note::default()),
            vp_vk: pallas::Base::zero(),
            nonce: pallas::Base::zero(),
            sk: pallas::Base::zero(),
            rcv_pk: pallas::Point::generator(),
            auth_vp_vk: pallas::Base::zero(),
        }
    }
}

impl ValidityPredicateInfo for ReceiverValidityPredicateCircuit {
    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        let mut instances = self.get_note_instances();

        assert_eq!(NUM_NOTE, 2);
        let target_note =
            if self.get_owned_note_pub_id() == self.get_output_notes()[0].commitment().get_x() {
                self.get_output_notes()[0]
            } else {
                self.get_output_notes()[1]
            };
        let message = vec![
            target_note.note_type.app_vk,
            target_note.note_type.app_data_static,
            target_note.app_data_dynamic,
            pallas::Base::from(target_note.value),
            target_note.rho.inner(),
            target_note.get_nk_commitment(),
            target_note.psi,
            target_note.rcm,
        ];
        assert_eq!(message.len() + 1, CIPHER_LEN);
        let key = SecretKey::from_dh_exchange(&self.rcv_pk, &mod_r_p(self.sk));
        let cipher = NoteCipher::encrypt(&message, &key, &self.nonce);
        cipher.cipher.iter().for_each(|&c| instances.push(c));

        instances.push(self.nonce);
        let generator = GENERATOR.to_curve();
        let pk = generator * mod_r_p(self.sk);
        let pk_coord = pk.to_affine().coordinates().unwrap();
        instances.push(*pk_coord.x());
        instances.push(*pk_coord.y());
        instances
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

impl ValidityPredicateCircuit for ReceiverValidityPredicateCircuit {
    type VPConfig = GeneralVerificationValidityPredicateConfig;
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        let nonce = assign_free_advice(
            layouter.namespace(|| "witness nonce"),
            config.advices[0],
            Value::known(self.nonce),
        )?;

        let sk = assign_free_advice(
            layouter.namespace(|| "witness sk"),
            config.advices[0],
            Value::known(self.sk),
        )?;

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.get_note_config().ecc_config);

        let rcv_pk = NonIdentityPoint::new(
            ecc_chip.clone(),
            layouter.namespace(|| "witness rcv_pk"),
            Value::known(self.rcv_pk.to_affine()),
        )?;

        let owned_note_pub_id = basic_variables.get_owned_note_pub_id();
        let app_data_dynamic = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_data_dynamic"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_dynamic_searchable_pairs(),
        )?;

        let auth_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness auth vp vk"),
            config.advices[0],
            Value::known(*COMPRESSED_TOKEN_AUTH_VK),
        )?;
        let receiver_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness receiver vp vk"),
            config.advices[0],
            Value::known(self.vp_vk),
        )?;

        // Decode the app_data_dynamic, and check the app_data_dynamic encoding
        let encoded_app_data_dynamic = poseidon_hash_gadget(
            config.get_note_config().poseidon_config,
            layouter.namespace(|| "app_data_dynamic encoding"),
            [
                rcv_pk.inner().x(),
                rcv_pk.inner().y(),
                auth_vp_vk,
                receiver_vp_vk,
            ],
        )?;

        layouter.assign_region(
            || "check app_data_dynamic encoding",
            |mut region| {
                region.constrain_equal(encoded_app_data_dynamic.cell(), app_data_dynamic.cell())
            },
        )?;

        // search target note and get the app_static_data
        let app_data_static = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_data_static"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // search target note and get the app_vk
        let app_vk = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_vk"),
            &owned_note_pub_id,
            &basic_variables.get_app_vk_searchable_pairs(),
        )?;

        // search target note and get the value
        let value = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note value"),
            &owned_note_pub_id,
            &basic_variables.get_value_searchable_pairs(),
        )?;

        let rho = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note rho"),
            &owned_note_pub_id,
            &basic_variables.get_rho_searchable_pairs(),
        )?;

        let nk_com = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note nk_com"),
            &owned_note_pub_id,
            &basic_variables.get_nk_com_searchable_pairs(),
        )?;

        let psi = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note psi"),
            &owned_note_pub_id,
            &basic_variables.get_psi_searchable_pairs(),
        )?;

        let rcm = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note psi"),
            &owned_note_pub_id,
            &basic_variables.get_rcm_searchable_pairs(),
        )?;

        let message = vec![
            app_vk,
            app_data_static,
            app_data_dynamic,
            value,
            rho,
            nk_com,
            psi,
            rcm,
        ];

        let add_chip = AddChip::<pallas::Base>::construct(config.add_config.clone(), ());

        // Encryption
        let ret = note_encryption_gadget(
            layouter.namespace(|| "note encryption"),
            config.advices[0],
            config.get_note_config().poseidon_config,
            add_chip,
            ecc_chip,
            nonce,
            sk,
            rcv_pk,
            &message,
        )?;

        // Publicize cihper and mac
        ret.cipher.iter().enumerate().for_each(|(i, c)| {
            layouter
                .constrain_instance(
                    c.cell(),
                    config.instances,
                    VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX + i,
                )
                .unwrap()
        });

        // Publicize nonce, the nonce is constant though
        layouter.constrain_instance(
            ret.nonce.cell(),
            config.instances,
            VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX + ret.cipher.len(),
        )?;

        // Publicize sender's pk
        layouter.constrain_instance(
            ret.sender_pk.inner().x().cell(),
            config.instances,
            VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX + ret.cipher.len() + 1,
        )?;
        layouter.constrain_instance(
            ret.sender_pk.inner().y().cell(),
            config.instances,
            VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX + ret.cipher.len() + 2,
        )?;

        Ok(())
    }
}

vp_circuit_impl!(ReceiverValidityPredicateCircuit);

// TODO: we don't have a generic API to decrypt the instances since the indexes vary among applications.
// If we want a unified API, we may need to fix the indexes and number of the ciphertext in the instances.
pub fn decrypt_note(instances: Vec<pallas::Base>, sk: pallas::Base) -> Option<Note> {
    let len = instances.len();
    let cipher = NoteCipher {
        cipher: instances[VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX
            ..VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX + CIPHER_LEN]
            .to_vec(),
    };
    let sender_pk = pallas::Affine::from_xy(instances[len - 2], instances[len - 1])
        .unwrap()
        .to_curve();
    let key = SecretKey::from_dh_exchange(&sender_pk, &mod_r_p(sk));
    let nonce = instances[len - 3];
    match cipher.decrypt(&key, &nonce) {
        Some(plaintext) => {
            assert_eq!(plaintext.len(), CIPHER_LEN - 1);
            let value = u64::from_le_bytes(
                plaintext[3].to_repr()[..8]
                    .try_into()
                    .expect("slice with incorrect length"),
            );
            let rho = Nullifier::new(plaintext[4]);
            let nk = NullifierKeyContainer::from_commitment(plaintext[5]);
            let note = Note::from_full(
                plaintext[0],
                plaintext[1],
                plaintext[2],
                value,
                nk,
                rho,
                true,
                plaintext[6],
                plaintext[7],
            );
            Some(note)
        }
        None => None,
    }
}

#[test]
fn test_halo2_receiver_vp_circuit() {
    use crate::{
        note::tests::{random_input_note, random_output_note},
        utils::poseidon_hash_n,
    };
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let (circuit, rcv_sk) = {
        let input_notes = [(); NUM_NOTE].map(|_| random_input_note(&mut rng));
        let mut output_notes = input_notes
            .iter()
            .map(|input| random_output_note(&mut rng, input.get_nf().unwrap()))
            .collect::<Vec<_>>();
        let nonce = pallas::Base::from_u128(23333u128);
        let sk = pallas::Base::random(&mut rng);
        let rcv_sk = pallas::Base::random(&mut rng);
        let generator = GENERATOR.to_curve();
        let rcv_pk = generator * mod_r_p(rcv_sk);
        let rcv_pk_coord = rcv_pk.to_affine().coordinates().unwrap();
        output_notes[0].app_data_dynamic = poseidon_hash_n([
            *rcv_pk_coord.x(),
            *rcv_pk_coord.y(),
            *COMPRESSED_TOKEN_AUTH_VK,
            *COMPRESSED_RECEIVER_VK,
        ]);
        let owned_note_pub_id = output_notes[0].commitment().get_x();
        (
            ReceiverValidityPredicateCircuit {
                owned_note_pub_id,
                input_notes,
                output_notes: output_notes.try_into().unwrap(),
                vp_vk: *COMPRESSED_RECEIVER_VK,
                nonce,
                sk,
                rcv_pk,
                auth_vp_vk: *COMPRESSED_TOKEN_AUTH_VK,
            },
            rcv_sk,
        )
    };
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let decrypted_note = decrypt_note(instances, rcv_sk).unwrap();
    assert_eq!(decrypted_note, circuit.output_notes[0]);
}
