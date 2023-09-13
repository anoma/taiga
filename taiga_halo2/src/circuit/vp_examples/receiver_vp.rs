use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            add::AddChip, assign_free_advice, poseidon_hash::poseidon_hash_gadget,
            target_note_variable::get_owned_note_variable,
        },
        note_encryption_circuit::note_encryption_gadget,
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
        vp_examples::signature_verification::COMPRESSED_TOKEN_AUTH_VK,
    },
    constant::{GENERATOR, NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, RandomSeed},
    note_encryption::{NoteCiphertext, NotePlaintext, SecretKey},
    proof::Proof,
    utils::mod_r_p,
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
};
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
use rand::RngCore;
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

impl ValidityPredicateCircuit for ReceiverValidityPredicateCircuit {
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
        let ecc_chip = EccChip::construct(config.ecc_config);

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
            config.poseidon_config.clone(),
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

        let mut message = vec![
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
        note_encryption_gadget(
            layouter.namespace(|| "note encryption"),
            config.advices[0],
            config.instances,
            config.poseidon_config,
            add_chip,
            ecc_chip,
            nonce,
            sk,
            rcv_pk,
            &mut message,
        )?;

        // Publicize the dynamic vp commitments with default value
        publicize_default_dynamic_vp_commitments(
            &mut layouter,
            config.advices[0],
            config.instances,
        )?;

        Ok(())
    }

    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_public_inputs(&self, rng: impl RngCore) -> ValidityPredicatePublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let default_vp_cm: [pallas::Base; 2] =
            ValidityPredicateCommitment::default().to_public_inputs();
        public_inputs.extend(default_vp_cm);
        public_inputs.extend(default_vp_cm);
        let custom_public_input_padding =
            ValidityPredicatePublicInputs::get_custom_public_input_padding(
                public_inputs.len(),
                &RandomSeed::random(rng),
            );
        public_inputs.extend(custom_public_input_padding.iter());
        assert_eq!(NUM_NOTE, 2);
        let target_note =
            if self.get_owned_note_pub_id() == self.get_output_notes()[0].commitment().inner() {
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
        let plaintext = NotePlaintext::padding(&message);
        let key = SecretKey::from_dh_exchange(&self.rcv_pk, &mod_r_p(self.sk));
        let cipher = NoteCiphertext::encrypt(&plaintext, &key, &self.nonce);
        cipher.inner().iter().for_each(|&c| public_inputs.push(c));

        let generator = GENERATOR.to_curve();
        let pk = generator * mod_r_p(self.sk);
        let pk_coord = pk.to_affine().coordinates().unwrap();
        public_inputs.push(*pk_coord.x());
        public_inputs.push(*pk_coord.y());
        public_inputs.into()
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

vp_circuit_impl!(ReceiverValidityPredicateCircuit);

#[test]
fn test_halo2_receiver_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use crate::{
        note::tests::{random_input_note, random_output_note},
        utils::poseidon_hash_n,
    };
    use ff::{Field, PrimeField};
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
        let owned_note_pub_id = output_notes[0].commitment().inner();
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
    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover = MockProver::<pallas::Base>::run(
        VP_CIRCUIT_PARAMS_SIZE,
        &circuit,
        vec![public_inputs.to_vec()],
    )
    .unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let de_cipher = public_inputs.decrypt(rcv_sk).unwrap();
    assert_eq!(de_cipher[0], circuit.output_notes[0].get_app_vk());
    assert_eq!(de_cipher[1], circuit.output_notes[0].get_app_data_static());
    assert_eq!(de_cipher[2], circuit.output_notes[0].app_data_dynamic);
    assert_eq!(
        de_cipher[3],
        pallas::Base::from(circuit.output_notes[0].value)
    );
    assert_eq!(de_cipher[4], circuit.output_notes[0].rho.inner());
    assert_eq!(de_cipher[5], circuit.output_notes[0].get_nk_commitment());
    assert_eq!(de_cipher[6], circuit.output_notes[0].get_psi());
    assert_eq!(de_cipher[7], circuit.output_notes[0].get_rcm());
}
