use crate::{
    circuit::{
        gadgets::{
            add::{AddChip, AddConfig},
            assign_free_advice,
            poseidon_hash::poseidon_hash_gadget,
            target_note_variable::{get_owned_note_variable, GetOwnedNoteVariableConfig},
        },
        note_circuit::NoteConfig,
        note_encryption_circuit::note_encryption_gadget,
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{GENERATOR, NUM_NOTE, SETUP_PARAMS_MAP, VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX},
    note::Note,
    note_encryption::{NoteCipher, SecretKey},
    proof::Proof,
    utils::{mod_r_p, poseidon_hash},
    vp_vk::ValidityPredicateVerifyingKey,
};
use ff::{Field, PrimeField};
use group::Group;
use group::{cofactor::CofactorCurveAffine, Curve};
use halo2_gadgets::ecc::{chip::EccChip, NonIdentityPoint};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

// NoteEncryptionValidityPredicateCircuit
#[derive(Clone, Debug)]
struct NoteEncryptionValidityPredicateCircuit {
    owned_note_pub_id: pallas::Base,
    input_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    nonce: pallas::Base,
    sk: pallas::Base,
    rcv_pk: pallas::Point,
}

impl Default for NoteEncryptionValidityPredicateCircuit {
    fn default() -> Self {
        Self {
            owned_note_pub_id: pallas::Base::zero(),
            input_notes: [(); NUM_NOTE].map(|_| Note::default()),
            output_notes: [(); NUM_NOTE].map(|_| Note::default()),
            nonce: pallas::Base::zero(),
            sk: pallas::Base::zero(),
            rcv_pk: pallas::Point::generator(),
        }
    }
}

#[derive(Clone, Debug)]
struct NoteEncryptionValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    add_config: AddConfig,
    get_owned_note_variable_config: GetOwnedNoteVariableConfig,
}

impl ValidityPredicateConfig for NoteEncryptionValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);

        let advices = note_conifg.advices;
        let instances = note_conifg.instances;

        // configure custom config here
        let add_config = note_conifg.add_config.clone();

        let get_owned_note_variable_config = GetOwnedNoteVariableConfig::configure(
            meta,
            advices[0],
            [advices[1], advices[2], advices[3], advices[4]],
        );

        Self {
            note_conifg,
            advices,
            instances,
            add_config,
            get_owned_note_variable_config,
        }
    }
}

impl NoteEncryptionValidityPredicateCircuit {
    pub fn new<R: RngCore>(mut rng: R) -> Self {
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let mut output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let nonce = pallas::Base::from_u128(23333u128);
        let sk = pallas::Base::random(&mut rng);
        let rcv_pk = pallas::Point::random(&mut rng);
        let rcv_pk_coord = rcv_pk.to_affine().coordinates().unwrap();
        output_notes[0].app_data_dynamic = poseidon_hash(*rcv_pk_coord.x(), *rcv_pk_coord.y());
        let owned_note_pub_id = output_notes[0].commitment().get_x();
        Self {
            owned_note_pub_id,
            input_notes,
            output_notes,
            nonce,
            sk,
            rcv_pk,
        }
    }
}

impl ValidityPredicateInfo for NoteEncryptionValidityPredicateCircuit {
    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        let mut instances = self.get_note_instances();

        // Should search the target note, hardcode the first output note as the target note for simplicity.
        let target_note = self.get_output_notes()[0];
        let message = vec![
            target_note.note_type.app_data_static,
            target_note.note_type.app_vk,
            pallas::Base::from(target_note.value),
        ];
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

impl ValidityPredicateCircuit for NoteEncryptionValidityPredicateCircuit {
    type VPConfig = NoteEncryptionValidityPredicateConfig;
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

        let message = vec![app_data_static, app_vk, value];

        // search target note and get the app_data_dynamic
        let app_data_dynamic = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_data_dynamic"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_dynamic_searchable_pairs(),
        )?;

        // Decode the app_data_static, the rcv_pk is embedded in the app_data_static
        let encoded_rcv_pk = poseidon_hash_gadget::<2>(
            config.get_note_config().poseidon_config,
            layouter.namespace(|| "app_data_static encoding"),
            [rcv_pk.inner().x(), rcv_pk.inner().y()],
        )?;

        layouter.assign_region(
            || "check app_data_dynamic encoding",
            |mut region| region.constrain_equal(encoded_rcv_pk.cell(), app_data_dynamic.cell()),
        )?;

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

vp_circuit_impl!(NoteEncryptionValidityPredicateCircuit);

#[test]
fn test_halo2_note_encryption_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = NoteEncryptionValidityPredicateCircuit::new(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(13, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
