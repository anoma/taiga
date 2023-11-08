use crate::{
    circuit::{
        blake2s::{vp_commitment_gadget, Blake2sChip},
        gadgets::{
            assign_free_advice, assign_free_constant,
            poseidon_hash::poseidon_hash_gadget,
            target_note_variable::{get_is_input_note_flag, get_owned_note_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
        vp_examples::receiver_vp::{ReceiverValidityPredicateCircuit, COMPRESSED_RECEIVER_VK},
        vp_examples::signature_verification::{
            SignatureVerificationValidityPredicateCircuit, COMPRESSED_TOKEN_AUTH_VK,
        },
    },
    constant::{
        NUM_NOTE, PRF_EXPAND_DYNAMIC_VP_1_CM_R, SETUP_PARAMS_MAP, VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_1,
        VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_2, VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_1,
        VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_2,
    },
    note::{Note, NoteValidityPredicates, RandomSeed},
    nullifier::Nullifier,
    proof::Proof,
    utils::poseidon_hash_n,
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
};
use ff::Field;
use group::{Curve, Group};
use halo2_gadgets::ecc::{chip::EccChip, NonIdentityPoint};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::{group::ff::PrimeField, pallas};
use rand::{rngs::OsRng, Rng, RngCore};

lazy_static! {
    pub static ref TOKEN_VK: ValidityPredicateVerifyingKey =
        TokenValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_TOKEN_VK: pallas::Base = TOKEN_VK.get_compressed();
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenName(String);

impl TokenName {
    pub fn encode(&self) -> pallas::Base {
        assert!(self.0.len() < 32);
        let mut bytes: [u8; 32] = [0; 32];
        bytes[..self.0.len()].copy_from_slice(self.0.as_bytes());
        pallas::Base::from_repr(bytes).unwrap()
    }

    pub fn inner(&self) -> String {
        self.0.clone()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Token {
    name: TokenName,
    value: u64,
}

impl Token {
    pub fn new(name: String, value: u64) -> Self {
        Self {
            name: TokenName(name),
            value,
        }
    }

    pub fn name(&self) -> &TokenName {
        &self.name
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn encode_name(&self) -> pallas::Base {
        self.name.encode()
    }

    pub fn encode_value(&self) -> pallas::Base {
        pallas::Base::from(self.value)
    }

    pub fn create_random_input_token_note<R: RngCore>(
        &self,
        mut rng: R,
        nk: pallas::Base,
        auth: &TokenAuthorization,
    ) -> TokenNote {
        let app_data_static = self.encode_name();
        let app_data_dynamic = auth.to_app_data_dynamic();
        let rseed = RandomSeed::random(&mut rng);
        let rho = Nullifier::random(&mut rng);
        let note = Note::new_input_note(
            *COMPRESSED_TOKEN_VK,
            app_data_static,
            app_data_dynamic,
            self.value(),
            nk,
            rho,
            true,
            rseed,
        );

        TokenNote {
            token_name: self.name().clone(),
            note,
        }
    }

    pub fn create_random_output_token_note(
        &self,
        nk_com: pallas::Base,
        auth: &TokenAuthorization,
    ) -> TokenNote {
        let app_data_static = self.encode_name();
        let app_data_dynamic = auth.to_app_data_dynamic();
        let note = Note::new_output_note(
            *COMPRESSED_TOKEN_VK,
            app_data_static,
            app_data_dynamic,
            self.value(),
            nk_com,
            true,
        );

        TokenNote {
            token_name: self.name().clone(),
            note,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TokenNote {
    pub token_name: TokenName,
    pub note: Note,
}

impl std::ops::Deref for TokenNote {
    type Target = Note;

    fn deref(&self) -> &Self::Target {
        &self.note
    }
}

impl TokenNote {
    pub fn token_name(&self) -> &TokenName {
        &self.token_name
    }

    pub fn encode_name(&self) -> pallas::Base {
        self.token_name.encode()
    }

    pub fn encode_value(&self) -> pallas::Base {
        pallas::Base::from(self.note().value)
    }

    pub fn note(&self) -> &Note {
        &self.note
    }

    pub fn generate_input_token_vps<R: RngCore>(
        &self,
        mut rng: R,
        auth: TokenAuthorization,
        auth_sk: pallas::Scalar,
        input_notes: [Note; NUM_NOTE],
        output_notes: [Note; NUM_NOTE],
    ) -> NoteValidityPredicates {
        let TokenNote { token_name, note } = self;
        // token VP
        let nf = note.get_nf().unwrap().inner();
        let token_vp = TokenValidityPredicateCircuit {
            owned_note_pub_id: nf,
            input_notes,
            output_notes,
            token_name: token_name.clone(),
            auth,
            receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        };

        // token auth VP
        let token_auth_vp = SignatureVerificationValidityPredicateCircuit::from_sk_and_sign(
            &mut rng,
            nf,
            input_notes,
            output_notes,
            auth.vk,
            auth_sk,
            *COMPRESSED_RECEIVER_VK,
        );

        NoteValidityPredicates::new(Box::new(token_vp), vec![Box::new(token_auth_vp)])
    }

    pub fn generate_output_token_vps<R: RngCore>(
        &self,
        mut rng: R,
        auth: TokenAuthorization,
        input_notes: [Note; NUM_NOTE],
        output_notes: [Note; NUM_NOTE],
    ) -> NoteValidityPredicates {
        let TokenNote { token_name, note } = self;

        let owned_note_pub_id = note.commitment().inner();
        // token VP
        let token_vp = TokenValidityPredicateCircuit {
            owned_note_pub_id,
            input_notes,
            output_notes,
            token_name: token_name.clone(),
            auth,
            receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        };

        // receiver VP
        let receiver_vp = ReceiverValidityPredicateCircuit {
            owned_note_pub_id,
            input_notes,
            output_notes,
            vp_vk: *COMPRESSED_RECEIVER_VK,
            nonce: pallas::Base::from_u128(rng.gen()),
            sk: pallas::Base::random(&mut rng),
            rcv_pk: auth.pk,
            auth_vp_vk: *COMPRESSED_TOKEN_AUTH_VK,
        };

        NoteValidityPredicates::new(Box::new(token_vp), vec![Box::new(receiver_vp)])
    }
}

// TokenValidityPredicateCircuit
#[derive(Clone, Debug)]
pub struct TokenValidityPredicateCircuit {
    pub owned_note_pub_id: pallas::Base,
    pub input_notes: [Note; NUM_NOTE],
    pub output_notes: [Note; NUM_NOTE],
    // The token_name goes to app_data_static. It can be extended to a list and embedded to app_data_static.
    pub token_name: TokenName,
    // The auth goes to app_data_dynamic and defines how to consume and create the note.
    pub auth: TokenAuthorization,
    pub receiver_vp_vk: pallas::Base,
    // rseed is to generate the randomness for vp commitment
    pub rseed: RandomSeed,
}

#[derive(Clone, Debug, Copy)]
pub struct TokenAuthorization {
    pub pk: pallas::Point,
    pub vk: pallas::Base,
}

impl Default for TokenAuthorization {
    fn default() -> Self {
        Self {
            pk: pallas::Point::generator(),
            vk: pallas::Base::one(),
        }
    }
}

impl Default for TokenValidityPredicateCircuit {
    fn default() -> Self {
        Self {
            owned_note_pub_id: pallas::Base::zero(),
            input_notes: [(); NUM_NOTE].map(|_| Note::default()),
            output_notes: [(); NUM_NOTE].map(|_| Note::default()),
            token_name: TokenName("Token_name".to_string()),
            auth: TokenAuthorization::default(),
            receiver_vp_vk: pallas::Base::zero(),
            rseed: RandomSeed::default(),
        }
    }
}

impl ValidityPredicateCircuit for TokenValidityPredicateCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        let owned_note_pub_id = basic_variables.get_owned_note_pub_id();

        let token_property = assign_free_advice(
            layouter.namespace(|| "witness token_property"),
            config.advices[0],
            Value::known(self.token_name.encode()),
        )?;

        // We can add more constraints on token_property or extend the token_properties.

        // search target note and get the app_static_data
        let app_data_static = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_data_static"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // check app_data_static
        layouter.assign_region(
            || "check app_data_static",
            |mut region| region.constrain_equal(token_property.cell(), app_data_static.cell()),
        )?;

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);

        let pk = NonIdentityPoint::new(
            ecc_chip,
            layouter.namespace(|| "witness pk"),
            Value::known(self.auth.pk.to_affine()),
        )?;

        let auth_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness auth vp vk"),
            config.advices[0],
            Value::known(self.auth.vk),
        )?;

        // search target note and get the app_data_dynamic
        let app_data_dynamic = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_data_dynamic"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_dynamic_searchable_pairs(),
        )?;

        let receiver_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness receiver vp vk"),
            config.advices[0],
            Value::known(self.receiver_vp_vk),
        )?;

        // Decode the app_data_dynamic, and check the app_data_dynamic encoding
        let encoded_app_data_dynamic = poseidon_hash_gadget(
            config.poseidon_config,
            layouter.namespace(|| "app_data_dynamic encoding"),
            [
                pk.inner().x(),
                pk.inner().y(),
                auth_vp_vk.clone(),
                receiver_vp_vk.clone(),
            ],
        )?;

        layouter.assign_region(
            || "check app_data_dynamic encoding",
            |mut region| {
                region.constrain_equal(encoded_app_data_dynamic.cell(), app_data_dynamic.cell())
            },
        )?;

        // check the is_merkle_checked flag
        let is_merkle_checked = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get is_merkle_checked"),
            &owned_note_pub_id,
            &basic_variables.get_is_merkle_checked_searchable_pairs(),
        )?;
        let constant_one = assign_free_constant(
            layouter.namespace(|| "one"),
            config.advices[0],
            pallas::Base::one(),
        )?;
        layouter.assign_region(
            || "check is_merkle_checked",
            |mut region| region.constrain_equal(is_merkle_checked.cell(), constant_one.cell()),
        )?;

        // VP Commitment
        // Commt the sender(authorization method included) vp if it's an input note;
        // Commit the receiver(note encryption constraints included) vp if it's an output note.
        let first_dynamic_vp = {
            let is_input_note = get_is_input_note_flag(
                config.get_is_input_note_flag_config,
                layouter.namespace(|| "get is_input_note_flag"),
                &owned_note_pub_id,
                &basic_variables.get_input_note_nfs(),
                &basic_variables.get_output_note_cms(),
            )?;
            layouter.assign_region(
                || "conditional select: ",
                |mut region| {
                    config.conditional_select_config.assign_region(
                        &is_input_note,
                        &auth_vp_vk,
                        &receiver_vp_vk,
                        0,
                        &mut region,
                    )
                },
            )?
        };

        // Construct a blake2s chip
        let blake2s_chip = Blake2sChip::construct(config.blake2s_config);
        let vp_cm_r = assign_free_advice(
            layouter.namespace(|| "vp_cm_r"),
            config.advices[0],
            Value::known(self.rseed.get_vp_cm_r(PRF_EXPAND_DYNAMIC_VP_1_CM_R)),
        )?;
        let first_dynamic_vp_cm =
            vp_commitment_gadget(&mut layouter, &blake2s_chip, first_dynamic_vp, vp_cm_r)?;

        layouter.constrain_instance(
            first_dynamic_vp_cm[0].cell(),
            config.instances,
            VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_1,
        )?;
        layouter.constrain_instance(
            first_dynamic_vp_cm[1].cell(),
            config.instances,
            VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_2,
        )?;

        // Publicize the second dynamic vp commitment with default value
        let vp_cm_fields: [pallas::Base; 2] =
            ValidityPredicateCommitment::default().to_public_inputs();
        let vp_cm_1 = assign_free_advice(
            layouter.namespace(|| "vp_cm 1"),
            config.advices[0],
            Value::known(vp_cm_fields[0]),
        )?;
        let vp_cm_2 = assign_free_advice(
            layouter.namespace(|| "vp_cm 2"),
            config.advices[0],
            Value::known(vp_cm_fields[1]),
        )?;

        layouter.constrain_instance(
            vp_cm_1.cell(),
            config.instances,
            VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_1,
        )?;
        layouter.constrain_instance(
            vp_cm_2.cell(),
            config.instances,
            VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_2,
        )?;

        Ok(())
    }

    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ValidityPredicatePublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let dynamic_vp = if self.owned_note_pub_id == self.output_notes[0].commitment().inner()
            || self.owned_note_pub_id == self.output_notes[1].commitment().inner()
        {
            self.receiver_vp_vk
        } else {
            self.auth.vk
        };

        let vp_com_r = self.rseed.get_vp_cm_r(PRF_EXPAND_DYNAMIC_VP_1_CM_R);
        let vp_com: [pallas::Base; 2] =
            ValidityPredicateCommitment::commit(&dynamic_vp, &vp_com_r).to_public_inputs();

        public_inputs.extend(vp_com);
        let default_vp_cm: [pallas::Base; 2] =
            ValidityPredicateCommitment::default().to_public_inputs();
        public_inputs.extend(default_vp_cm);
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

vp_circuit_impl!(TokenValidityPredicateCircuit);
vp_verifying_info_impl!(TokenValidityPredicateCircuit);

impl TokenAuthorization {
    pub fn new(pk: pallas::Point, vk: pallas::Base) -> Self {
        Self { pk, vk }
    }

    pub fn random<R: RngCore>(mut rng: R) -> Self {
        Self {
            pk: pallas::Point::random(&mut rng),
            vk: *COMPRESSED_TOKEN_AUTH_VK,
        }
    }

    pub fn to_app_data_dynamic(&self) -> pallas::Base {
        let pk_coord = self.pk.to_affine().coordinates().unwrap();
        poseidon_hash_n::<4>([
            *pk_coord.x(),
            *pk_coord.y(),
            self.vk,
            *COMPRESSED_RECEIVER_VK,
        ])
    }

    pub fn from_sk_vk(sk: &pallas::Scalar, vk: &pallas::Base) -> Self {
        let generator = pallas::Point::generator().to_affine();
        let pk = generator * sk;
        Self { pk, vk: *vk }
    }
}

#[test]
fn test_halo2_token_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use crate::note::tests::random_note;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let mut input_notes = [(); NUM_NOTE].map(|_| random_note(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| random_note(&mut rng));
        let token_name = TokenName("Token_name".to_string());
        let auth = TokenAuthorization::random(&mut rng);
        input_notes[0].note_type.app_data_static = token_name.encode();
        input_notes[0].app_data_dynamic = auth.to_app_data_dynamic();
        TokenValidityPredicateCircuit {
            owned_note_pub_id: input_notes[0].get_nf().unwrap().inner(),
            input_notes,
            output_notes,
            token_name,
            auth,
            receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        }
    };

    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover = MockProver::<pallas::Base>::run(
        VP_CIRCUIT_PARAMS_SIZE,
        &circuit,
        vec![public_inputs.to_vec()],
    )
    .unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
