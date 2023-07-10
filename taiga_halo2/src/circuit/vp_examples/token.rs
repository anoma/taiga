use crate::{
    circuit::{
        gadgets::{
            assign_free_advice, assign_free_constant,
            poseidon_hash::poseidon_hash_gadget,
            target_note_variable::{get_owned_note_variable, GetOwnedNoteVariableConfig},
        },
        note_circuit::NoteConfig,
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
        vp_examples::receiver_vp::{ReceiverValidityPredicateCircuit, COMPRESSED_RECEIVER_VK},
        vp_examples::signature_verification::{
            SignatureVerificationValidityPredicateCircuit, COMPRESSED_TOKEN_AUTH_VK,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    merkle_tree::MerklePath,
    note::{InputNoteProvingInfo, Note, OutputNoteProvingInfo, RandomSeed},
    proof::Proof,
    utils::poseidon_hash_n,
    vp_vk::ValidityPredicateVerifyingKey, nullifier::{Nullifier, NullifierKeyCom},
};
use ff::Field;
use group::{Curve, Group};
use halo2_gadgets::ecc::{chip::EccChip, NonIdentityPoint};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance},
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

pub fn transfrom_token_name_to_token_property(token_name: &str) -> pallas::Base {
    assert!(token_name.len() < 32);
    let mut bytes: [u8; 32] = [0; 32];
    bytes[..token_name.len()].copy_from_slice(token_name.as_bytes());
    pallas::Base::from_repr(bytes).unwrap()
}

#[derive(Clone, Debug, Default)]
pub struct Token {
    pub name: String,
    pub value: u64,
}

// TokenValidityPredicateCircuit
#[derive(Clone, Debug)]
pub struct TokenValidityPredicateCircuit {
    pub owned_note_pub_id: pallas::Base,
    pub input_notes: [Note; NUM_NOTE],
    pub output_notes: [Note; NUM_NOTE],
    // The token_name goes to app_data_static. It can be extended to a list and embedded to app_data_static.
    pub token_name: String,
    // The auth goes to app_data_dynamic and defines how to consume and create the note.
    pub auth: TokenAuthorization,
    pub receiver_vp_vk: pallas::Base,
}

#[derive(Clone, Debug, Copy)]
pub struct TokenAuthorization {
    pub pk: pallas::Point,
    pub vk: pallas::Base,
}

#[derive(Clone, Debug)]
pub struct TokenValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    get_owned_note_variable_config: GetOwnedNoteVariableConfig,
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
            token_name: "Token_name".to_string(),
            auth: TokenAuthorization::default(),
            receiver_vp_vk: pallas::Base::zero(),
        }
    }
}

impl ValidityPredicateConfig for TokenValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);

        let advices = note_conifg.advices;
        let instances = note_conifg.instances;

        let get_owned_note_variable_config = GetOwnedNoteVariableConfig::configure(
            meta,
            advices[0],
            [advices[1], advices[2], advices[3], advices[4]],
        );

        Self {
            note_conifg,
            advices,
            instances,
            get_owned_note_variable_config,
        }
    }
}

impl TokenValidityPredicateCircuit {
    // TODO: Move the random function to the test mod
    pub fn random<R: RngCore>(mut rng: R) -> Self {
        let mut input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let token_name = "Token_name".to_string();
        let auth = TokenAuthorization::random(&mut rng);
        input_notes[0].note_type.app_data_static =
            transfrom_token_name_to_token_property(&token_name);
        input_notes[0].app_data_dynamic = auth.to_app_data_dynamic();
        Self {
            owned_note_pub_id: input_notes[0].get_nf().unwrap().inner(),
            input_notes,
            output_notes,
            token_name,
            auth,
            receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
        }
    }
}

impl ValidityPredicateInfo for TokenValidityPredicateCircuit {
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

impl ValidityPredicateCircuit for TokenValidityPredicateCircuit {
    type VPConfig = TokenValidityPredicateConfig;
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
            Value::known(transfrom_token_name_to_token_property(&self.token_name)),
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
        let ecc_chip = EccChip::construct(config.get_note_config().ecc_config);

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
            config.get_note_config().poseidon_config,
            layouter.namespace(|| "app_data_dynamic encoding"),
            [pk.inner().x(), pk.inner().y(), auth_vp_vk, receiver_vp_vk],
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

        // TODO: add the sender(authorization method included) vp commitment if it's an input note;
        // Add the receiver(note encryption constraints included) vp commitment if it's an output note.

        Ok(())
    }
}

vp_circuit_impl!(TokenValidityPredicateCircuit);

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

#[allow(clippy::too_many_arguments)]
pub fn generate_input_token_note_proving_info<R: RngCore>(
    mut rng: R,
    input_note: Note,
    token_name: String,
    auth: TokenAuthorization,
    auth_sk: pallas::Scalar,
    merkle_path: MerklePath,
    input_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
) -> InputNoteProvingInfo {
    // token VP
    let nf = input_note.get_nf().unwrap().inner();
    let token_vp = TokenValidityPredicateCircuit {
        owned_note_pub_id: nf,
        input_notes,
        output_notes,
        token_name,
        auth,
        receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
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

    // input note proving info
    InputNoteProvingInfo::new(
        input_note,
        merkle_path,
        Box::new(token_vp),
        vec![Box::new(token_auth_vp)],
    )
}

pub fn generate_output_token_note_proving_info<R: RngCore>(
    mut rng: R,
    output_note: Note,
    token_name: String,
    auth: TokenAuthorization,
    input_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
) -> OutputNoteProvingInfo {
    let owned_note_pub_id = output_note.commitment().get_x();
    // token VP
    let token_vp = TokenValidityPredicateCircuit {
        owned_note_pub_id,
        input_notes,
        output_notes,
        token_name,
        auth,
        receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
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

    OutputNoteProvingInfo::new(output_note, Box::new(token_vp), vec![Box::new(receiver_vp)])
}

pub fn create_token_note<R: RngCore>(
    name: &str,
    value: u64,
    rho: Nullifier,
    nk_com: NullifierKeyCom,
    auth: &TokenAuthorization,
    rseed: RandomSeed
) -> Note {
    let app_data_static = transfrom_token_name_to_token_property(name);
    let app_data_dynamic = auth.to_app_data_dynamic();
    Note::new(
        *COMPRESSED_TOKEN_VK,
        app_data_static,
        app_data_dynamic,
        value,
        nk_com,
        rho,
        true,
        rseed,
    )
}
#[test]
fn test_halo2_token_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = TokenValidityPredicateCircuit::random(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
