use crate::{
    circuit::{
        gadgets::{
            assign_free_advice, assign_free_constant,
            target_note_variable::{get_owned_note_variable, GetOwnedNoteVariableConfig},
        },
        note_circuit::NoteConfig,
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NOTE_COMMIT_DOMAIN, NUM_NOTE, SETUP_PARAMS_MAP},
    note::Note,
    proof::Proof,
    utils::poseidon_hash_n,
    vp_vk::ValidityPredicateVerifyingKey,
};
use group::{Curve, Group};
use halo2_gadgets::ecc::{chip::EccChip, NonIdentityPoint};
use halo2_gadgets::poseidon::{
    primitives as poseidon, primitives::ConstantLength, Hash as PoseidonHash,
    Pow5Chip as PoseidonChip,
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

// TokenValidityPredicateCircuit
#[derive(Clone, Debug)]
pub struct TokenValidityPredicateCircuit {
    owned_note_pub_id: pallas::Base,
    input_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    // The token_property goes to app_data_static and decides the note type. It can be extended to a list and embedded to app_data_static.
    token_property: pallas::Base,
    // The auth goes to app_data_dynamic and defines how to consume and create the note.
    auth: TokenAuthorization,
}

#[derive(Clone, Debug)]
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
            token_property: pallas::Base::zero(),
            auth: TokenAuthorization::default(),
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
    pub fn random<R: RngCore>(mut rng: R) -> Self {
        let mut input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let token_property = pallas::Base::random(&mut rng);
        let auth = TokenAuthorization::random(&mut rng);
        input_notes[0].note_type.app_data_static = token_property;
        input_notes[0].app_data_dynamic = auth.to_app_data_dynamic();
        Self {
            owned_note_pub_id: input_notes[0].get_nf().unwrap().inner(),
            input_notes,
            output_notes,
            token_property,
            auth,
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
            Value::known(self.token_property),
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

        let vk = assign_free_advice(
            layouter.namespace(|| "witness vk"),
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

        // Decode the app_data_dynamic, and check the app_data_dynamic encoding
        let encoded_app_data_dynamic = {
            let poseidon_config = config.get_note_config().poseidon_config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<4>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;

            let padding_zero = assign_free_constant(
                layouter.namespace(|| "zero"),
                config.advices[0],
                pallas::Base::zero(),
            )?;
            let poseidon_message = [pk.inner().x(), pk.inner().y(), vk, padding_zero];
            poseidon_hasher.hash(
                layouter.namespace(|| "check app_data_dynamic encoding"),
                poseidon_message,
            )?
        };
        layouter.assign_region(
            || "check app_data_dynamic encoding",
            |mut region| {
                region.constrain_equal(encoded_app_data_dynamic.cell(), app_data_dynamic.cell())
            },
        )?;

        // TODO: add authorization vp commitment

        Ok(())
    }
}

vp_circuit_impl!(TokenValidityPredicateCircuit);

impl TokenAuthorization {
    pub fn random<R: RngCore>(mut rng: R) -> Self {
        Self {
            pk: pallas::Point::random(&mut rng),
            vk: pallas::Base::random(&mut rng),
        }
    }

    pub fn to_app_data_dynamic(&self) -> pallas::Base {
        let pk_coord = self.pk.to_affine().coordinates().unwrap();
        poseidon_hash_n::<4>([*pk_coord.x(), *pk_coord.y(), self.vk, pallas::Base::zero()])
    }

    pub fn from_sk_vk(sk: pallas::Scalar, vk: pallas::Base) -> Self {
        let generator = NOTE_COMMIT_DOMAIN.R();
        let pk = generator * sk;
        Self { pk, vk }
    }
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
