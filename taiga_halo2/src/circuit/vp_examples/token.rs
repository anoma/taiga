use crate::{
    circuit::{
        gadgets::{
            assign_free_advice,
            target_note_variable::{get_owned_note_variable, GetOwnedNoteVariableConfig},
        },
        note_circuit::NoteConfig,
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::Note,
    proof::Proof,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_gadgets::poseidon::{
    primitives as poseidon, primitives::ConstantLength, Hash as PoseidonHash,
    Pow5Chip as PoseidonChip,
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

// TokenValidityPredicateCircuit
#[derive(Clone, Debug, Default)]
pub struct TokenValidityPredicateCircuit {
    owned_note_pub_id: pallas::Base,
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    // The token_property goes to app_data_static and decides the note type. It can be extended to a list and embedded to app_data_static.
    token_property: pallas::Base,
    // The auth goes to app_data_dynamic and defines how to spend and create the note.
    auth: TokenAuthorization,
}

#[derive(Clone, Debug, Default)]
pub struct TokenAuthorization {
    pub user_address: pallas::Base,
    pub auth_vk: ValidityPredicateVerifyingKey,
}

#[derive(Clone, Debug)]
pub struct TokenValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    get_owned_note_variable_config: GetOwnedNoteVariableConfig,
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
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        Self {
            owned_note_pub_id: pallas::Base::zero(),
            spend_notes,
            output_notes,
            token_property: pallas::Base::random(&mut rng),
            auth: TokenAuthorization::random(&mut rng),
        }
    }
}

impl ValidityPredicateInfo for TokenValidityPredicateCircuit {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
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

        let user_address = assign_free_advice(
            layouter.namespace(|| "witness user_address"),
            config.advices[0],
            Value::known(self.auth.user_address),
        )?;

        let auth_vk = assign_free_advice(
            layouter.namespace(|| "witness auth_vk"),
            config.advices[0],
            Value::known(self.auth.auth_vk.get_compressed()),
        )?;

        // TODO: add authorization vp commitment

        let encoded_auth = {
            let poseidon_config = config.get_note_config().poseidon_config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;

            let poseidon_message = [user_address, auth_vk];
            poseidon_hasher.hash(layouter.namespace(|| "encode the auth"), poseidon_message)?
        };

        // search target note and get the app_data_dynamic
        let app_data_dynamic = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_data_dynamic"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_dynamic_searchable_pairs(),
        )?;

        // Check app_data_dynamic
        layouter.assign_region(
            || "check app_data_dynamic",
            |mut region| region.constrain_equal(encoded_auth.cell(), app_data_dynamic.cell()),
        )?;

        Ok(())
    }
}

vp_circuit_impl!(TokenValidityPredicateCircuit);

impl TokenAuthorization {
    pub fn random<R: RngCore>(mut rng: R) -> Self {
        Self {
            user_address: pallas::Base::random(&mut rng),
            auth_vk: ValidityPredicateVerifyingKey::dummy(&mut rng),
        }
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
