/// The intent can be partially fulfilled.
/// For example, Alice has 5 BTC and wants 10 ETH.
/// Alice utilizes this intent to do a partial swap in proportion. She can exchange 2 BTC for 4 ETH and get 3 BTC back.
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            assign_free_constant,
            mul::MulChip,
            sub::{SubChip, SubInstructions},
            target_note_variable::{get_is_input_note_flag, get_owned_note_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, RandomSeed},
    proof::Proof,
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

mod swap;
use swap::Swap;

mod data_static;
use data_static::PartialFulfillmentIntentDataStatic;

lazy_static! {
    pub static ref PARTIAL_FULFILLMENT_INTENT_VK: ValidityPredicateVerifyingKey =
        PartialFulfillmentIntentValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK: pallas::Base =
        PARTIAL_FULFILLMENT_INTENT_VK.get_compressed();
}

// PartialFulfillmentIntentValidityPredicateCircuit
#[derive(Clone, Debug, Default)]
pub struct PartialFulfillmentIntentValidityPredicateCircuit {
    pub owned_note_pub_id: pallas::Base,
    pub input_notes: [Note; NUM_NOTE],
    pub output_notes: [Note; NUM_NOTE],
    swap: Swap,
}

impl ValidityPredicateCircuit for PartialFulfillmentIntentValidityPredicateCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        let sub_chip = SubChip::construct(config.sub_config.clone(), ());
        let mul_chip = MulChip::construct(config.mul_config.clone());

        let owned_note_pub_id = basic_variables.get_owned_note_pub_id();

        let app_data_static = self.swap.assign_app_data_static(
            config.advices[0],
            layouter.namespace(|| "assign app_data_static"),
        )?;
        let encoded_app_data_static = app_data_static.encode(
            config.poseidon_config.clone(),
            layouter.namespace(|| "encode app_data_static"),
        )?;

        // search target note and get the intent app_static_data
        let owned_note_app_data_static = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_data_static"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // Enforce consistency of app_data_static:
        //  - as witnessed in the swap, and
        //  - as encoded in the intent note
        layouter.assign_region(
            || "check app_data_static",
            |mut region| {
                region.constrain_equal(
                    encoded_app_data_static.cell(),
                    owned_note_app_data_static.cell(),
                )
            },
        )?;

        let is_input_note = get_is_input_note_flag(
            config.get_is_input_note_flag_config,
            layouter.namespace(|| "get is_input_note_flag"),
            &owned_note_pub_id,
            &basic_variables.get_input_note_nfs(),
            &basic_variables.get_output_note_cms(),
        )?;
        // Conditional checks if is_input_note == 1
        app_data_static.is_input_note_checks(
            &is_input_note,
            &basic_variables,
            &config.conditional_equal_config,
            layouter.namespace(|| "is_input_note checks"),
        )?;

        let is_output_note = {
            let constant_one = assign_free_constant(
                layouter.namespace(|| "one"),
                config.advices[0],
                pallas::Base::one(),
            )?;
            // TODO: use a nor gate to replace the sub gate.
            SubInstructions::sub(
                &sub_chip,
                layouter.namespace(|| "expected_sold_value - returned_value"),
                &is_input_note,
                &constant_one,
            )?
        };
        // Conditional checks if is_output_note == 1
        app_data_static.is_output_note_checks(
            &is_output_note,
            &basic_variables,
            &config.conditional_equal_config,
            layouter.namespace(|| "is_output_note checks"),
        )?;

        // Conditional checks if is_partial_fulfillment == 1
        app_data_static.is_partial_fulfillment_checks(
            &is_input_note,
            &basic_variables,
            &config.conditional_equal_config,
            &sub_chip,
            &mul_chip,
            layouter.namespace(|| "is_partial_fulfillment checks"),
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

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ValidityPredicatePublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let default_vp_cm: [pallas::Base; 2] =
            ValidityPredicateCommitment::default().to_public_inputs();
        public_inputs.extend(default_vp_cm);
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

vp_circuit_impl!(PartialFulfillmentIntentValidityPredicateCircuit);
vp_verifying_info_impl!(PartialFulfillmentIntentValidityPredicateCircuit);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::vp_examples::{
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    };
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;
    use rand::RngCore;

    // Generate a swap, along with its corresponding intent note and authorisation
    fn swap(mut rng: impl RngCore, sell: Token, buy: Token) -> Swap {
        let sk = pallas::Scalar::random(&mut rng);
        let auth = TokenAuthorization::from_sk_vk(&sk, &COMPRESSED_TOKEN_AUTH_VK);

        Swap::random(&mut rng, sell, buy, auth)
    }

    #[test]
    fn create_intent() {
        let mut rng = OsRng;
        let sell = Token::new("token1".to_string(), 2u64);
        let buy = Token::new("token2".to_string(), 4u64);

        let swap = swap(&mut rng, sell, buy);
        let intent_note = swap.create_intent_note(&mut rng);

        let input_padding_note = Note::random_padding_input_note(&mut rng);
        let output_padding_note =
            Note::random_padding_output_note(&mut rng, input_padding_note.get_nf().unwrap());

        let input_notes = [*swap.sell.note(), input_padding_note];
        let output_notes = [intent_note, output_padding_note];

        let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
            owned_note_pub_id: intent_note.commitment().inner(),
            input_notes,
            output_notes,
            swap,
        };
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            VP_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn full_fulfillment() {
        let mut rng = OsRng;
        let sell = Token::new("token1".to_string(), 2u64);
        let buy = Token::new("token2".to_string(), 4u64);

        let swap = swap(&mut rng, sell, buy);
        let intent_note = swap.create_intent_note(&mut rng);

        let bob_sell = swap.buy.clone();
        let (input_notes, output_notes) = swap.fill(&mut rng, intent_note, bob_sell);

        let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
            owned_note_pub_id: intent_note.get_nf().unwrap().inner(),
            input_notes,
            output_notes,
            swap,
        };
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            VP_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn partial_fulfillment() {
        let mut rng = OsRng;
        let sell = Token::new("token1".to_string(), 2u64);
        let buy = Token::new("token2".to_string(), 4u64);

        let swap = swap(&mut rng, sell, buy);
        let intent_note = swap.create_intent_note(&mut rng);

        let bob_sell = Token::new(swap.buy.name().inner().to_string(), 2u64);
        let (input_notes, output_notes) = swap.fill(&mut rng, intent_note, bob_sell);

        let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
            owned_note_pub_id: intent_note.get_nf().unwrap().inner(),
            input_notes,
            output_notes,
            swap,
        };
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            VP_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();
    }
}
