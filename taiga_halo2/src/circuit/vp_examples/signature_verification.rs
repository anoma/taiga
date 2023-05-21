use crate::{
    circuit::{
        gadgets::{
            add::{AddChip, AddConfig, AddInstructions},
            assign_free_advice,
        },
        note_circuit::NoteConfig,
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP, VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX},
    note::Note,
    proof::Proof,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

// AuthorizationValidityPredicateCircuit uses the schnorr signature.
#[derive(Clone, Debug, Default)]
pub struct AuthorizationValidityPredicateCircuit {
    owned_note_pub_id: pallas::Base,
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    // The secret key of the schnorr signature.
    sk: pallas::Base,
}

#[derive(Clone, Debug)]
struct AuthorizationValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
}

impl ValidityPredicateConfig for AuthorizationValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);

        let advices = note_conifg.advices;
        let instances = note_conifg.instances;

        Self {
            note_conifg,
            advices,
            instances,
        }
    }
}

impl AuthorizationValidityPredicateCircuit {
    pub fn random<R: RngCore>(mut rng: R) -> Self {
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let sk = pallas::Base::random(&mut rng);
        let owned_note_pub_id = pallas::Base::zero();
        Self {
            owned_note_pub_id,
            spend_notes,
            output_notes,
            sk,
        }
    }
}

impl ValidityPredicateInfo for AuthorizationValidityPredicateCircuit {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        let mut instances = self.get_note_instances();

        instances
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

impl ValidityPredicateCircuit for AuthorizationValidityPredicateCircuit {
    type VPConfig = AuthorizationValidityPredicateConfig;
    // Add custom constraints
    // Note: the trivial vp doesn't constrain on spend_note_variables and output_note_variables
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        _basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {


        Ok(())
    }
}

vp_circuit_impl!(AuthorizationValidityPredicateCircuit);

#[test]
fn test_halo2_auth_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = AuthorizationValidityPredicateCircuit::random(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
