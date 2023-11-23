use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            add::AddChip, assign_free_advice, poseidon_hash::poseidon_hash_gadget,
            target_resource_variable::get_owned_resource_variable,
        },
        resource_encryption_circuit::resource_encryption_gadget,
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
        vp_examples::signature_verification::COMPRESSED_TOKEN_AUTH_VK,
    },
    constant::{GENERATOR, NUM_RESOURCE, SETUP_PARAMS_MAP},
    error::TransactionError,
    proof::Proof,
    resource::{RandomSeed, Resource},
    resource_encryption::{ResourceCiphertext, ResourcePlaintext, SecretKey},
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

// ReceiverValidityPredicateCircuit is used in the token vp as dynamic vp and contains the resource encryption constraints.
#[derive(Clone, Debug)]
pub struct ReceiverValidityPredicateCircuit {
    pub owned_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
    pub vp_vk: pallas::Base,
    pub encrypt_nonce: pallas::Base,
    pub sk: pallas::Base,
    pub rcv_pk: pallas::Point,
    pub auth_vp_vk: pallas::Base,
}

impl Default for ReceiverValidityPredicateCircuit {
    fn default() -> Self {
        Self {
            owned_resource_id: pallas::Base::zero(),
            input_resources: [(); NUM_RESOURCE].map(|_| Resource::default()),
            output_resources: [(); NUM_RESOURCE].map(|_| Resource::default()),
            vp_vk: pallas::Base::zero(),
            encrypt_nonce: pallas::Base::zero(),
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
        let encrypt_nonce = assign_free_advice(
            layouter.namespace(|| "witness encrypt_nonce"),
            config.advices[0],
            Value::known(self.encrypt_nonce),
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

        let owned_resource_id = basic_variables.get_owned_resource_id();
        let value = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource value"),
            &owned_resource_id,
            &basic_variables.get_value_searchable_pairs(),
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

        // Decode the value, and check the value encoding
        let encoded_value = poseidon_hash_gadget(
            config.poseidon_config.clone(),
            layouter.namespace(|| "value encoding"),
            [
                rcv_pk.inner().x(),
                rcv_pk.inner().y(),
                auth_vp_vk,
                receiver_vp_vk,
            ],
        )?;

        layouter.assign_region(
            || "check value encoding",
            |mut region| region.constrain_equal(encoded_value.cell(), value.cell()),
        )?;

        // search target resource and get the label
        let label = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource label"),
            &owned_resource_id,
            &basic_variables.get_label_searchable_pairs(),
        )?;

        // search target resource and get the logic
        let logic = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource logic"),
            &owned_resource_id,
            &basic_variables.get_logic_searchable_pairs(),
        )?;

        // search target resource and get the quantity
        let quantity = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource quantity"),
            &owned_resource_id,
            &basic_variables.get_quantity_searchable_pairs(),
        )?;

        let nonce = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource nonce"),
            &owned_resource_id,
            &basic_variables.get_nonce_searchable_pairs(),
        )?;

        let npk = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource npk"),
            &owned_resource_id,
            &basic_variables.get_npk_searchable_pairs(),
        )?;

        let psi = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource psi"),
            &owned_resource_id,
            &basic_variables.get_psi_searchable_pairs(),
        )?;

        let rcm = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource psi"),
            &owned_resource_id,
            &basic_variables.get_rcm_searchable_pairs(),
        )?;

        let mut message = vec![logic, label, value, quantity, nonce, npk, psi, rcm];

        let add_chip = AddChip::<pallas::Base>::construct(config.add_config.clone(), ());

        // Encryption
        resource_encryption_gadget(
            layouter.namespace(|| "resource encryption"),
            config.advices[0],
            config.instances,
            config.poseidon_config,
            add_chip,
            ecc_chip,
            encrypt_nonce,
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

    fn get_input_resources(&self) -> &[Resource; NUM_RESOURCE] {
        &self.input_resources
    }

    fn get_output_resources(&self) -> &[Resource; NUM_RESOURCE] {
        &self.output_resources
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
        assert_eq!(NUM_RESOURCE, 2);
        let target_resource = if self.get_owned_resource_id()
            == self.get_output_resources()[0].commitment().inner()
        {
            self.get_output_resources()[0]
        } else {
            self.get_output_resources()[1]
        };
        let message = vec![
            target_resource.kind.logic,
            target_resource.kind.label,
            target_resource.value,
            pallas::Base::from(target_resource.quantity),
            target_resource.nonce.inner(),
            target_resource.get_npk(),
            target_resource.psi,
            target_resource.rcm,
        ];
        let plaintext = ResourcePlaintext::padding(&message);
        let key = SecretKey::from_dh_exchange(&self.rcv_pk, &mod_r_p(self.sk));
        let cipher = ResourceCiphertext::encrypt(&plaintext, &key, &self.encrypt_nonce);
        cipher.inner().iter().for_each(|&c| public_inputs.push(c));

        let generator = GENERATOR.to_curve();
        let pk = generator * mod_r_p(self.sk);
        let pk_coord = pk.to_affine().coordinates().unwrap();
        public_inputs.push(*pk_coord.x());
        public_inputs.push(*pk_coord.y());
        public_inputs.into()
    }

    fn get_owned_resource_id(&self) -> pallas::Base {
        self.owned_resource_id
    }
}

vp_circuit_impl!(ReceiverValidityPredicateCircuit);
vp_verifying_info_impl!(ReceiverValidityPredicateCircuit);

#[test]
fn test_halo2_receiver_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use crate::{resource::tests::random_resource, utils::poseidon_hash_n};
    use ff::{Field, PrimeField};
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let (circuit, rcv_sk) = {
        let input_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let mut output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let encrypt_nonce = pallas::Base::from_u128(23333u128);
        let sk = pallas::Base::random(&mut rng);
        let rcv_sk = pallas::Base::random(&mut rng);
        let generator = GENERATOR.to_curve();
        let rcv_pk = generator * mod_r_p(rcv_sk);
        let rcv_pk_coord = rcv_pk.to_affine().coordinates().unwrap();
        output_resources[0].value = poseidon_hash_n([
            *rcv_pk_coord.x(),
            *rcv_pk_coord.y(),
            *COMPRESSED_TOKEN_AUTH_VK,
            *COMPRESSED_RECEIVER_VK,
        ]);
        let owned_resource_id = output_resources[0].commitment().inner();
        (
            ReceiverValidityPredicateCircuit {
                owned_resource_id,
                input_resources,
                output_resources,
                vp_vk: *COMPRESSED_RECEIVER_VK,
                encrypt_nonce,
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
    assert_eq!(de_cipher[0], circuit.output_resources[0].get_logic());
    assert_eq!(de_cipher[1], circuit.output_resources[0].get_label());
    assert_eq!(de_cipher[2], circuit.output_resources[0].value);
    assert_eq!(
        de_cipher[3],
        pallas::Base::from(circuit.output_resources[0].quantity)
    );
    assert_eq!(de_cipher[4], circuit.output_resources[0].nonce.inner());
    assert_eq!(de_cipher[5], circuit.output_resources[0].get_npk());
    assert_eq!(de_cipher[6], circuit.output_resources[0].get_psi());
    assert_eq!(de_cipher[7], circuit.output_resources[0].get_rcm());
}
