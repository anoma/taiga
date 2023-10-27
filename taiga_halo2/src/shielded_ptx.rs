use crate::action::{ActionInfo, ActionPublicInputs};
use crate::circuit::vp_circuit::{VPVerifyingInfo, ValidityPredicate};
use crate::constant::{
    ACTION_CIRCUIT_PARAMS_SIZE, ACTION_PROVING_KEY, ACTION_VERIFYING_KEY, MAX_DYNAMIC_VP_NUM,
    NUM_NOTE, SETUP_PARAMS_MAP,
};
use crate::error::TransactionError;
use crate::executable::Executable;
use crate::merkle_tree::Anchor;
use crate::note::{NoteCommitment, NoteValidityPredicates};
use crate::nullifier::Nullifier;
use crate::proof::Proof;
use crate::value_commitment::ValueCommitment;
use halo2_proofs::plonk::Error;
use pasta_curves::pallas;
use rand::RngCore;

#[cfg(feature = "nif")]
use rustler::{Decoder, Encoder, Env, NifResult, NifStruct, Term};

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use crate::circuit::vp_bytecode::ApplicationByteCode;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "borsh")]
use ff::PrimeField;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShieldedPartialTransaction {
    actions: [ActionVerifyingInfo; NUM_NOTE],
    inputs: [NoteVPVerifyingInfoSet; NUM_NOTE],
    outputs: [NoteVPVerifyingInfoSet; NUM_NOTE],
    binding_sig_r: pallas::Scalar,
    hints: Vec<u8>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Action.VerifyingInfo")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActionVerifyingInfo {
    action_proof: Proof,
    action_instance: ActionPublicInputs,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Note.VerifyingInfo")]
pub struct NoteVPVerifyingInfoSet {
    app_vp_verifying_info: VPVerifyingInfo,
    app_dynamic_vp_verifying_info: Vec<VPVerifyingInfo>,
    // TODO: add verifier proof and according public inputs.
    // When the verifier proof is added, we may need to reconsider the structure of `VPVerifyingInfo`
}

// Is easier to derive traits for
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Shielded.PTX")]
struct ShieldedPartialTransactionProxy {
    actions: Vec<ActionVerifyingInfo>,
    inputs: Vec<NoteVPVerifyingInfoSet>,
    outputs: Vec<NoteVPVerifyingInfoSet>,
    binding_sig_r: pallas::Scalar,
    hints: Vec<u8>,
}

impl ShieldedPartialTransaction {
    #[cfg(feature = "borsh")]
    pub fn from_bytecode<R: RngCore>(
        actions: Vec<ActionInfo>,
        input_note_app: Vec<ApplicationByteCode>,
        output_note_app: Vec<ApplicationByteCode>,
        hints: Vec<u8>,
        mut rng: R,
    ) -> Self {
        let inputs: Vec<NoteVPVerifyingInfoSet> = input_note_app
            .into_iter()
            .map(|bytecode| bytecode.generate_proofs())
            .collect();
        let outputs: Vec<NoteVPVerifyingInfoSet> = output_note_app
            .into_iter()
            .map(|bytecode| bytecode.generate_proofs())
            .collect();
        let mut rcv_sum = pallas::Scalar::zero();
        let actions: Vec<ActionVerifyingInfo> = actions
            .iter()
            .map(|action_info| {
                rcv_sum += action_info.get_rcv();
                ActionVerifyingInfo::create(action_info, &mut rng).unwrap()
            })
            .collect();

        Self {
            actions: actions.try_into().unwrap(),
            inputs: inputs.try_into().unwrap(),
            outputs: outputs.try_into().unwrap(),
            binding_sig_r: rcv_sum,
            hints,
        }
    }

    pub fn build<R: RngCore>(
        action_pairs: Vec<ActionInfo>,
        input_note_vps: Vec<NoteValidityPredicates>,
        output_note_vps: Vec<NoteValidityPredicates>,
        hints: Vec<u8>,
        mut rng: R,
    ) -> Result<Self, Error> {
        // Generate action proofs
        let mut rcv_sum = pallas::Scalar::zero();
        let actions: Vec<ActionVerifyingInfo> = action_pairs
            .iter()
            .map(|action_info| {
                rcv_sum += action_info.get_rcv();
                ActionVerifyingInfo::create(action_info, &mut rng).unwrap()
            })
            .collect();

        // Generate input vp proofs
        let inputs: Vec<NoteVPVerifyingInfoSet> = input_note_vps
            .iter()
            .map(|input_note_vp| input_note_vp.build())
            .collect();

        // Generate output vp proofs
        let outputs: Vec<NoteVPVerifyingInfoSet> = output_note_vps
            .iter()
            .map(|output_note_vp| output_note_vp.build())
            .collect();

        Ok(Self {
            actions: actions.try_into().unwrap(),
            inputs: inputs.try_into().unwrap(),
            outputs: outputs.try_into().unwrap(),
            binding_sig_r: rcv_sum,
            hints,
        })
    }

    // verify zk proof
    pub fn verify_proof(&self) -> Result<(), TransactionError> {
        // Verify action proofs
        for verifying_info in self.actions.iter() {
            verifying_info.verify()?;
        }

        // Verify vp proofs from input notes
        for verifying_info in self.inputs.iter() {
            verifying_info.verify()?;
        }
        // Verify vp proofs from output notes
        for verifying_info in self.outputs.iter() {
            verifying_info.verify()?;
        }

        Ok(())
    }

    // check the nullifiers are from action proofs
    fn check_nullifiers(&self) -> Result<(), TransactionError> {
        assert_eq!(NUM_NOTE, 2);
        let action_nfs = self.get_nullifiers();
        for vp_info in self.inputs.iter() {
            for nfs in vp_info.get_nullifiers().iter() {
                // Check the vp actually uses the input notes from action circuits.
                if !((action_nfs[0].inner() == nfs[0] && action_nfs[1].inner() == nfs[1])
                    || (action_nfs[0].inner() == nfs[1] && action_nfs[1].inner() == nfs[0]))
                {
                    return Err(TransactionError::InconsistentNullifier);
                }
            }
        }

        for (vp_info, action_nf) in self.inputs.iter().zip(action_nfs.iter()) {
            // Check the app vp and the sub vps use the same owned_note_id in one note
            let owned_note_id = vp_info.app_vp_verifying_info.get_owned_note_pub_id();
            for logic_vp_verifying_info in vp_info.app_dynamic_vp_verifying_info.iter() {
                if owned_note_id != logic_vp_verifying_info.get_owned_note_pub_id() {
                    return Err(TransactionError::InconsistentOwnedNotePubID);
                }
            }

            // Check the owned_note_id that vp uses is consistent with the nf from the action circuit
            if owned_note_id != action_nf.inner() {
                return Err(TransactionError::InconsistentOwnedNotePubID);
            }
        }
        Ok(())
    }

    // check the output cms are from action proofs
    fn check_note_commitments(&self) -> Result<(), TransactionError> {
        assert_eq!(NUM_NOTE, 2);
        let action_cms = self.get_output_cms();
        for vp_info in self.outputs.iter() {
            for cms in vp_info.get_note_commitments().iter() {
                // Check the vp actually uses the output notes from action circuits.
                if !((action_cms[0] == cms[0] && action_cms[1] == cms[1])
                    || (action_cms[0] == cms[1] && action_cms[1] == cms[0]))
                {
                    return Err(TransactionError::InconsistentOutputNoteCommitment);
                }
            }
        }

        for (vp_info, action_cm) in self.outputs.iter().zip(action_cms.iter()) {
            // Check that the app vp and the sub vps use the same owned_note_id in one note
            let owned_note_id = vp_info.app_vp_verifying_info.get_owned_note_pub_id();
            for logic_vp_verifying_info in vp_info.app_dynamic_vp_verifying_info.iter() {
                if owned_note_id != logic_vp_verifying_info.get_owned_note_pub_id() {
                    return Err(TransactionError::InconsistentOwnedNotePubID);
                }
            }

            // Check the owned_note_id that vp uses is consistent with the cm from the action circuit
            if owned_note_id != action_cm.inner() {
                return Err(TransactionError::InconsistentOwnedNotePubID);
            }
        }
        Ok(())
    }

    // Conversion to the generic length proxy
    fn to_proxy(&self) -> ShieldedPartialTransactionProxy {
        ShieldedPartialTransactionProxy {
            actions: self.actions.to_vec(),
            inputs: self.inputs.to_vec(),
            outputs: self.outputs.to_vec(),
            binding_sig_r: self.binding_sig_r,
            hints: self.hints.clone(),
        }
    }

    pub fn get_binding_sig_r(&self) -> pallas::Scalar {
        self.binding_sig_r
    }

    pub fn get_hints(&self) -> Vec<u8> {
        self.hints.clone()
    }
}

impl ShieldedPartialTransactionProxy {
    fn to_concrete(&self) -> Option<ShieldedPartialTransaction> {
        let actions = self.actions.clone().try_into().ok()?;
        let inputs = self.inputs.clone().try_into().ok()?;
        let outputs = self.outputs.clone().try_into().ok()?;
        Some(ShieldedPartialTransaction {
            actions,
            inputs,
            outputs,
            binding_sig_r: self.binding_sig_r,
            hints: self.hints.clone(),
        })
    }
}

impl Executable for ShieldedPartialTransaction {
    fn execute(&self) -> Result<(), TransactionError> {
        self.verify_proof()?;
        self.check_nullifiers()?;
        self.check_note_commitments()?;
        Ok(())
    }

    fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.actions
            .iter()
            .map(|action| action.action_instance.nf)
            .collect()
    }

    fn get_output_cms(&self) -> Vec<NoteCommitment> {
        self.actions
            .iter()
            .map(|action| action.action_instance.cm)
            .collect()
    }

    fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        self.actions
            .iter()
            .map(|action| action.action_instance.cv_net)
            .collect()
    }

    fn get_anchors(&self) -> Vec<Anchor> {
        self.actions
            .iter()
            .map(|action| action.action_instance.anchor)
            .collect()
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for ShieldedPartialTransaction {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for action in self.actions.iter() {
            action.serialize(writer)?;
        }

        for input in self.inputs.iter() {
            input.serialize(writer)?;
        }

        for output in self.outputs.iter() {
            output.serialize(writer)?;
        }

        writer.write_all(&self.binding_sig_r.to_repr())?;

        self.hints.serialize(writer)?;

        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for ShieldedPartialTransaction {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let actions: Vec<_> = (0..NUM_NOTE)
            .map(|_| ActionVerifyingInfo::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let inputs: Vec<_> = (0..NUM_NOTE)
            .map(|_| NoteVPVerifyingInfoSet::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let outputs: Vec<_> = (0..NUM_NOTE)
            .map(|_| NoteVPVerifyingInfoSet::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let binding_sig_r_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let binding_sig_r = Option::from(pallas::Scalar::from_repr(binding_sig_r_bytes))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "binding_sig_r not in field",
                )
            })?;
        let hints = Vec::<u8>::deserialize_reader(reader)?;
        Ok(ShieldedPartialTransaction {
            actions: actions.try_into().unwrap(),
            inputs: inputs.try_into().unwrap(),
            outputs: outputs.try_into().unwrap(),
            binding_sig_r,
            hints,
        })
    }
}

#[cfg(feature = "nif")]
impl Encoder for ShieldedPartialTransaction {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_proxy().encode(env)
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for ShieldedPartialTransaction {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let val: ShieldedPartialTransactionProxy = Decoder::decode(term)?;
        val.to_concrete()
            .ok_or(rustler::Error::RaiseAtom("Could not decode proxy"))
    }
}

impl ActionVerifyingInfo {
    pub fn create<R: RngCore>(action_info: &ActionInfo, mut rng: R) -> Result<Self, Error> {
        let (action_instance, circuit) = action_info.build();
        let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();
        let action_proof = Proof::create(
            &ACTION_PROVING_KEY,
            params,
            circuit,
            &[&action_instance.to_instance()],
            &mut rng,
        )?;
        Ok(Self {
            action_proof,
            action_instance,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();
        self.action_proof.verify(
            &ACTION_VERIFYING_KEY,
            params,
            &[&self.action_instance.to_instance()],
        )
    }
}

impl NoteVPVerifyingInfoSet {
    pub fn new(
        app_vp_verifying_info: VPVerifyingInfo,
        app_dynamic_vp_verifying_info: Vec<VPVerifyingInfo>,
    ) -> Self {
        assert!(app_dynamic_vp_verifying_info.len() <= MAX_DYNAMIC_VP_NUM);

        Self {
            app_vp_verifying_info,
            app_dynamic_vp_verifying_info,
        }
    }

    // TODO: remove it.
    pub fn build(
        application_vp: Box<ValidityPredicate>,
        dynamic_vps: Vec<Box<ValidityPredicate>>,
    ) -> Self {
        assert!(dynamic_vps.len() <= MAX_DYNAMIC_VP_NUM);

        let app_vp_verifying_info = application_vp.get_verifying_info();

        let app_dynamic_vp_verifying_info = dynamic_vps
            .into_iter()
            .map(|verifying_info| verifying_info.get_verifying_info())
            .collect();

        Self {
            app_vp_verifying_info,
            app_dynamic_vp_verifying_info,
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        // Verify application vp proof
        self.app_vp_verifying_info.verify()?;

        // Verify application dynamic vp proofs
        for verify_info in self.app_dynamic_vp_verifying_info.iter() {
            verify_info.verify()?;
        }

        // TODO: Verify vp verifier proofs

        Ok(())
    }

    pub fn get_nullifiers(&self) -> Vec<[pallas::Base; NUM_NOTE]> {
        let mut nfs = vec![self.app_vp_verifying_info.get_nullifiers()];
        self.app_dynamic_vp_verifying_info
            .iter()
            .for_each(|vp_info| nfs.push(vp_info.get_nullifiers()));
        nfs
    }

    pub fn get_note_commitments(&self) -> Vec<[NoteCommitment; NUM_NOTE]> {
        let mut cms = vec![self.app_vp_verifying_info.get_note_commitments()];
        self.app_dynamic_vp_verifying_info
            .iter()
            .for_each(|vp_info| cms.push(vp_info.get_note_commitments()));
        cms
    }
}

#[cfg(test)]
pub mod testing {
    use crate::{
        action::ActionInfo,
        circuit::vp_circuit::{ValidityPredicate, ValidityPredicateVerifyingInfo},
        circuit::vp_examples::TrivialValidityPredicateCircuit,
        constant::TAIGA_COMMITMENT_TREE_DEPTH,
        merkle_tree::MerklePath,
        note::{Note, NoteValidityPredicates, RandomSeed},
        nullifier::{Nullifier, NullifierKeyContainer},
        shielded_ptx::ShieldedPartialTransaction,
        utils::poseidon_hash,
    };
    use halo2_proofs::arithmetic::Field;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    pub fn create_shielded_ptx() -> ShieldedPartialTransaction {
        let mut rng = OsRng;

        // Create empty VP circuit without note info
        let trivial_vp_circuit = TrivialValidityPredicateCircuit::default();
        let trivial_vp_vk = trivial_vp_circuit.get_vp_vk();
        let compressed_trivial_vp_vk = trivial_vp_vk.get_compressed();

        // Generate notes
        let input_note_1 = {
            let app_data_static = pallas::Base::zero();
            // TODO: add real application dynamic VPs and encode them to app_data_dynamic later.
            let app_dynamic_vp_vk = [compressed_trivial_vp_vk, compressed_trivial_vp_vk];
            // Encode the app_dynamic_vp_vk into app_data_dynamic
            // The encoding method is flexible and defined in the application vp.
            // Use poseidon hash to encode the two dynamic VPs here
            let app_data_dynamic = poseidon_hash(app_dynamic_vp_vk[0], app_dynamic_vp_vk[1]);
            let rho = Nullifier::from(pallas::Base::random(&mut rng));
            let value = 5000u64;
            let nk = NullifierKeyContainer::random_key(&mut rng);
            let rseed = RandomSeed::random(&mut rng);
            let is_merkle_checked = true;
            Note::new(
                compressed_trivial_vp_vk,
                app_data_static,
                app_data_dynamic,
                value,
                nk,
                rho,
                is_merkle_checked,
                rseed,
            )
        };
        let output_note_1 = {
            let app_data_static = pallas::Base::zero();
            // TODO: add real application dynamic VPs and encode them to app_data_dynamic later.
            // If the dynamic VP is not used, set app_data_dynamic pallas::Base::zero() by default.
            let app_data_dynamic = pallas::Base::zero();
            let rho = input_note_1.get_nf().unwrap();
            let value = 5000u64;
            let nk_com = NullifierKeyContainer::random_commitment(&mut rng);
            let rseed = RandomSeed::random(&mut rng);
            let is_merkle_checked = true;
            Note::new(
                compressed_trivial_vp_vk,
                app_data_static,
                app_data_dynamic,
                value,
                nk_com,
                rho,
                is_merkle_checked,
                rseed,
            )
        };

        // Construct action pair
        let merkle_path_1 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let anchor_1 = input_note_1.calculate_root(&merkle_path_1);
        let rseed_1 = RandomSeed::random(&mut rng);
        let action_1 = ActionInfo::new(
            input_note_1,
            merkle_path_1,
            anchor_1,
            output_note_1,
            rseed_1,
        );

        // Generate notes
        let input_note_2 = {
            let app_data_static = pallas::Base::one();
            let app_data_dynamic = pallas::Base::zero();
            let rho = Nullifier::from(pallas::Base::random(&mut rng));
            let value = 10u64;
            let nk = NullifierKeyContainer::random_key(&mut rng);
            let rseed = RandomSeed::random(&mut rng);
            let is_merkle_checked = true;
            Note::new(
                compressed_trivial_vp_vk,
                app_data_static,
                app_data_dynamic,
                value,
                nk,
                rho,
                is_merkle_checked,
                rseed,
            )
        };
        let output_note_2 = {
            let app_data_static = pallas::Base::one();
            let app_data_dynamic = pallas::Base::zero();
            let rho = input_note_2.get_nf().unwrap();
            let value = 10u64;
            let nk_com = NullifierKeyContainer::random_commitment(&mut rng);
            let rseed = RandomSeed::random(&mut rng);
            let is_merkle_checked = true;
            Note::new(
                compressed_trivial_vp_vk,
                app_data_static,
                app_data_dynamic,
                value,
                nk_com,
                rho,
                is_merkle_checked,
                rseed,
            )
        };

        // Construct action pair
        let merkle_path_2 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let anchor_2 = input_note_2.calculate_root(&merkle_path_2);
        let rseed_2 = RandomSeed::random(&mut rng);
        let action_2 = ActionInfo::new(
            input_note_2,
            merkle_path_2,
            anchor_2,
            output_note_2,
            rseed_2,
        );

        // Create vp circuit and fill the note info
        let mut trivial_vp_circuit = TrivialValidityPredicateCircuit {
            owned_note_pub_id: input_note_1.get_nf().unwrap().inner(),
            input_notes: [input_note_1, input_note_2],
            output_notes: [output_note_1, output_note_2],
        };
        let input_application_vp_1 = Box::new(trivial_vp_circuit.clone());
        let trivial_app_logic_1: Box<ValidityPredicate> = Box::new(trivial_vp_circuit.clone());
        let trivial_app_logic_2 = Box::new(trivial_vp_circuit.clone());
        let trivial_dynamic_vps = vec![trivial_app_logic_1, trivial_app_logic_2];
        let input_note_1_vps =
            NoteValidityPredicates::new(input_application_vp_1, trivial_dynamic_vps);

        // The following notes use empty logic vps and use app_data_dynamic with pallas::Base::zero() by default.
        trivial_vp_circuit.owned_note_pub_id = input_note_2.get_nf().unwrap().inner();
        let input_application_vp_2 = Box::new(trivial_vp_circuit.clone());
        let input_note_2_vps = NoteValidityPredicates::new(input_application_vp_2, vec![]);

        trivial_vp_circuit.owned_note_pub_id = output_note_1.commitment().inner();
        let output_application_vp_1 = Box::new(trivial_vp_circuit.clone());
        let output_note_1_vps = NoteValidityPredicates::new(output_application_vp_1, vec![]);

        trivial_vp_circuit.owned_note_pub_id = output_note_2.commitment().inner();
        let output_application_vp_2 = Box::new(trivial_vp_circuit);
        let output_note_2_vps = NoteValidityPredicates::new(output_application_vp_2, vec![]);

        // Create shielded partial tx
        ShieldedPartialTransaction::build(
            vec![action_1, action_2],
            vec![input_note_1_vps, input_note_2_vps],
            vec![output_note_1_vps, output_note_2_vps],
            vec![],
            &mut rng,
        )
        .unwrap()
    }
}
