use crate::action::{ActionInfo, ActionInstance};
use crate::circuit::vp_circuit::{VPVerifyingInfo, ValidityPredicate};
use crate::constant::{
    ACTION_CIRCUIT_PARAMS_SIZE, ACTION_PROVING_KEY, ACTION_VERIFYING_KEY, MAX_DYNAMIC_VP_NUM,
    NUM_NOTE, SETUP_PARAMS_MAP,
};
use crate::error::TransactionError;
use crate::executable::Executable;
use crate::note::{InputNoteProvingInfo, NoteCommitment, OutputNoteProvingInfo};
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
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShieldedPartialTransaction {
    actions: [ActionVerifyingInfo; NUM_NOTE],
    inputs: [NoteVPVerifyingInfoSet; NUM_NOTE],
    outputs: [NoteVPVerifyingInfoSet; NUM_NOTE],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Action.VerifyingInfo")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActionVerifyingInfo {
    action_proof: Proof,
    action_instance: ActionInstance,
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
}

impl ShieldedPartialTransaction {
    pub fn build<R: RngCore>(
        input_info: [InputNoteProvingInfo; NUM_NOTE],
        output_info: [OutputNoteProvingInfo; NUM_NOTE],
        mut rng: R,
    ) -> (Self, pallas::Scalar) {
        let inputs: Vec<NoteVPVerifyingInfoSet> = input_info
            .iter()
            .map(|input_note| {
                NoteVPVerifyingInfoSet::build(
                    input_note.get_application_vp(),
                    input_note.get_dynamic_vps(),
                )
            })
            .collect();
        let outputs: Vec<NoteVPVerifyingInfoSet> = output_info
            .iter()
            .map(|output_note| {
                NoteVPVerifyingInfoSet::build(
                    output_note.get_application_vp(),
                    output_note.get_dynamic_vps(),
                )
            })
            .collect();
        let mut rcv_sum = pallas::Scalar::zero();
        let actions: Vec<ActionVerifyingInfo> = input_info
            .into_iter()
            .zip(output_info)
            .map(|(input, output)| {
                let action_info = ActionInfo::from_proving_info(input, output, &mut rng);
                rcv_sum += action_info.get_rcv();
                ActionVerifyingInfo::create(action_info, &mut rng).unwrap()
            })
            .collect();

        (
            Self {
                actions: actions.try_into().unwrap(),
                inputs: inputs.try_into().unwrap(),
                outputs: outputs.try_into().unwrap(),
            },
            rcv_sum,
        )
    }

    // verify zk proof
    fn verify_proof(&self) -> Result<(), Error> {
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
        }
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

    fn get_anchors(&self) -> Vec<pallas::Base> {
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
        Ok(ShieldedPartialTransaction {
            actions: actions.try_into().unwrap(),
            inputs: inputs.try_into().unwrap(),
            outputs: outputs.try_into().unwrap(),
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
    pub fn create<R: RngCore>(action_info: ActionInfo, mut rng: R) -> Result<Self, Error> {
        let (action_instance, circuit) = action_info.build();
        let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();
        let action_proof = Proof::create(
            &ACTION_PROVING_KEY,
            params,
            circuit,
            &[&action_instance.to_instance()],
            &mut rng,
        )
        .unwrap();
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
        circuit::vp_circuit::{ValidityPredicate, ValidityPredicateVerifyingInfo},
        circuit::vp_examples::TrivialValidityPredicateCircuit,
        constant::TAIGA_COMMITMENT_TREE_DEPTH,
        merkle_tree::MerklePath,
        note::{InputNoteProvingInfo, Note, OutputNoteProvingInfo, RandomSeed},
        nullifier::{Nullifier, NullifierKeyContainer},
        shielded_ptx::ShieldedPartialTransaction,
        utils::poseidon_hash,
    };
    use halo2_proofs::arithmetic::Field;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    pub fn create_shielded_ptx() -> (ShieldedPartialTransaction, pallas::Scalar) {
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

        // Generate note info
        let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
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
        let input_note_proving_info_1 = InputNoteProvingInfo::new(
            input_note_1,
            merkle_path.clone(),
            input_application_vp_1,
            trivial_dynamic_vps.clone(),
        );
        // The following notes use empty logic vps and use app_data_dynamic with pallas::Base::zero() by default.
        trivial_vp_circuit.owned_note_pub_id = input_note_2.get_nf().unwrap().inner();
        let input_application_vp_2 = Box::new(trivial_vp_circuit.clone());
        let dynamic_vps = vec![];
        let input_note_proving_info_2 = InputNoteProvingInfo::new(
            input_note_2,
            merkle_path,
            input_application_vp_2,
            dynamic_vps.clone(),
        );

        trivial_vp_circuit.owned_note_pub_id = output_note_1.commitment().inner();
        let output_application_vp_1 = Box::new(trivial_vp_circuit.clone());
        let output_note_proving_info_1 =
            OutputNoteProvingInfo::new(output_note_1, output_application_vp_1, dynamic_vps.clone());

        trivial_vp_circuit.owned_note_pub_id = output_note_2.commitment().inner();
        let output_application_vp_2 = Box::new(trivial_vp_circuit);
        let output_note_proving_info_2 =
            OutputNoteProvingInfo::new(output_note_2, output_application_vp_2, dynamic_vps);

        // Create shielded partial tx
        ShieldedPartialTransaction::build(
            [input_note_proving_info_1, input_note_proving_info_2],
            [output_note_proving_info_1, output_note_proving_info_2],
            &mut rng,
        )
    }
}
