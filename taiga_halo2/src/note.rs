use crate::{
    circuit::{
        vp_circuit::ValidityPredicate,
        vp_examples::{TrivialValidityPredicateCircuit, COMPRESSED_TRIVIAL_VP_VK},
    },
    constant::{
        BASE_BITS_NUM, NOTE_COMMIT_DOMAIN, NUM_NOTE, POSEIDON_TO_CURVE_INPUT_LEN,
        PRF_EXPAND_INPUT_VP_CM_R, PRF_EXPAND_OUTPUT_VP_CM_R, PRF_EXPAND_PERSONALIZATION,
        PRF_EXPAND_PSI, PRF_EXPAND_PUBLIC_INPUT_PADDING, PRF_EXPAND_RCM, PRF_EXPAND_VCM_R,
    },
    merkle_tree::MerklePath,
    nullifier::{Nullifier, NullifierKeyContainer},
    utils::{extract_p, mod_r_p, poseidon_hash, poseidon_to_curve},
};
use bitvec::{array::BitArray, order::Lsb0};
use blake2b_simd::Params as Blake2bParams;
use core::iter;
use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::arithmetic::Field;
use pasta_curves::{
    group::{ff::PrimeFieldBits, Group, GroupEncoding},
    pallas,
};
use rand::RngCore;
use std::hash::{Hash, Hasher};

#[cfg(feature = "nif")]
use rustler::{NifStruct, NifTuple};

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// A commitment to a note.
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifTuple))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NoteCommitment(pallas::Point);

impl NoteCommitment {
    pub fn inner(&self) -> pallas::Point {
        self.0
    }

    pub fn get_x(&self) -> pallas::Base {
        extract_p(&self.0)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Default for NoteCommitment {
    fn default() -> NoteCommitment {
        NoteCommitment(pallas::Point::generator())
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for NoteCommitment {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_bytes())?;
        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for NoteCommitment {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        let value = Option::from(pallas::Point::from_bytes(&repr)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Node value not in field")
        })?;
        Ok(Self(value))
    }
}

impl Hash for NoteCommitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().as_ref().hash(state);
    }
}

/// A note
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Note")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Note {
    pub note_type: NoteType,
    /// app_data_dynamic is the data defined in application vp and will NOT be used to derive type
    /// sub-vps and any other data can be encoded to the app_data_dynamic
    pub app_data_dynamic: pallas::Base,
    /// value denotes the amount of the note.
    pub value: u64,
    /// NullifierKeyContainer contains the nullifier_key or the nullifier_key commitment.
    pub nk_container: NullifierKeyContainer,
    /// old nullifier. Nonce which is a deterministically computed, unique nonce
    pub rho: Nullifier,
    /// psi is to derive the nullifier
    pub psi: pallas::Base,
    /// rcm is the trapdoor of the note commitment
    pub rcm: pallas::Base,
    /// If the is_merkle_checked flag is true, the merkle path authorization(membership) of input note will be checked in ActionProof.
    pub is_merkle_checked: bool,
}

/// The parameters in the NoteType are used to derive note type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.NoteType")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NoteType {
    /// app_vk is the compressed verifying key of VP
    pub app_vk: pallas::Base,
    /// app_data_static is the encoded data that is defined in application vp
    pub app_data_static: pallas::Base,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct RandomSeed([u8; 32]);

#[derive(Clone)]
pub struct InputNoteProvingInfo {
    pub note: Note,
    pub merkle_path: MerklePath,
    application_vp: Box<ValidityPredicate>,
    dynamic_vps: Vec<Box<ValidityPredicate>>,
}

#[derive(Clone)]
pub struct OutputNoteProvingInfo {
    pub note: Note,
    application_vp: Box<ValidityPredicate>,
    dynamic_vps: Vec<Box<ValidityPredicate>>,
}

impl Note {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_vk: pallas::Base,
        app_data_static: pallas::Base,
        app_data_dynamic: pallas::Base,
        value: u64,
        nk_container: NullifierKeyContainer,
        rho: Nullifier,
        is_merkle_checked: bool,
        rseed: RandomSeed,
    ) -> Self {
        let note_type = NoteType::new(app_vk, app_data_static);
        Self {
            note_type,
            app_data_dynamic,
            value,
            nk_container,
            is_merkle_checked,
            psi: rseed.get_psi(&rho),
            rcm: rseed.get_rcm(&rho),
            rho,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_full(
        app_vk: pallas::Base,
        app_data_static: pallas::Base,
        app_data_dynamic: pallas::Base,
        value: u64,
        nk_container: NullifierKeyContainer,
        rho: Nullifier,
        is_merkle_checked: bool,
        psi: pallas::Base,
        rcm: pallas::Base,
    ) -> Self {
        let note_type = NoteType::new(app_vk, app_data_static);
        Self {
            note_type,
            app_data_dynamic,
            value,
            nk_container,
            is_merkle_checked,
            psi,
            rcm,
            rho,
        }
    }

    pub fn random_padding_input_note<R: RngCore>(mut rng: R) -> Self {
        let app_vk = *COMPRESSED_TRIVIAL_VP_VK;
        let app_data_static = pallas::Base::random(&mut rng);
        let note_type = NoteType::new(app_vk, app_data_static);
        let app_data_dynamic = pallas::Base::random(&mut rng);
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        let nk = NullifierKeyContainer::from_key(pallas::Base::random(&mut rng));
        let rseed = RandomSeed::random(&mut rng);
        Note {
            note_type,
            app_data_dynamic,
            value: 0,
            nk_container: nk,
            rho,
            psi: rseed.get_psi(&rho),
            rcm: rseed.get_rcm(&rho),
            is_merkle_checked: false,
        }
    }

    pub fn random_padding_output_note<R: RngCore>(mut rng: R, rho: Nullifier) -> Self {
        let app_vk = *COMPRESSED_TRIVIAL_VP_VK;
        let app_data_static = pallas::Base::random(&mut rng);
        let note_type = NoteType::new(app_vk, app_data_static);
        let app_data_dynamic = pallas::Base::random(&mut rng);
        let nk_com = NullifierKeyContainer::from_commitment(pallas::Base::random(&mut rng));
        let rseed = RandomSeed::random(&mut rng);
        Note {
            note_type,
            app_data_dynamic,
            value: 0,
            nk_container: nk_com,
            rho,
            psi: rseed.get_psi(&rho),
            rcm: rseed.get_rcm(&rho),
            is_merkle_checked: false,
        }
    }
    // cm = SinsemillaCommit^rcm(address || app_vk || app_data_static || rho || psi || is_merkle_checked || value)
    pub fn commitment(&self) -> NoteCommitment {
        let address = self.get_address();
        let ret = NOTE_COMMIT_DOMAIN
            .commit(
                iter::empty()
                    .chain(address.to_le_bits().iter().by_vals().take(BASE_BITS_NUM))
                    .chain(
                        self.get_app_vk()
                            .to_le_bits()
                            .iter()
                            .by_vals()
                            .take(BASE_BITS_NUM),
                    )
                    .chain(
                        self.get_app_data_static()
                            .to_le_bits()
                            .iter()
                            .by_vals()
                            .take(BASE_BITS_NUM),
                    )
                    .chain(
                        self.rho
                            .inner()
                            .to_le_bits()
                            .iter()
                            .by_vals()
                            .take(BASE_BITS_NUM),
                    )
                    .chain(
                        self.get_psi()
                            .to_le_bits()
                            .iter()
                            .by_vals()
                            .take(BASE_BITS_NUM),
                    )
                    .chain([self.is_merkle_checked])
                    .chain(
                        BitArray::<_, Lsb0>::new(self.value.to_le())
                            .iter()
                            .by_vals(),
                    ),
                &mod_r_p(self.get_rcm()),
            )
            .unwrap();
        NoteCommitment(ret)
    }

    pub fn get_nf(&self) -> Option<Nullifier> {
        Nullifier::derive(
            &self.nk_container,
            &self.rho.inner(),
            &self.psi,
            &self.commitment(),
        )
    }

    pub fn get_address(&self) -> pallas::Base {
        poseidon_hash(self.app_data_dynamic, self.get_nk_commitment())
    }

    pub fn get_nk(&self) -> Option<pallas::Base> {
        self.nk_container.get_nk()
    }

    pub fn get_nk_commitment(&self) -> pallas::Base {
        self.nk_container.get_commitment()
    }

    pub fn get_note_type(&self) -> pallas::Point {
        self.note_type.derive_note_type()
    }

    pub fn get_app_vk(&self) -> pallas::Base {
        self.note_type.app_vk
    }

    pub fn get_app_data_static(&self) -> pallas::Base {
        self.note_type.app_data_static
    }

    pub fn get_psi(&self) -> pallas::Base {
        self.psi
    }

    pub fn get_rcm(&self) -> pallas::Base {
        self.rcm
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for Note {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        use byteorder::{LittleEndian, WriteBytesExt};
        // Write app_vk
        writer.write_all(&self.note_type.app_vk.to_repr())?;
        // Write app_data_static
        writer.write_all(&self.note_type.app_data_static.to_repr())?;
        // Write app_data_dynamic
        writer.write_all(&self.app_data_dynamic.to_repr())?;
        // Write note value
        writer.write_u64::<LittleEndian>(self.value)?;
        // Write nk_container
        match self.nk_container {
            NullifierKeyContainer::Commitment(nk) => {
                writer.write_u8(1)?;
                writer.write_all(&nk.to_repr())
            }
            NullifierKeyContainer::Key(nk) => {
                writer.write_u8(2)?;
                writer.write_all(&nk.to_repr())
            }
        }?;
        // Write rho
        writer.write_all(&self.rho.to_bytes())?;
        // Write psi
        writer.write_all(&self.psi.to_repr())?;
        // Write rcm
        writer.write_all(&self.rcm.to_repr())?;
        // Write is_merkle_checked
        writer.write_u8(if self.is_merkle_checked { 1 } else { 0 })?;

        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for Note {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io;
        // Read app_vk
        let mut app_vk_bytes = [0u8; 32];
        reader.read_exact(&mut app_vk_bytes)?;
        let app_vk = Option::from(pallas::Base::from_repr(app_vk_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "app_vk not in field"))?;
        // Read app_data_static
        let mut app_data_static_bytes = [0u8; 32];
        reader.read_exact(&mut app_data_static_bytes)?;
        let app_data_static = Option::from(pallas::Base::from_repr(app_data_static_bytes))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "app_data_static not in field")
            })?;
        // Read app_data_dynamic
        let mut app_data_dynamic_bytes = [0u8; 32];
        reader.read_exact(&mut app_data_dynamic_bytes)?;
        let app_data_dynamic = Option::from(pallas::Base::from_repr(app_data_dynamic_bytes))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "app_data_dynamic not in field")
            })?;
        // Read note value
        let value = reader.read_u64::<LittleEndian>()?;
        // Read nk_container
        let mut nk_container_type = [0u8; 1];
        reader.read_exact(&mut nk_container_type)?;
        let nk_container_type = nk_container_type[0];
        let mut nk_container_bytes = [0u8; 32];
        reader.read_exact(&mut nk_container_bytes)?;
        let nk = Option::from(pallas::Base::from_repr(nk_container_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "nk not in field"))?;
        let nk_container = if nk_container_type == 0x01 {
            NullifierKeyContainer::from_commitment(nk)
        } else {
            NullifierKeyContainer::from_key(nk)
        };
        // Read rho
        let mut rho_bytes = [0u8; 32];
        reader.read_exact(&mut rho_bytes)?;
        let rho = Option::from(Nullifier::from_bytes(rho_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "rho not in field"))?;
        // Read psi
        let mut psi_bytes = [0u8; 32];
        reader.read_exact(&mut psi_bytes)?;
        let psi = Option::from(pallas::Base::from_repr(psi_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "psi not in field"))?;
        // Read rcm
        let mut rcm_bytes = [0u8; 32];
        reader.read_exact(&mut rcm_bytes)?;
        let rcm = Option::from(pallas::Base::from_repr(rcm_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "rcm not in field"))?;
        // Read is_merkle_checked
        let mut is_merkle_checked_byte = [0u8; 1];
        reader.read_exact(&mut is_merkle_checked_byte)?;
        let is_merkle_checked_byte = is_merkle_checked_byte[0];
        let is_merkle_checked = is_merkle_checked_byte == 0x01;
        // Construct note
        Ok(Note::from_full(
            app_vk,
            app_data_static,
            app_data_dynamic,
            value,
            nk_container,
            rho,
            is_merkle_checked,
            psi,
            rcm,
        ))
    }
}

impl NoteType {
    pub fn new(vk: pallas::Base, data: pallas::Base) -> Self {
        Self {
            app_vk: vk,
            app_data_static: data,
        }
    }

    pub fn derive_note_type(&self) -> pallas::Point {
        let inputs = [self.app_vk, self.app_data_static];
        poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&inputs)
    }
}

impl Hash for NoteType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.app_vk.to_repr().as_ref().hash(state);
        self.app_data_static.to_repr().as_ref().hash(state);
    }
}

impl RandomSeed {
    pub fn random<R: RngCore>(mut rng: R) -> Self {
        let mut rseed = [0; 32];
        rng.fill_bytes(&mut rseed);
        Self(rseed)
    }

    pub fn from_bytes(rseed: [u8; 32]) -> Self {
        Self(rseed)
    }

    pub fn get_psi(&self, rho: &Nullifier) -> pallas::Base {
        let mut h = Blake2bParams::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state();
        h.update(&[PRF_EXPAND_PSI]);
        h.update(&self.0);
        h.update(&rho.to_bytes());
        let psi_bytes = *h.finalize().as_array();
        pallas::Base::from_uniform_bytes(&psi_bytes)
    }

    pub fn get_rcm(&self, rho: &Nullifier) -> pallas::Base {
        let mut h = Blake2bParams::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state();
        h.update(&[PRF_EXPAND_RCM]);
        h.update(&self.0);
        h.update(&rho.to_bytes());
        let rcm_bytes = *h.finalize().as_array();
        pallas::Base::from_uniform_bytes(&rcm_bytes)
    }

    pub fn get_random_padding(&self, padding_len: usize) -> Vec<pallas::Base> {
        (0..padding_len)
            .map(|i| {
                let mut h = Blake2bParams::new()
                    .hash_length(64)
                    .personal(PRF_EXPAND_PERSONALIZATION)
                    .to_state();
                h.update(&[PRF_EXPAND_PUBLIC_INPUT_PADDING, i as u8]);
                h.update(&self.0);
                let rcm_bytes = *h.finalize().as_array();
                pallas::Base::from_uniform_bytes(&rcm_bytes)
            })
            .collect()
    }

    pub fn get_rcv(&self) -> pallas::Scalar {
        let mut h = Blake2bParams::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state();
        h.update(&[PRF_EXPAND_VCM_R]);
        h.update(&self.0);
        let bytes = *h.finalize().as_array();
        pallas::Scalar::from_uniform_bytes(&bytes)
    }

    pub fn get_input_vp_cm_r(&self) -> pallas::Base {
        let mut h = Blake2bParams::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state();
        h.update(&[PRF_EXPAND_INPUT_VP_CM_R]);
        h.update(&self.0);
        let bytes = *h.finalize().as_array();
        pallas::Base::from_uniform_bytes(&bytes)
    }

    pub fn get_output_vp_cm_r(&self) -> pallas::Base {
        let mut h = Blake2bParams::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state();
        h.update(&[PRF_EXPAND_OUTPUT_VP_CM_R]);
        h.update(&self.0);
        let bytes = *h.finalize().as_array();
        pallas::Base::from_uniform_bytes(&bytes)
    }
}

impl InputNoteProvingInfo {
    pub fn new(
        note: Note,
        merkle_path: MerklePath,
        application_vp: Box<ValidityPredicate>,
        dynamic_vps: Vec<Box<ValidityPredicate>>,
    ) -> Self {
        Self {
            note,
            merkle_path,
            application_vp,
            dynamic_vps,
        }
    }

    pub fn get_application_vp(&self) -> Box<ValidityPredicate> {
        self.application_vp.clone()
    }

    pub fn get_dynamic_vps(&self) -> Vec<Box<ValidityPredicate>> {
        self.dynamic_vps.clone()
    }

    pub fn create_padding_note_proving_info(
        padding_note: Note,
        merkle_path: MerklePath,
        input_notes: [Note; NUM_NOTE],
        output_notes: [Note; NUM_NOTE],
    ) -> Self {
        let trivail_vp = Box::new(TrivialValidityPredicateCircuit {
            owned_note_pub_id: padding_note.get_nf().unwrap().inner(),
            input_notes,
            output_notes,
        });
        InputNoteProvingInfo::new(padding_note, merkle_path, trivail_vp, vec![])
    }
}

impl OutputNoteProvingInfo {
    pub fn new(
        note: Note,
        application_vp: Box<ValidityPredicate>,
        dynamic_vps: Vec<Box<ValidityPredicate>>,
    ) -> Self {
        Self {
            note,
            application_vp,
            dynamic_vps,
        }
    }

    pub fn get_application_vp(&self) -> Box<ValidityPredicate> {
        self.application_vp.clone()
    }

    pub fn get_dynamic_vps(&self) -> Vec<Box<ValidityPredicate>> {
        self.dynamic_vps.clone()
    }

    pub fn create_padding_note_proving_info(
        padding_note: Note,
        input_notes: [Note; NUM_NOTE],
        output_notes: [Note; NUM_NOTE],
    ) -> Self {
        let trivail_vp = Box::new(TrivialValidityPredicateCircuit {
            owned_note_pub_id: padding_note.commitment().get_x(),
            input_notes,
            output_notes,
        });
        OutputNoteProvingInfo::new(padding_note, trivail_vp, vec![])
    }
}

#[cfg(test)]
pub mod tests {
    use super::{InputNoteProvingInfo, Note, NoteType, OutputNoteProvingInfo, RandomSeed};
    use crate::{
        circuit::vp_examples::tests::random_trivial_vp_circuit,
        constant::TAIGA_COMMITMENT_TREE_DEPTH,
        merkle_tree::MerklePath,
        nullifier::{tests::*, Nullifier, NullifierKeyContainer},
    };
    use halo2_proofs::arithmetic::Field;
    use pasta_curves::pallas;
    use rand::{Rng, RngCore};

    pub fn random_note_type<R: RngCore>(mut rng: R) -> NoteType {
        let app_vk = pallas::Base::random(&mut rng);
        let app_data_static = pallas::Base::random(&mut rng);
        NoteType::new(app_vk, app_data_static)
    }

    pub fn random_input_note<R: RngCore>(mut rng: R) -> Note {
        let rho = random_nullifier(&mut rng);
        let nk = random_nullifier_key(&mut rng);
        random_note_from_parts(&mut rng, rho, nk)
    }

    pub fn random_output_note<R: RngCore>(mut rng: R, rho: Nullifier) -> Note {
        let nk_com = random_nullifier_key_commitment(&mut rng);
        random_note_from_parts(&mut rng, rho, nk_com)
    }

    fn random_note_from_parts<R: RngCore>(
        mut rng: R,
        rho: Nullifier,
        nk_container: NullifierKeyContainer,
    ) -> Note {
        let note_type = random_note_type(&mut rng);
        let app_data_dynamic = pallas::Base::random(&mut rng);
        let value: u64 = rng.gen();
        let rseed = RandomSeed::random(&mut rng);
        Note {
            note_type,
            app_data_dynamic,
            value,
            nk_container,
            is_merkle_checked: true,
            psi: rseed.get_psi(&rho),
            rcm: rseed.get_rcm(&rho),
            rho,
        }
    }

    pub fn random_input_proving_info<R: RngCore>(mut rng: R) -> InputNoteProvingInfo {
        let note = random_input_note(&mut rng);
        let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let application_vp = Box::new(random_trivial_vp_circuit(&mut rng));
        let dynamic_vps = vec![];
        InputNoteProvingInfo::new(note, merkle_path, application_vp, dynamic_vps)
    }

    pub fn random_output_proving_info<R: RngCore>(
        mut rng: R,
        rho: Nullifier,
    ) -> OutputNoteProvingInfo {
        let note = random_output_note(&mut rng, rho);
        let application_vp = Box::new(random_trivial_vp_circuit(&mut rng));
        let dynamic_vps = vec![];
        OutputNoteProvingInfo {
            note,
            application_vp,
            dynamic_vps,
        }
    }

    #[cfg(feature = "borsh")]
    #[test]
    fn note_borsh_serialization_test() {
        use borsh::BorshDeserialize;
        use rand::rngs::OsRng;

        use crate::note::NoteCommitment;
        let mut rng = OsRng;

        let input_note = random_input_note(&mut rng);
        {
            // BorshSerialize
            let borsh = borsh::to_vec(&input_note).unwrap();
            // BorshDeserialize
            let de_note: Note = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            assert_eq!(input_note, de_note);
        }

        let output_note = random_output_note(&mut rng, input_note.rho);
        {
            // BorshSerialize
            let borsh = borsh::to_vec(&output_note).unwrap();
            // BorshDeserialize
            let de_note: Note = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            assert_eq!(output_note, de_note);
        }

        let icm = input_note.commitment();
        {
            // BorshSerialize
            let borsh = borsh::to_vec(&icm).unwrap();
            // BorshDeserialize
            let de_icm: NoteCommitment =
                BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            assert_eq!(icm, de_icm);
        }

        let ocm = output_note.commitment();
        {
            // BorshSerialize
            let borsh = borsh::to_vec(&ocm).unwrap();
            // BorshDeserialize
            let de_ocm: NoteCommitment =
                BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            assert_eq!(ocm, de_ocm);
        }
    }
}
