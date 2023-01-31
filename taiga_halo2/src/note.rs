use crate::{
    circuit::vp_circuit::ValidityPredicateInfo,
    constant::{
        BASE_BITS_NUM, NOTE_COMMIT_DOMAIN, POSEIDON_TO_CURVE_INPUT_LEN, TAIGA_COMMITMENT_TREE_DEPTH,
    },
    merkle_tree::{MerklePath, Node},
    nullifier::{Nullifier, NullifierDerivingKey, NullifierKeyCom},
    utils::{extract_p, poseidon_hash, poseidon_to_curve},
    vp_vk::ValidityPredicateVerifyingKey,
};
use bitvec::{array::BitArray, order::Lsb0};
use core::iter;
use ff::{Field, PrimeFieldBits};
use group::{Group, GroupEncoding};
use pasta_curves::pallas;
use rand::{Rng, RngCore};

/// A commitment to a note.
#[derive(Copy, Debug, Clone)]
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

/// A note
#[derive(Debug, Clone, Default)]
pub struct Note {
    pub value_base: NoteValueBase,
    /// vp_data_nonhashed is the data defined in application vp and will NOT be used to derive value base
    /// vp_data_nonhashed denotes the encoded user-specific data and sub-vps
    pub vp_data_nonhashed: pallas::Base,
    /// value denotes the amount of the note.
    pub value: u64,
    /// the wrapped nullifier key.
    pub nk_com: NullifierKeyCom,
    /// old nullifier. Nonce which is a deterministically computed, unique nonce
    pub rho: Nullifier,
    /// computed from spent_note_nf and rcm by using a PRF
    pub psi: pallas::Base,
    pub rcm: pallas::Scalar,
    /// If the is_merkle_checked flag is true, the merkle path authorization(membership) of the spent note will be checked in ActionProof.
    pub is_merkle_checked: bool,
    /// note data bytes
    pub note_data: Vec<u8>,
}

/// The parameters in the NoteValueBase are used to derive note value base.
#[derive(Debug, Clone, Default)]
pub struct NoteValueBase {
    /// app_vk is the verifying key of VP
    app_vk: ValidityPredicateVerifyingKey,
    /// app_data is the encoded data that is defined in application vp
    app_data: pallas::Base,
}

#[derive(Clone)]
pub struct SpendNoteInfo {
    pub note: Note,
    pub auth_path: [(pallas::Base, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    pub root: pallas::Base,
    app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
    app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
}

#[derive(Clone)]
pub struct OutputNoteInfo {
    pub note: Note,
    app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
    app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
}

impl Note {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_vk: ValidityPredicateVerifyingKey,
        app_data: pallas::Base,
        vp_data_nonhashed: pallas::Base,
        value: u64,
        nk_com: NullifierKeyCom,
        rho: Nullifier,
        psi: pallas::Base,
        rcm: pallas::Scalar,
        is_merkle_checked: bool,
        note_data: Vec<u8>,
    ) -> Self {
        let value_base = NoteValueBase::new(app_vk, app_data);
        Self {
            value_base,
            vp_data_nonhashed,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            is_merkle_checked,
            note_data,
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        Self::dummy_from_rho(rng, rho)
    }

    pub fn dummy_from_rho<R: RngCore>(mut rng: R, rho: Nullifier) -> Self {
        let app_vk = ValidityPredicateVerifyingKey::dummy(&mut rng);
        let app_data = pallas::Base::random(&mut rng);
        let value_base = NoteValueBase::new(app_vk, app_data);
        let vp_data_nonhashed = pallas::Base::zero();
        let value: u64 = rng.gen();
        let nk_com = NullifierKeyCom::rand(&mut rng);
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        let note_data = vec![0u8; 32];
        Self {
            value_base,
            vp_data_nonhashed,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            is_merkle_checked: true,
            note_data,
        }
    }

    // cm = SinsemillaCommit^rcm(address || app_vk || app_data || rho || psi || is_merkle_checked || value)
    pub fn commitment(&self) -> NoteCommitment {
        let address = self.get_address();
        let ret = NOTE_COMMIT_DOMAIN
            .commit(
                iter::empty()
                    .chain(address.to_le_bits().iter().by_vals().take(BASE_BITS_NUM))
                    .chain(
                        self.get_compressed_app_vk()
                            .to_le_bits()
                            .iter()
                            .by_vals()
                            .take(BASE_BITS_NUM),
                    )
                    .chain(
                        self.get_value_base_app_data()
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
                    .chain(self.psi.to_le_bits().iter().by_vals().take(BASE_BITS_NUM))
                    .chain([self.is_merkle_checked])
                    .chain(
                        BitArray::<_, Lsb0>::new(self.value.to_le())
                            .iter()
                            .by_vals(),
                    ),
                &self.rcm,
            )
            .unwrap();
        NoteCommitment(ret)
    }

    pub fn get_nf(&self) -> Option<Nullifier> {
        match self.get_nk() {
            Some(nk) => {
                let cm = self.commitment();
                Some(Nullifier::derive_native(
                    &nk,
                    &self.rho.inner(),
                    &self.psi,
                    &cm,
                ))
            }
            None => None,
        }
    }

    pub fn get_address(&self) -> pallas::Base {
        poseidon_hash(self.vp_data_nonhashed, self.nk_com.get_nk_com())
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey> {
        self.nk_com.get_nk()
    }

    pub fn get_value_base(&self) -> pallas::Point {
        self.value_base.derive_value_base()
    }

    pub fn get_compressed_app_vk(&self) -> pallas::Base {
        self.value_base.app_vk.get_compressed()
    }

    pub fn get_value_base_app_data(&self) -> pallas::Base {
        self.value_base.app_data
    }
}

impl NoteValueBase {
    pub fn new(vk: ValidityPredicateVerifyingKey, data: pallas::Base) -> Self {
        Self {
            app_vk: vk,
            app_data: data,
        }
    }

    pub fn derive_value_base(&self) -> pallas::Point {
        let inputs = [self.app_vk.get_compressed(), self.app_data];
        poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&inputs)
    }
}

impl SpendNoteInfo {
    pub fn new(
        note: Note,
        merkle_path: MerklePath,
        app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
        app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
    ) -> Self {
        let cm_node = Node::new(note.commitment().get_x());
        let root = merkle_path.root(cm_node).inner();
        let auth_path: [(pallas::Base, bool); TAIGA_COMMITMENT_TREE_DEPTH] =
            merkle_path.get_path().as_slice().try_into().unwrap();
        Self {
            note,
            auth_path,
            root,
            app_vp_proving_info,
            app_logic_vp_proving_info,
        }
    }

    pub fn get_app_vp_proving_info(&self) -> Box<dyn ValidityPredicateInfo> {
        self.app_vp_proving_info.clone()
    }

    pub fn get_app_logic_vp_proving_info(&self) -> Vec<Box<dyn ValidityPredicateInfo>> {
        self.app_logic_vp_proving_info.clone()
    }
}

impl OutputNoteInfo {
    pub fn new(
        note: Note,
        app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
        app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
    ) -> Self {
        Self {
            note,
            app_vp_proving_info,
            app_logic_vp_proving_info,
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R, nf: Nullifier) -> Self {
        use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
        let note = Note::dummy_from_rho(&mut rng, nf);
        let app_vp_proving_info = Box::new(TrivialValidityPredicateCircuit::dummy(&mut rng));
        let app_logic_vp_proving_info = vec![];
        Self {
            note,
            app_vp_proving_info,
            app_logic_vp_proving_info,
        }
    }

    pub fn get_app_vp_proving_info(&self) -> Box<dyn ValidityPredicateInfo> {
        self.app_vp_proving_info.clone()
    }

    pub fn get_app_logic_vp_proving_info(&self) -> Vec<Box<dyn ValidityPredicateInfo>> {
        self.app_logic_vp_proving_info.clone()
    }
}
