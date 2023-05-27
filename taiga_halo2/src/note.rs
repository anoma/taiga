use crate::{
    circuit::{vp_circuit::ValidityPredicateVerifyingInfo, vp_examples::TRIVIAL_VP_VK},
    constant::{
        BASE_BITS_NUM, NOTE_COMMIT_DOMAIN, POSEIDON_TO_CURVE_INPUT_LEN, TAIGA_COMMITMENT_TREE_DEPTH,
    },
    merkle_tree::{MerklePath, Node, LR},
    nullifier::{Nullifier, NullifierDerivingKey, NullifierKeyCom},
    utils::{extract_p, poseidon_hash, poseidon_to_curve},
    vp_vk::ValidityPredicateVerifyingKey,
};
use bitvec::{array::BitArray, order::Lsb0};
use core::iter;
use halo2_proofs::arithmetic::Field;
use pasta_curves::{
    group::{ff::PrimeFieldBits, Group, GroupEncoding},
    pallas,
};
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
// TODO: add copy when app_vk is changed to pallas::Base
#[derive(Debug, Clone, Default)]
pub struct Note {
    pub note_type: ValueBase,
    /// app_data_dynamic is the data defined in application vp and will NOT be used to derive value base
    /// sub-vps and any other data can be encoded to the app_data_dynamic
    pub app_data_dynamic: pallas::Base,
    /// value denotes the amount of the note.
    pub value: u64,
    /// the wrapped nullifier key.
    pub nk_com: NullifierKeyCom,
    /// old nullifier. Nonce which is a deterministically computed, unique nonce
    pub rho: Nullifier,
    /// computed from input_note_nf and rcm by using a PRF
    pub psi: pallas::Base,
    pub rcm: pallas::Scalar,
    /// If the is_merkle_checked flag is true, the merkle path authorization(membership) of input note will be checked in ActionProof.
    pub is_merkle_checked: bool,
}

/// The parameters in the ValueBase are used to derive note value base.
// TODO: add copy when app_vk is changed to pallas::Base
#[derive(Debug, Clone, Default)]
pub struct ValueBase {
    /// app_vk is the verifying key of VP
    pub app_vk: ValidityPredicateVerifyingKey,
    /// app_data_static is the encoded data that is defined in application vp
    pub app_data_static: pallas::Base,
}

#[derive(Clone)]
pub struct InputNoteInfo {
    pub note: Note,
    pub auth_path: [(pallas::Base, LR); TAIGA_COMMITMENT_TREE_DEPTH],
    pub root: pallas::Base,
    app_vp_verifying_info: Box<dyn ValidityPredicateVerifyingInfo>,
    app_vp_verifying_info_dynamic: Vec<Box<dyn ValidityPredicateVerifyingInfo>>,
}

#[derive(Clone)]
pub struct OutputNoteInfo {
    pub note: Note,
    app_vp_verifying_info: Box<dyn ValidityPredicateVerifyingInfo>,
    app_vp_verifying_info_dynamic: Vec<Box<dyn ValidityPredicateVerifyingInfo>>,
}

impl Note {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_vk: ValidityPredicateVerifyingKey,
        app_data_static: pallas::Base,
        app_data_dynamic: pallas::Base,
        value: u64,
        nk_com: NullifierKeyCom,
        rho: Nullifier,
        psi: pallas::Base,
        rcm: pallas::Scalar,
        is_merkle_checked: bool,
    ) -> Self {
        let note_type = ValueBase::new(app_vk, app_data_static);
        Self {
            note_type,
            app_data_dynamic,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            is_merkle_checked,
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        Self::dummy_from_rho(rng, rho)
    }

    pub fn dummy_from_rho<R: RngCore>(mut rng: R, rho: Nullifier) -> Self {
        let app_vk = ValidityPredicateVerifyingKey::dummy(&mut rng);
        let app_data_static = pallas::Base::random(&mut rng);
        let note_type = ValueBase::new(app_vk, app_data_static);
        let app_data_dynamic = pallas::Base::zero();
        let value: u64 = rng.gen();
        let nk_com = NullifierKeyCom::rand(&mut rng);
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        Self {
            note_type,
            app_data_dynamic,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            is_merkle_checked: true,
        }
    }

    pub fn dummy_zero_note<R: RngCore>(mut rng: R, rho: Nullifier) -> Self {
        let app_vk = TRIVIAL_VP_VK.clone();
        let app_data_static = pallas::Base::random(&mut rng);
        let note_type = ValueBase::new(app_vk, app_data_static);
        let app_data_dynamic = pallas::Base::zero();
        let nk_com = NullifierKeyCom::rand(&mut rng);
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        Self {
            note_type,
            app_data_dynamic,
            value: 0,
            nk_com,
            rho,
            psi,
            rcm,
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
                        self.get_compressed_app_vk()
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
        poseidon_hash(self.app_data_dynamic, self.nk_com.get_nk_com())
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey> {
        self.nk_com.get_nk()
    }

    pub fn get_value_base(&self) -> pallas::Point {
        self.note_type.derive_value_base()
    }

    pub fn get_compressed_app_vk(&self) -> pallas::Base {
        self.note_type.app_vk.get_compressed()
    }

    pub fn get_app_data_static(&self) -> pallas::Base {
        self.note_type.app_data_static
    }
}

impl ValueBase {
    pub fn new(vk: ValidityPredicateVerifyingKey, data: pallas::Base) -> Self {
        Self {
            app_vk: vk,
            app_data_static: data,
        }
    }

    pub fn derive_value_base(&self) -> pallas::Point {
        let inputs = [self.app_vk.get_compressed(), self.app_data_static];
        poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&inputs)
    }
}

impl InputNoteInfo {
    pub fn new(
        note: Note,
        merkle_path: MerklePath,
        app_vp_verifying_info: Box<dyn ValidityPredicateVerifyingInfo>,
        app_vp_verifying_info_dynamic: Vec<Box<dyn ValidityPredicateVerifyingInfo>>,
    ) -> Self {
        let cm_node = Node::new(note.commitment().get_x());
        let root = merkle_path.root(cm_node).inner();
        let auth_path: [(pallas::Base, LR); TAIGA_COMMITMENT_TREE_DEPTH] =
            merkle_path.get_path().try_into().unwrap();
        Self {
            note,
            auth_path,
            root,
            app_vp_verifying_info,
            app_vp_verifying_info_dynamic,
        }
    }

    pub fn get_app_vp_verifying_info(&self) -> Box<dyn ValidityPredicateVerifyingInfo> {
        self.app_vp_verifying_info.clone()
    }

    pub fn get_app_vp_verifying_info_dynamic(
        &self,
    ) -> Vec<Box<dyn ValidityPredicateVerifyingInfo>> {
        self.app_vp_verifying_info_dynamic.clone()
    }
}

impl OutputNoteInfo {
    pub fn new(
        note: Note,
        app_vp_verifying_info: Box<dyn ValidityPredicateVerifyingInfo>,
        app_vp_verifying_info_dynamic: Vec<Box<dyn ValidityPredicateVerifyingInfo>>,
    ) -> Self {
        Self {
            note,
            app_vp_verifying_info,
            app_vp_verifying_info_dynamic,
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R, nf: Nullifier) -> Self {
        use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
        let note = Note::dummy_from_rho(&mut rng, nf);
        let app_vp_verifying_info = Box::new(TrivialValidityPredicateCircuit::dummy(&mut rng));
        let app_vp_verifying_info_dynamic = vec![];
        Self {
            note,
            app_vp_verifying_info,
            app_vp_verifying_info_dynamic,
        }
    }

    pub fn get_app_vp_verifying_info(&self) -> Box<dyn ValidityPredicateVerifyingInfo> {
        self.app_vp_verifying_info.clone()
    }

    pub fn get_app_vp_verifying_info_dynamic(
        &self,
    ) -> Vec<Box<dyn ValidityPredicateVerifyingInfo>> {
        self.app_vp_verifying_info_dynamic.clone()
    }
}
