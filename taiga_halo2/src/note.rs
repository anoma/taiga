use crate::{
    application::Application,
    circuit::vp_circuit::ValidityPredicateInfo,
    constant::{BASE_BITS_NUM, NOTE_COMMIT_DOMAIN, TAIGA_COMMITMENT_TREE_DEPTH},
    merkle_tree::{MerklePath, Node},
    nullifier::Nullifier,
    utils::extract_p,
};
use bitvec::{array::BitArray, order::Lsb0};
use core::iter;
use ff::{Field, PrimeFieldBits};
use group::Group;
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
}

impl Default for NoteCommitment {
    fn default() -> NoteCommitment {
        NoteCommitment(pallas::Point::generator())
    }
}

/// A note
#[derive(Debug, Clone, Default)]
pub struct Note {
    pub application: Application,
    pub value: u64,
    /// old nullifier. Nonce which is a deterministically computed, unique nonce
    pub rho: Nullifier,
    /// computed from spent_note_nf and rcm by using a PRF
    pub psi: pallas::Base,
    pub rcm: pallas::Scalar,
    /// If the is_merkle_checked flag is true, the merkle path authorization(membership) of the spent note will be checked in ActionProof.
    pub is_merkle_checked: bool,
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
    pub application: Application,
    pub value: u64,
    pub is_merkle_checked: bool,
    app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
    app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
}

impl Note {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        application: Application,
        value: u64,
        rho: Nullifier,
        psi: pallas::Base,
        rcm: pallas::Scalar,
        is_merkle_checked: bool,
    ) -> Self {
        Self {
            application,
            value,
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
        let application = Application::dummy(&mut rng);
        let value: u64 = rng.gen();
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        Self {
            application,
            value,
            rho,
            psi,
            rcm,
            is_merkle_checked: true,
        }
    }

    // cm = SinsemillaCommit^rcm(user_address || app_vp || app_data || rho || psi || is_merkle_checked || value)
    pub fn commitment(&self) -> NoteCommitment {
        let user_address = self.application.get_user_address();
        let app_vp = self.application.get_vp();
        let ret = NOTE_COMMIT_DOMAIN
            .commit(
                iter::empty()
                    .chain(
                        user_address
                            .to_le_bits()
                            .iter()
                            .by_vals()
                            .take(BASE_BITS_NUM),
                    )
                    .chain(app_vp.to_le_bits().iter().by_vals().take(BASE_BITS_NUM))
                    .chain(
                        self.application
                            .get_vp_data()
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

    pub fn get_nf(&self) -> Nullifier {
        let nk = self.application.get_nk().unwrap();
        let cm = self.commitment();
        Nullifier::derive_native(&nk, &self.rho.inner(), &self.psi, &cm)
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
        application: Application,
        value: u64,
        is_merkle_checked: bool,
        app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
        app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
    ) -> Self {
        Self {
            application,
            value,
            is_merkle_checked,
            app_vp_proving_info,
            app_logic_vp_proving_info,
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        use crate::circuit::vp_examples::DummyValidityPredicateCircuit;
        let application = Application::dummy(&mut rng);
        let value: u64 = rng.gen();
        let app_vp_proving_info = Box::new(DummyValidityPredicateCircuit::dummy(&mut rng));
        let app_logic_vp_proving_info = vec![];
        Self {
            application,
            value,
            is_merkle_checked: true,
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
