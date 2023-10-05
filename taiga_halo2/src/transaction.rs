use crate::binding_signature::{BindingSignature, BindingSigningKey, BindingVerificationKey};
use crate::constant::TRANSACTION_BINDING_HASH_PERSONALIZATION;
use crate::error::TransactionError;
use crate::executable::Executable;
use crate::merkle_tree::Anchor;
use crate::note::NoteCommitment;
use crate::nullifier::Nullifier;
use crate::shielded_ptx::ShieldedPartialTransaction;
use crate::transparent_ptx::{OutputResource, TransparentPartialTransaction};
use crate::value_commitment::ValueCommitment;
use blake2b_simd::Params as Blake2bParams;
use pasta_curves::{group::Group, pallas};
use rand::{CryptoRng, RngCore};

#[cfg(feature = "nif")]
use rustler::{atoms, types::atom, Decoder, Env, NifRecord, NifResult, NifStruct, Term};

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Transaction {
    // TODO: Other parameters to be added.
    shielded_ptx_bundle: ShieldedPartialTxBundle,
    transparent_ptx_bundle: TransparentPartialTxBundle,
    // binding signature to check balance
    signature: BindingSignature,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "nif", derive(NifRecord))]
#[cfg_attr(feature = "nif", tag = "bundle")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShieldedPartialTxBundle(Vec<ShieldedPartialTransaction>);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Transaction.Result")]
pub struct ShieldedResult {
    pub anchors: Vec<Anchor>,
    pub nullifiers: Vec<Nullifier>,
    pub output_cms: Vec<NoteCommitment>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransparentPartialTxBundle(Vec<TransparentPartialTransaction>);

// TODO: add other outputs if needed.
#[derive(Debug, Clone)]
pub struct TransparentResult {
    pub nullifiers: Vec<Nullifier>,
    pub outputs: Vec<OutputResource>,
}

impl Transaction {
    // Generate the transaction
    pub fn build<R: RngCore + CryptoRng>(
        rng: R,
        shielded_ptx_bundle: ShieldedPartialTxBundle,
        transparent_ptx_bundle: TransparentPartialTxBundle,
    ) -> Self {
        assert!(!(shielded_ptx_bundle.is_empty() && transparent_ptx_bundle.is_empty()));
        let shielded_sk = shielded_ptx_bundle.get_bindig_sig_r();
        let transparent_sk = transparent_ptx_bundle.get_bindig_sig_r();
        let binding_sk = BindingSigningKey::from(shielded_sk + transparent_sk);
        let sig_hash = Self::digest(&shielded_ptx_bundle, &transparent_ptx_bundle);
        let signature = binding_sk.sign(rng, &sig_hash);

        Self {
            shielded_ptx_bundle,
            transparent_ptx_bundle,
            signature,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn execute(&self) -> Result<(ShieldedResult, TransparentResult), TransactionError> {
        let shielded_result = self.shielded_ptx_bundle.execute()?;
        let transparent_result = self.transparent_ptx_bundle.execute()?;

        // check balance
        self.verify_binding_sig()?;

        Ok((shielded_result, transparent_result))
    }

    fn verify_binding_sig(&self) -> Result<(), TransactionError> {
        let binding_vk = self.get_binding_vk();
        let sig_hash = Self::digest(&self.shielded_ptx_bundle, &self.transparent_ptx_bundle);
        binding_vk
            .verify(&sig_hash, &self.signature)
            .map_err(|_| TransactionError::InvalidBindingSignature)
    }

    fn get_binding_vk(&self) -> BindingVerificationKey {
        let mut vk = pallas::Point::identity();
        vk = self
            .shielded_ptx_bundle
            .get_value_commitments()
            .iter()
            .fold(vk, |acc, cv| acc + cv.inner());

        vk = self
            .transparent_ptx_bundle
            .get_value_commitments()
            .iter()
            .fold(vk, |acc, cv| acc + cv.inner());

        BindingVerificationKey::from(vk)
    }

    fn digest(
        shielded_bundle: &ShieldedPartialTxBundle,
        transparent_bundle: &TransparentPartialTxBundle,
    ) -> [u8; 32] {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(TRANSACTION_BINDING_HASH_PERSONALIZATION)
            .to_state();
        shielded_bundle.get_nullifiers().iter().for_each(|nf| {
            h.update(&nf.to_bytes());
        });
        shielded_bundle.get_output_cms().iter().for_each(|cm| {
            h.update(&cm.to_bytes());
        });
        shielded_bundle
            .get_value_commitments()
            .iter()
            .for_each(|vc| {
                h.update(&vc.to_bytes());
            });
        shielded_bundle.get_anchors().iter().for_each(|anchor| {
            h.update(&anchor.to_bytes());
        });

        // TODO: the transparent digest may be not reasonable, fix it once the transparent execution is nailed down.
        transparent_bundle.get_nullifiers().iter().for_each(|nf| {
            h.update(&nf.to_bytes());
        });
        transparent_bundle.get_output_cms().iter().for_each(|cm| {
            h.update(&cm.to_bytes());
        });
        transparent_bundle
            .get_value_commitments()
            .iter()
            .for_each(|vc| {
                h.update(&vc.to_bytes());
            });
        transparent_bundle.get_anchors().iter().for_each(|anchor| {
            h.update(&anchor.to_bytes());
        });

        h.finalize().as_bytes().try_into().unwrap()
    }
}

#[cfg(feature = "nif")]
atoms! { transaction }

#[cfg(feature = "nif")]
impl rustler::Encoder for Transaction {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            transaction().encode(env),
            self.shielded_ptx_bundle.encode(env),
            borsh::to_vec(&self.transparent_ptx_bundle)
                .unwrap_or_default()
                .encode(env),
            borsh::to_vec(&self.signature)
                .unwrap_or_default()
                .encode(env),
        )
            .encode(env)
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for Transaction {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let (term, shielded_ptx_bundle, transparent_bytes, sig_bytes): (
            atom::Atom,
            ShieldedPartialTxBundle,
            Vec<u8>,
            Vec<u8>,
        ) = term.decode()?;
        if term == transaction() {
            let transparent_ptx_bundle =
                BorshDeserialize::deserialize(&mut transparent_bytes.as_slice())
                    .map_err(|_e| rustler::Error::Atom("Failure to decode"))?;
            let signature = BorshDeserialize::deserialize(&mut sig_bytes.as_slice())
                .map_err(|_e| rustler::Error::Atom("Failure to decode"))?;
            Ok(Transaction {
                shielded_ptx_bundle,
                signature,
                transparent_ptx_bundle,
            })
        } else {
            Err(rustler::Error::BadArg)
        }
    }
}

impl ShieldedPartialTxBundle {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get_bindig_sig_r(&self) -> pallas::Scalar {
        self.0.iter().fold(pallas::Scalar::zero(), |acc, ptx| {
            acc + ptx.get_binding_sig_r()
        })
    }

    pub fn build(partial_txs: Vec<ShieldedPartialTransaction>) -> Self {
        Self(partial_txs)
    }

    pub fn add_partial_tx(&mut self, ptx: ShieldedPartialTransaction) {
        self.0.push(ptx);
    }

    #[allow(clippy::type_complexity)]
    pub fn execute(&self) -> Result<ShieldedResult, TransactionError> {
        for partial_tx in self.0.iter() {
            partial_tx.execute()?;
        }

        // Return Nullifiers to check double-spent, NoteCommitments to store, anchors to check the root-existence
        Ok(ShieldedResult {
            nullifiers: self.get_nullifiers(),
            output_cms: self.get_output_cms(),
            anchors: self.get_anchors(),
        })
    }

    pub fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        self.0
            .iter()
            .flat_map(|ptx| ptx.get_value_commitments())
            .collect()
    }

    pub fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.0.iter().flat_map(|ptx| ptx.get_nullifiers()).collect()
    }

    pub fn get_output_cms(&self) -> Vec<NoteCommitment> {
        self.0.iter().flat_map(|ptx| ptx.get_output_cms()).collect()
    }

    pub fn get_anchors(&self) -> Vec<Anchor> {
        self.0.iter().flat_map(|ptx| ptx.get_anchors()).collect()
    }

    fn get_binding_vk(&self) -> BindingVerificationKey {
        let vk = self
            .get_value_commitments()
            .iter()
            .fold(pallas::Point::identity(), |acc, cv| acc + cv.inner());

        BindingVerificationKey::from(vk)
    }
}

impl TransparentPartialTxBundle {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn build(partial_txs: Vec<TransparentPartialTransaction>) -> Self {
        Self(partial_txs)
    }

    pub fn add_partial_tx(&mut self, ptx: TransparentPartialTransaction) {
        self.0.push(ptx);
    }

    pub fn execute(&self) -> Result<TransparentResult, TransactionError> {
        for partial_tx in self.0.iter() {
            partial_tx.execute()?;
        }

        Ok(TransparentResult {
            nullifiers: vec![],
            outputs: vec![],
        })
    }

    pub fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        // TODO: add the real value commitments
        vec![]
    }

    pub fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.0.iter().flat_map(|ptx| ptx.get_nullifiers()).collect()
    }

    pub fn get_output_cms(&self) -> Vec<NoteCommitment> {
        self.0.iter().flat_map(|ptx| ptx.get_output_cms()).collect()
    }

    pub fn get_anchors(&self) -> Vec<Anchor> {
        self.0.iter().flat_map(|ptx| ptx.get_anchors()).collect()
    }

    pub fn get_bindig_sig_r(&self) -> pallas::Scalar {
        // TODO: add the real r
        pallas::Scalar::zero()
    }
}

#[cfg(test)]
pub mod testing {
    use crate::shielded_ptx::testing::create_shielded_ptx;
    use crate::transaction::ShieldedPartialTxBundle;

    pub fn create_shielded_ptx_bundle(num: usize) -> ShieldedPartialTxBundle {
        let mut bundle = vec![];
        for _ in 0..num {
            let ptx = create_shielded_ptx();
            bundle.push(ptx);
        }
        ShieldedPartialTxBundle::build(bundle)
    }

    #[test]
    fn test_halo2_transaction() {
        use super::*;
        use rand::rngs::OsRng;

        let rng = OsRng;

        let shielded_ptx_bundle = create_shielded_ptx_bundle(2);
        // TODO: add transparent_ptx_bundle test
        let transparent_ptx_bundle = TransparentPartialTxBundle::default();
        let tx = Transaction::build(rng, shielded_ptx_bundle, transparent_ptx_bundle);
        let (_shielded_ret, _) = tx.execute().unwrap();

        #[cfg(feature = "borsh")]
        {
            let borsh = borsh::to_vec(&tx).unwrap();
            let de_tx: Transaction = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            let (de_shielded_ret, _) = de_tx.execute().unwrap();
            assert_eq!(_shielded_ret, de_shielded_ret);
        }
    }
}
