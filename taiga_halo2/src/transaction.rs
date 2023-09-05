use crate::binding_signature::{BindingSignature, BindingSigningKey, BindingVerificationKey};
use crate::constant::TRANSACTION_BINDING_HASH_PERSONALIZATION;
use crate::error::TransactionError;
use crate::executable::Executable;
use crate::nullifier::Nullifier;
use crate::shielded_ptx::ShieldedPartialTransaction;
use crate::transparent_ptx::{OutputResource, TransparentPartialTransaction};
use crate::value_commitment::ValueCommitment;
use blake2b_simd::Params as Blake2bParams;
use pasta_curves::{
    group::{ff::PrimeField, Group},
    pallas,
};
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
    shielded_ptx_bundle: Option<ShieldedPartialTxBundle>,
    transparent_ptx_bundle: Option<TransparentPartialTxBundle>,
    // binding signature to check balance
    signature: InProgressBindingSignature,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InProgressBindingSignature {
    Authorized(BindingSignature),
    Unauthorized(BindingSigningKey),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "nif", derive(NifRecord))]
#[cfg_attr(feature = "nif", tag = "bundle")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShieldedPartialTxBundle {
    partial_txs: Vec<ShieldedPartialTransaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Transaction.Result")]
pub struct ShieldedResult {
    anchors: Vec<pallas::Base>,
    nullifiers: Vec<Nullifier>,
    output_cms: Vec<pallas::Base>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransparentPartialTxBundle {
    partial_txs: Vec<TransparentPartialTransaction>,
}

// TODO: add other outputs if needed.
#[derive(Debug, Clone)]
pub struct TransparentResult {
    pub nullifiers: Vec<Nullifier>,
    pub outputs: Vec<OutputResource>,
}

impl Transaction {
    // Init the transaction with shielded_ptx_bundle, transparent_ptx_bundle and the key of BindingSignature
    pub fn init(
        shielded_ptx_bundle: Option<ShieldedPartialTxBundle>,
        transparent_ptx_bundle: Option<TransparentPartialTxBundle>,
        // random from value commitment
        rcv_vec: Vec<pallas::Scalar>,
    ) -> Self {
        assert!(shielded_ptx_bundle.is_some() || transparent_ptx_bundle.is_some());
        assert!(!rcv_vec.is_empty());
        let sk = rcv_vec
            .iter()
            .fold(pallas::Scalar::zero(), |acc, rcv| acc + rcv);
        let signature = InProgressBindingSignature::Unauthorized(BindingSigningKey::from(sk));
        Self {
            shielded_ptx_bundle,
            transparent_ptx_bundle,
            signature,
        }
    }

    // Finalize the transaction and complete the Binding Signature.
    pub fn finalize<R: RngCore + CryptoRng>(&mut self, rng: R) {
        if let InProgressBindingSignature::Unauthorized(sk) = &self.signature {
            let vk = self.get_binding_vk();
            assert_eq!(vk, sk.get_vk(), "The notes value is unbalanced");
            let sig_hash = self.digest();
            let signature = sk.sign(rng, &sig_hash);
            self.signature = InProgressBindingSignature::Authorized(signature);
        }
    }

    // Init and finalize the transaction
    pub fn build<R: RngCore + CryptoRng>(
        rng: R,
        shielded_ptx_bundle: Option<ShieldedPartialTxBundle>,
        transparent_ptx_bundle: Option<TransparentPartialTxBundle>,
        rcv_vec: Vec<pallas::Scalar>,
    ) -> Self {
        let mut tx = Self::init(shielded_ptx_bundle, transparent_ptx_bundle, rcv_vec);
        tx.finalize(rng);
        tx
    }

    pub fn transparent_bundle(&self) -> Option<&TransparentPartialTxBundle> {
        self.transparent_ptx_bundle.as_ref()
    }

    pub fn shielded_bundle(&self) -> Option<&ShieldedPartialTxBundle> {
        self.shielded_ptx_bundle.as_ref()
    }

    #[allow(clippy::type_complexity)]
    pub fn execute(
        &self,
    ) -> Result<(Option<ShieldedResult>, Option<TransparentResult>), TransactionError> {
        let shielded_result = match self.shielded_bundle() {
            Some(bundle) => Some(bundle.execute()?),
            None => None,
        };

        let transparent_result = match self.transparent_bundle() {
            Some(bundle) => Some(bundle.execute()?),
            None => None,
        };

        // check balance
        self.verify_binding_sig()?;

        Ok((shielded_result, transparent_result))
    }

    fn verify_binding_sig(&self) -> Result<(), TransactionError> {
        let binding_vk = self.get_binding_vk();
        let sig_hash = self.digest();
        if let InProgressBindingSignature::Authorized(sig) = &self.signature {
            binding_vk
                .verify(&sig_hash, sig)
                .map_err(|_| TransactionError::InvalidBindingSignature)?;
        } else {
            return Err(TransactionError::MissingBindingSignatures);
        }

        Ok(())
    }

    fn get_binding_vk(&self) -> BindingVerificationKey {
        let mut vk = pallas::Point::identity();
        if let Some(bundle) = self.shielded_bundle() {
            vk = bundle
                .get_value_commitments()
                .iter()
                .fold(vk, |acc, cv| acc + cv.inner());
        }

        if let Some(bundle) = self.transparent_bundle() {
            vk = bundle
                .get_value_commitments()
                .iter()
                .fold(vk, |acc, cv| acc + cv.inner());
        }

        BindingVerificationKey::from(vk)
    }

    fn digest(&self) -> [u8; 32] {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(TRANSACTION_BINDING_HASH_PERSONALIZATION)
            .to_state();
        if let Some(bundle) = self.shielded_bundle() {
            bundle.get_nullifiers().iter().for_each(|nf| {
                h.update(&nf.to_bytes());
            });
            bundle.get_output_cms().iter().for_each(|cm_x| {
                h.update(&cm_x.to_repr());
            });
            bundle.get_value_commitments().iter().for_each(|vc| {
                h.update(&vc.to_bytes());
            });
            bundle.get_anchors().iter().for_each(|anchor| {
                h.update(&anchor.to_repr());
            });
        }

        // TODO: the transparent digest may be not reasonable, fix it once the transparent execution is nailed down.
        if let Some(bundle) = self.transparent_bundle() {
            bundle.get_nullifiers().iter().for_each(|nf| {
                h.update(&nf.to_bytes());
            });
            bundle.get_output_cms().iter().for_each(|cm| {
                h.update(&cm.to_repr());
            });
            bundle.get_value_commitments().iter().for_each(|vc| {
                h.update(&vc.to_bytes());
            });
            bundle.get_anchors().iter().for_each(|anchor| {
                h.update(&anchor.to_repr());
            });
        }

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
                .unwrap_or(vec![])
                .encode(env),
            borsh::to_vec(&self.signature).unwrap_or(vec![]).encode(env),
        )
            .encode(env)
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for Transaction {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let (term, shielded_ptx_bundle, transparent_bytes, sig_bytes): (
            atom::Atom,
            Option<ShieldedPartialTxBundle>,
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
    pub fn new() -> Self {
        Self {
            partial_txs: vec![],
        }
    }

    pub fn build(partial_txs: Vec<ShieldedPartialTransaction>) -> Self {
        Self { partial_txs }
    }

    pub fn add_partial_tx(&mut self, ptx: ShieldedPartialTransaction) {
        self.partial_txs.push(ptx);
    }

    #[allow(clippy::type_complexity)]
    pub fn execute(&self) -> Result<ShieldedResult, TransactionError> {
        for partial_tx in self.partial_txs.iter() {
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
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_value_commitments())
            .collect()
    }

    pub fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_nullifiers())
            .collect()
    }

    pub fn get_output_cms(&self) -> Vec<pallas::Base> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_output_cms())
            .collect()
    }

    pub fn get_anchors(&self) -> Vec<pallas::Base> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_anchors())
            .collect()
    }

    fn get_binding_vk(&self) -> BindingVerificationKey {
        let vk = self
            .get_value_commitments()
            .iter()
            .fold(pallas::Point::identity(), |acc, cv| acc + cv.inner());

        BindingVerificationKey::from(vk)
    }
}

impl Default for ShieldedPartialTxBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl TransparentPartialTxBundle {
    pub fn build(partial_txs: Vec<TransparentPartialTransaction>) -> Self {
        Self { partial_txs }
    }

    pub fn add_partial_tx(&mut self, ptx: TransparentPartialTransaction) {
        self.partial_txs.push(ptx);
    }

    pub fn execute(&self) -> Result<TransparentResult, TransactionError> {
        for partial_tx in self.partial_txs.iter() {
            partial_tx.execute()?;
        }

        Ok(TransparentResult {
            nullifiers: vec![],
            outputs: vec![],
        })
    }

    pub fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        unimplemented!()
    }

    pub fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_nullifiers())
            .collect()
    }

    pub fn get_output_cms(&self) -> Vec<pallas::Base> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_output_cms())
            .collect()
    }

    pub fn get_anchors(&self) -> Vec<pallas::Base> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_anchors())
            .collect()
    }
}

#[cfg(test)]
pub mod testing {
    use crate::shielded_ptx::testing::create_shielded_ptx;
    use crate::transaction::ShieldedPartialTxBundle;
    use pasta_curves::pallas;

    pub fn create_shielded_ptx_bundle(
        num: usize,
    ) -> (ShieldedPartialTxBundle, Vec<pallas::Scalar>) {
        let mut bundle = ShieldedPartialTxBundle::new();
        let mut r_vec = vec![];
        for _ in 0..num {
            let (ptx, r) = create_shielded_ptx();
            bundle.add_partial_tx(ptx);
            r_vec.push(r);
        }
        (bundle, r_vec)
    }

    #[test]
    fn test_halo2_transaction() {
        use super::*;
        use rand::rngs::OsRng;

        let rng = OsRng;

        let (shielded_ptx_bundle, r_vec) = create_shielded_ptx_bundle(2);
        // TODO: add transparent_ptx_bundle test
        let transparent_ptx_bundle = None;
        let tx = Transaction::build(
            rng,
            Some(shielded_ptx_bundle),
            transparent_ptx_bundle,
            r_vec,
        );
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
