use crate::{
    circuit::{
        resource_logic_circuit::ResourceLogic,
        resource_logic_examples::COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK,
    },
    constant::{
        POSEIDON_TO_CURVE_INPUT_LEN, PRF_EXPAND_PERSONALIZATION,
        PRF_EXPAND_PERSONALIZATION_TO_FIELD, PRF_EXPAND_PSI, PRF_EXPAND_PUBLIC_INPUT_PADDING,
        PRF_EXPAND_RCM, PRF_EXPAND_VCM_R,
    },
    merkle_tree::{Anchor, MerklePath, Node},
    nullifier::{Nullifier, NullifierKeyContainer},
    shielded_ptx::ResourceLogicVerifyingInfoSet,
    utils::{poseidon_hash_n, poseidon_to_curve},
};
use blake2b_simd::Params as Blake2bParams;
use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::RngCore;
use std::hash::{Hash, Hasher};
use subtle::CtOption;

#[cfg(feature = "nif")]
use rustler::{NifStruct, NifTuple};

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// A commitment to a resource.
#[derive(Copy, Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "nif", derive(NifTuple))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceCommitment(pallas::Base);

impl ResourceCommitment {
    pub fn inner(&self) -> pallas::Base {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(bytes).map(ResourceCommitment)
    }
}

impl From<pallas::Base> for ResourceCommitment {
    fn from(cm: pallas::Base) -> Self {
        ResourceCommitment(cm)
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for ResourceCommitment {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for ResourceCommitment {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let value = crate::utils::read_base_field(reader)?;
        Ok(Self(value))
    }
}

impl Hash for ResourceCommitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().as_ref().hash(state);
    }
}

/// A resource
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Resource")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Resource {
    pub kind: ResourceKind,
    /// value is the fungible data of the resource
    /// sub-resource_logics and any other data can be encoded to the value
    pub value: pallas::Base,
    /// the quantity of the resource.
    pub quantity: u64,
    /// NullifierKeyContainer contains the nullifier_key or the nullifier_key commitment.
    pub nk_container: NullifierKeyContainer,
    /// nonce guarantees the uniqueness of the resource computable fields
    pub nonce: Nullifier,
    /// If the is_ephemeral flag is false, the merkle path authorization(membership) of input resource will be checked in ComplianceProof.
    pub is_ephemeral: bool,
    /// randomness seed used to derive whatever randomness needed (e.g., the resource commitment randomness and nullifier derivation randomness)
    pub rseed: pallas::Base,
}

/// The parameters in the ResourceKind are used to derive resource kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.ResourceKind")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceKind {
    /// logic is a hash of a predicate associated with the resource
    pub logic: pallas::Base,
    /// label specifies the fungibility domain for the resource
    pub label: pallas::Base,
}

#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct RandomSeed([u8; 32]);

/// ResourceLogics consists of one application(static) resource logic and a few user(dynamic) resource logics.
#[derive(Clone)]
pub struct ResourceLogics {
    application_resource_logic: Box<ResourceLogic>,
    dynamic_resource_logics: Vec<Box<ResourceLogic>>,
}

impl Resource {
    #[allow(clippy::too_many_arguments)]
    pub fn new_input_resource(
        logic: pallas::Base,
        label: pallas::Base,
        value: pallas::Base,
        quantity: u64,
        nk: pallas::Base,
        nonce: Nullifier,
        is_ephemeral: bool,
        rseed: pallas::Base,
    ) -> Self {
        let kind = ResourceKind::new(logic, label);
        Self {
            kind,
            value,
            quantity,
            nk_container: NullifierKeyContainer::Key(nk),
            is_ephemeral,
            nonce,
            rseed,
        }
    }

    // The nonce, psi, and rcm are not specified until the compliance is constructed.
    #[allow(clippy::too_many_arguments)]
    pub fn new_output_resource(
        logic: pallas::Base,
        label: pallas::Base,
        value: pallas::Base,
        quantity: u64,
        npk: pallas::Base,
        is_ephemeral: bool,
        rseed: pallas::Base,
    ) -> Self {
        let kind = ResourceKind::new(logic, label);
        Self {
            kind,
            value,
            quantity,
            nk_container: NullifierKeyContainer::PublicKey(npk),
            is_ephemeral,
            rseed,
            nonce: Nullifier::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_full(
        logic: pallas::Base,
        label: pallas::Base,
        value: pallas::Base,
        quantity: u64,
        nk_container: NullifierKeyContainer,
        nonce: Nullifier,
        is_ephemeral: bool,
        rseed: pallas::Base,
    ) -> Self {
        let kind = ResourceKind::new(logic, label);
        Self {
            kind,
            value,
            quantity,
            nk_container,
            is_ephemeral,
            nonce,
            rseed,
        }
    }

    pub fn random_padding_resource<R: RngCore>(mut rng: R) -> Self {
        let logic = *COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK;
        let label = pallas::Base::random(&mut rng);
        let kind = ResourceKind::new(logic, label);
        let value = pallas::Base::random(&mut rng);
        let nonce = Nullifier::from(pallas::Base::random(&mut rng));
        let nk = NullifierKeyContainer::from_key(pallas::Base::random(&mut rng));
        let rseed = pallas::Base::random(&mut rng);
        Resource {
            kind,
            value,
            quantity: 0,
            nk_container: nk,
            nonce,
            rseed,
            is_ephemeral: true,
        }
    }

    // resource_commitment = poseidon_hash(logic || label || value || npk || nonce || psi || is_ephemeral || quantity || rcm)
    pub fn commitment(&self) -> ResourceCommitment {
        let compose_is_ephemeral_quantity = if self.is_ephemeral {
            pallas::Base::from_u128(1 << 64).square() + pallas::Base::from(self.quantity)
        } else {
            pallas::Base::from(self.quantity)
        };
        let ret = poseidon_hash_n([
            self.get_logic(),
            self.get_label(),
            self.value,
            self.get_npk(),
            self.nonce.inner(),
            self.get_psi(),
            compose_is_ephemeral_quantity,
            self.get_rcm(),
        ]);
        ResourceCommitment(ret)
    }

    pub fn get_nf(&self) -> Option<Nullifier> {
        Nullifier::derive(
            &self.nk_container,
            &self.nonce.inner(),
            &self.get_psi(),
            &self.commitment(),
        )
    }

    pub fn get_nk(&self) -> Option<pallas::Base> {
        self.nk_container.get_nk()
    }

    pub fn get_npk(&self) -> pallas::Base {
        self.nk_container.get_npk()
    }

    pub fn get_kind(&self) -> pallas::Point {
        self.kind.derive_kind()
    }

    pub fn get_logic(&self) -> pallas::Base {
        self.kind.logic
    }

    pub fn get_label(&self) -> pallas::Base {
        self.kind.label
    }

    // psi is the randomness used to derive the nullifier
    pub fn get_psi(&self) -> pallas::Base {
        poseidon_hash_n([
            *PRF_EXPAND_PERSONALIZATION_TO_FIELD,
            pallas::Base::from(PRF_EXPAND_PSI as u64),
            self.rseed,
            self.nonce.inner(),
        ])
    }

    // rcm is the randomness of resource commitment
    pub fn get_rcm(&self) -> pallas::Base {
        poseidon_hash_n([
            *PRF_EXPAND_PERSONALIZATION_TO_FIELD,
            pallas::Base::from(PRF_EXPAND_RCM as u64),
            self.rseed,
            self.nonce.inner(),
        ])
    }

    pub fn calculate_root(&self, path: &MerklePath) -> Anchor {
        let cm_node = Node::from(self);
        path.root(cm_node)
    }

    pub fn set_nonce(&mut self, input_resource: &Resource) {
        self.nonce = input_resource.get_nf().unwrap();
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for Resource {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        use byteorder::{LittleEndian, WriteBytesExt};
        // Write logic
        writer.write_all(&self.kind.logic.to_repr())?;
        // Write label
        writer.write_all(&self.kind.label.to_repr())?;
        // Write value
        writer.write_all(&self.value.to_repr())?;
        // Write resource quantity
        writer.write_u64::<LittleEndian>(self.quantity)?;
        // Write nk_container
        match self.nk_container {
            NullifierKeyContainer::PublicKey(nk) => {
                writer.write_u8(1)?;
                writer.write_all(&nk.to_repr())
            }
            NullifierKeyContainer::Key(nk) => {
                writer.write_u8(2)?;
                writer.write_all(&nk.to_repr())
            }
        }?;
        // Write nonce
        writer.write_all(&self.nonce.to_bytes())?;
        // Write is_ephemeral
        writer.write_u8(if self.is_ephemeral { 1 } else { 0 })?;
        // Write rseed
        writer.write_all(&self.rseed.to_repr())?;

        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for Resource {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        use crate::utils::read_base_field;
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io;
        // Read logic
        let logic = read_base_field(reader)?;
        // Read label
        let label = read_base_field(reader)?;
        // Read value
        let value = read_base_field(reader)?;
        // Read resource quantity
        let quantity = reader.read_u64::<LittleEndian>()?;
        // Read nk_container
        let nk_container_type = reader.read_u8()?;
        let nk = read_base_field(reader)?;
        let nk_container = if nk_container_type == 0x01 {
            NullifierKeyContainer::from_npk(nk)
        } else {
            NullifierKeyContainer::from_key(nk)
        };
        // Read nonce
        let mut nonce_bytes = [0u8; 32];
        reader.read_exact(&mut nonce_bytes)?;
        let nonce = Option::from(Nullifier::from_bytes(nonce_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "nonce not in field"))?;

        // Read is_ephemeral
        let mut is_ephemeral_byte = [0u8; 1];
        reader.read_exact(&mut is_ephemeral_byte)?;
        let is_ephemeral_byte = is_ephemeral_byte[0];
        let is_ephemeral = is_ephemeral_byte == 0x01;

        // Read rseed
        let rseed = read_base_field(reader)?;

        // Construct resource
        Ok(Resource::from_full(
            logic,
            label,
            value,
            quantity,
            nk_container,
            nonce,
            is_ephemeral,
            rseed,
        ))
    }
}

impl ResourceKind {
    pub fn new(vk: pallas::Base, data: pallas::Base) -> Self {
        Self {
            logic: vk,
            label: data,
        }
    }

    pub fn derive_kind(&self) -> pallas::Point {
        let inputs = [self.logic, self.label];
        poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&inputs)
    }
}

impl Hash for ResourceKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.logic.to_repr().as_ref().hash(state);
        self.label.to_repr().as_ref().hash(state);
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

    pub fn get_resource_logic_cm_r(&self, tag: u8) -> pallas::Base {
        let mut h = Blake2bParams::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state();
        h.update(&[tag]);
        h.update(&self.0);
        let bytes = *h.finalize().as_array();
        pallas::Base::from_uniform_bytes(&bytes)
    }
}

impl ResourceLogics {
    pub fn new(
        application_resource_logic: Box<ResourceLogic>,
        dynamic_resource_logics: Vec<Box<ResourceLogic>>,
    ) -> Self {
        Self {
            application_resource_logic,
            dynamic_resource_logics,
        }
    }

    // Generate resource logic proofs
    pub fn build(&self) -> ResourceLogicVerifyingInfoSet {
        let app_resource_logic_verifying_info =
            self.application_resource_logic.get_verifying_info();

        let app_dynamic_resource_logic_verifying_info = self
            .dynamic_resource_logics
            .iter()
            .map(|verifying_info| verifying_info.get_verifying_info())
            .collect();

        ResourceLogicVerifyingInfoSet::new(
            app_resource_logic_verifying_info,
            app_dynamic_resource_logic_verifying_info,
        )
    }

    // // Create resource logics for an input padding resource
    // pub fn create_input_padding_resource_resource_logics(
    //     resource: &Resource,
    //     input_resources: [Resource; NUM_RESOURCE],
    //     output_resources: [Resource; NUM_RESOURCE],
    // ) -> Self {
    //     let self_resource_id = resource.get_nf().unwrap().inner();
    //     let application_resource_logic = Box::new(TrivialResourceLogicCircuit::new(
    //         self_resource_id,
    //         input_resources,
    //         output_resources,
    //     ));
    //     Self {
    //         application_resource_logic,
    //         dynamic_resource_logics: vec![],
    //     }
    // }

    // // Create resource logics for an output padding resource
    // pub fn create_output_padding_resource_resource_logics(
    //     resource: &Resource,
    //     input_resources: [Resource; NUM_RESOURCE],
    //     output_resources: [Resource; NUM_RESOURCE],
    // ) -> Self {
    //     let self_resource_id = resource.commitment().inner();
    //     let application_resource_logic = Box::new(TrivialResourceLogicCircuit::new(
    //         self_resource_id,
    //         input_resources,
    //         output_resources,
    //     ));
    //     Self {
    //         application_resource_logic,
    //         dynamic_resource_logics: vec![],
    //     }
    // }
}

#[cfg(test)]
pub mod tests {
    use super::{Resource, ResourceKind};
    use crate::nullifier::tests::*;
    use halo2_proofs::arithmetic::Field;
    use pasta_curves::pallas;
    use rand::{Rng, RngCore};

    pub fn random_kind<R: RngCore>(mut rng: R) -> ResourceKind {
        let logic = pallas::Base::random(&mut rng);
        let label = pallas::Base::random(&mut rng);
        ResourceKind::new(logic, label)
    }

    pub fn random_resource<R: RngCore>(mut rng: R) -> Resource {
        let nonce = random_nullifier(&mut rng);
        let rseed = pallas::Base::random(&mut rng);
        Resource {
            kind: random_kind(&mut rng),
            value: pallas::Base::random(&mut rng),
            quantity: rng.gen(),
            nk_container: random_nullifier_key(&mut rng),
            is_ephemeral: false,
            nonce,
            rseed,
        }
    }

    #[cfg(feature = "borsh")]
    #[test]
    fn resource_borsh_serialization_test() {
        use borsh::BorshDeserialize;
        use rand::rngs::OsRng;

        use crate::resource::ResourceCommitment;
        let mut rng = OsRng;

        let input_resource = random_resource(&mut rng);
        {
            // BorshSerialize
            let borsh = borsh::to_vec(&input_resource).unwrap();
            // BorshDeserialize
            let de_resource: Resource = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            assert_eq!(input_resource, de_resource);
        }

        let mut output_resource = input_resource;
        {
            output_resource.nk_container = random_nullifier_key_commitment(&mut rng);
            // BorshSerialize
            let borsh = borsh::to_vec(&output_resource).unwrap();
            // BorshDeserialize
            let de_resource: Resource = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            assert_eq!(output_resource, de_resource);
        }

        let icm = input_resource.commitment();
        {
            // BorshSerialize
            let borsh = borsh::to_vec(&icm).unwrap();
            // BorshDeserialize
            let de_icm: ResourceCommitment =
                BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            assert_eq!(icm, de_icm);
        }

        let ocm = output_resource.commitment();
        {
            // BorshSerialize
            let borsh = borsh::to_vec(&ocm).unwrap();
            // BorshDeserialize
            let de_ocm: ResourceCommitment =
                BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            assert_eq!(ocm, de_ocm);
        }
    }
}
