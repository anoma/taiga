use crate::{
    circuit::{
        vp_circuit::ValidityPredicate,
        vp_examples::{TrivialValidityPredicateCircuit, COMPRESSED_TRIVIAL_VP_VK},
    },
    constant::{
        NUM_RESOURCE, POSEIDON_TO_CURVE_INPUT_LEN, PRF_EXPAND_PERSONALIZATION, PRF_EXPAND_PSI,
        PRF_EXPAND_PUBLIC_INPUT_PADDING, PRF_EXPAND_RCM, PRF_EXPAND_VCM_R,
    },
    merkle_tree::{Anchor, MerklePath, Node},
    nullifier::{Nullifier, NullifierKeyContainer},
    shielded_ptx::ResourceVPVerifyingInfoSet,
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
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        let value = Option::from(pallas::Base::from_repr(repr)).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ResourceCommitment value not in field",
            )
        })?;
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
    /// app_data_dynamic is the data defined in application vp and will NOT be used to derive kind
    /// sub-vps and any other data can be encoded to the app_data_dynamic
    pub app_data_dynamic: pallas::Base,
    /// the quantity of the resource.
    pub quantity: u64,
    /// NullifierKeyContainer contains the nullifier_key or the nullifier_key commitment.
    pub nk_container: NullifierKeyContainer,
    /// old nullifier. Nonce which is a deterministically computed, unique nonce
    pub rho: Nullifier,
    /// psi is to derive the nullifier
    pub psi: pallas::Base,
    /// rcm is the trapdoor of the resource commitment
    pub rcm: pallas::Base,
    /// If the is_merkle_checked flag is true, the merkle path authorization(membership) of input resource will be checked in ActionProof.
    pub is_merkle_checked: bool,
}

/// The parameters in the ResourceKind are used to derive resource kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.ResourceKind")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceKind {
    /// logic is a hash of a predicate associated with the resource
    pub logic: pallas::Base,
    /// app_data_static is the encoded data that is defined in application vp
    pub app_data_static: pallas::Base,
}

#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct RandomSeed([u8; 32]);

/// ResourceValidityPredicates includes one application(static) VP and a few dynamic VPs.
#[derive(Clone)]
pub struct ResourceValidityPredicates {
    application_vp: Box<ValidityPredicate>,
    dynamic_vps: Vec<Box<ValidityPredicate>>,
}

impl Resource {
    #[allow(clippy::too_many_arguments)]
    pub fn new_input_resource(
        logic: pallas::Base,
        app_data_static: pallas::Base,
        app_data_dynamic: pallas::Base,
        quantity: u64,
        nk: pallas::Base,
        rho: Nullifier,
        is_merkle_checked: bool,
        rseed: RandomSeed,
    ) -> Self {
        let kind = ResourceKind::new(logic, app_data_static);
        Self {
            kind,
            app_data_dynamic,
            quantity,
            nk_container: NullifierKeyContainer::Key(nk),
            is_merkle_checked,
            psi: rseed.get_psi(&rho),
            rcm: rseed.get_rcm(&rho),
            rho,
        }
    }

    // The rho, psi, and rcm are not specified until the action is constructed.
    #[allow(clippy::too_many_arguments)]
    pub fn new_output_resource(
        logic: pallas::Base,
        app_data_static: pallas::Base,
        app_data_dynamic: pallas::Base,
        quantity: u64,
        nk_com: pallas::Base,
        is_merkle_checked: bool,
    ) -> Self {
        let kind = ResourceKind::new(logic, app_data_static);
        Self {
            kind,
            app_data_dynamic,
            quantity,
            nk_container: NullifierKeyContainer::Commitment(nk_com),
            is_merkle_checked,
            psi: pallas::Base::default(),
            rcm: pallas::Base::default(),
            rho: Nullifier::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_full(
        logic: pallas::Base,
        app_data_static: pallas::Base,
        app_data_dynamic: pallas::Base,
        quantity: u64,
        nk_container: NullifierKeyContainer,
        rho: Nullifier,
        is_merkle_checked: bool,
        psi: pallas::Base,
        rcm: pallas::Base,
    ) -> Self {
        let kind = ResourceKind::new(logic, app_data_static);
        Self {
            kind,
            app_data_dynamic,
            quantity,
            nk_container,
            is_merkle_checked,
            psi,
            rcm,
            rho,
        }
    }

    pub fn random_padding_resource<R: RngCore>(mut rng: R) -> Self {
        let logic = *COMPRESSED_TRIVIAL_VP_VK;
        let app_data_static = pallas::Base::random(&mut rng);
        let kind = ResourceKind::new(logic, app_data_static);
        let app_data_dynamic = pallas::Base::random(&mut rng);
        let rho = Nullifier::from(pallas::Base::random(&mut rng));
        let nk = NullifierKeyContainer::from_key(pallas::Base::random(&mut rng));
        let rseed = RandomSeed::random(&mut rng);
        Resource {
            kind,
            app_data_dynamic,
            quantity: 0,
            nk_container: nk,
            rho,
            psi: rseed.get_psi(&rho),
            rcm: rseed.get_rcm(&rho),
            is_merkle_checked: false,
        }
    }

    // resource_commitment = poseidon_hash(logic || app_data_static || app_data_dynamic || nk_commitment || rho || psi || is_merkle_checked || quantity || rcm)
    pub fn commitment(&self) -> ResourceCommitment {
        let compose_is_merkle_checked_quantity = if self.is_merkle_checked {
            pallas::Base::from_u128(1 << 64).square() + pallas::Base::from(self.quantity)
        } else {
            pallas::Base::from(self.quantity)
        };
        let ret = poseidon_hash_n([
            self.get_logic(),
            self.get_app_data_static(),
            self.app_data_dynamic,
            self.get_nk_commitment(),
            self.rho.inner(),
            self.psi,
            compose_is_merkle_checked_quantity,
            self.rcm,
        ]);
        ResourceCommitment(ret)
    }

    pub fn get_nf(&self) -> Option<Nullifier> {
        Nullifier::derive(
            &self.nk_container,
            &self.rho.inner(),
            &self.psi,
            &self.commitment(),
        )
    }

    pub fn get_nk(&self) -> Option<pallas::Base> {
        self.nk_container.get_nk()
    }

    pub fn get_nk_commitment(&self) -> pallas::Base {
        self.nk_container.get_commitment()
    }

    pub fn get_kind(&self) -> pallas::Point {
        self.kind.derive_kind()
    }

    pub fn get_logic(&self) -> pallas::Base {
        self.kind.logic
    }

    pub fn get_app_data_static(&self) -> pallas::Base {
        self.kind.app_data_static
    }

    pub fn get_psi(&self) -> pallas::Base {
        self.psi
    }

    pub fn get_rcm(&self) -> pallas::Base {
        self.rcm
    }

    pub fn calculate_root(&self, path: &MerklePath) -> Anchor {
        let cm_node = Node::from(self);
        path.root(cm_node)
    }

    pub fn set_rho<R: RngCore>(&mut self, input_resource: &Resource, mut rng: R) {
        let rseed = RandomSeed::random(&mut rng);

        self.rho = input_resource.get_nf().unwrap();
        self.psi = rseed.get_psi(&self.rho);
        self.rcm = rseed.get_rcm(&self.rho);
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for Resource {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        use byteorder::{LittleEndian, WriteBytesExt};
        // Write logic
        writer.write_all(&self.kind.logic.to_repr())?;
        // Write app_data_static
        writer.write_all(&self.kind.app_data_static.to_repr())?;
        // Write app_data_dynamic
        writer.write_all(&self.app_data_dynamic.to_repr())?;
        // Write resource quantity
        writer.write_u64::<LittleEndian>(self.quantity)?;
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
impl BorshDeserialize for Resource {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io;
        // Read logic
        let mut logic_bytes = [0u8; 32];
        reader.read_exact(&mut logic_bytes)?;
        let logic = Option::from(pallas::Base::from_repr(logic_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "logic not in field"))?;
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
        // Read resource quantity
        let quantity = reader.read_u64::<LittleEndian>()?;
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
        // Construct resource
        Ok(Resource::from_full(
            logic,
            app_data_static,
            app_data_dynamic,
            quantity,
            nk_container,
            rho,
            is_merkle_checked,
            psi,
            rcm,
        ))
    }
}

impl ResourceKind {
    pub fn new(vk: pallas::Base, data: pallas::Base) -> Self {
        Self {
            logic: vk,
            app_data_static: data,
        }
    }

    pub fn derive_kind(&self) -> pallas::Point {
        let inputs = [self.logic, self.app_data_static];
        poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&inputs)
    }
}

impl Hash for ResourceKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.logic.to_repr().as_ref().hash(state);
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

    pub fn get_vp_cm_r(&self, tag: u8) -> pallas::Base {
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

impl ResourceValidityPredicates {
    pub fn new(
        application_vp: Box<ValidityPredicate>,
        dynamic_vps: Vec<Box<ValidityPredicate>>,
    ) -> Self {
        Self {
            application_vp,
            dynamic_vps,
        }
    }

    // Generate vp proofs
    pub fn build(&self) -> ResourceVPVerifyingInfoSet {
        let app_vp_verifying_info = self.application_vp.get_verifying_info();

        let app_dynamic_vp_verifying_info = self
            .dynamic_vps
            .iter()
            .map(|verifying_info| verifying_info.get_verifying_info())
            .collect();

        ResourceVPVerifyingInfoSet::new(app_vp_verifying_info, app_dynamic_vp_verifying_info)
    }

    // Create an input padding resource vps
    pub fn create_input_padding_resource_vps(
        resource: &Resource,
        input_resources: [Resource; NUM_RESOURCE],
        output_resources: [Resource; NUM_RESOURCE],
    ) -> Self {
        let owned_resource_id = resource.get_nf().unwrap().inner();
        let application_vp = Box::new(TrivialValidityPredicateCircuit::new(
            owned_resource_id,
            input_resources,
            output_resources,
        ));
        Self {
            application_vp,
            dynamic_vps: vec![],
        }
    }

    // Create an output padding resource vps
    pub fn create_output_padding_resource_vps(
        resource: &Resource,
        input_resources: [Resource; NUM_RESOURCE],
        output_resources: [Resource; NUM_RESOURCE],
    ) -> Self {
        let owned_resource_id = resource.commitment().inner();
        let application_vp = Box::new(TrivialValidityPredicateCircuit::new(
            owned_resource_id,
            input_resources,
            output_resources,
        ));
        Self {
            application_vp,
            dynamic_vps: vec![],
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::{RandomSeed, Resource, ResourceKind};
    use crate::nullifier::tests::*;
    use halo2_proofs::arithmetic::Field;
    use pasta_curves::pallas;
    use rand::{Rng, RngCore};

    pub fn random_kind<R: RngCore>(mut rng: R) -> ResourceKind {
        let logic = pallas::Base::random(&mut rng);
        let app_data_static = pallas::Base::random(&mut rng);
        ResourceKind::new(logic, app_data_static)
    }

    pub fn random_resource<R: RngCore>(mut rng: R) -> Resource {
        let rho = random_nullifier(&mut rng);
        let rseed = RandomSeed::random(&mut rng);
        Resource {
            kind: random_kind(&mut rng),
            app_data_dynamic: pallas::Base::random(&mut rng),
            quantity: rng.gen(),
            nk_container: random_nullifier_key(&mut rng),
            is_merkle_checked: true,
            psi: rseed.get_psi(&rho),
            rcm: rseed.get_rcm(&rho),
            rho,
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