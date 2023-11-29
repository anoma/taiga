/// A resource machine compliance proof is required to ensure that the provided transaction is well-formed.
/// This proof, among other checks, includes the check that the resource was created only once, was consumed
/// only once and strictly after it was created. Its commitment and nullifier must be derived correctly according
/// to the rules for commitment/nullifier derivation. It also requires explicit check of the presence of all
/// other required proofs

use crate::{
    circuit::compliance_circuit::ComplianceCircuit,
    constant::{PRF_EXPAND_INPUT_VP_CM_R, PRF_EXPAND_OUTPUT_VP_CM_R},
    delta_commitment::DeltaCommitment,
    merkle_tree::{Anchor, MerklePath},
    nullifier::Nullifier,
    resource::{RandomSeed, Resource, ResourceCommitment},
    vp_commitment::ValidityPredicateCommitment,
};
use pasta_curves::pallas;
use rand::RngCore;

#[cfg(feature = "nif")]
use rustler::NifStruct;

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// The public inputs of compliance proof.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Compliance.PublicInputs")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompliancePublicInputs {
    /// The root of the resource commitment Merkle tree.
    pub anchor: Anchor,
    /// The nullifier of input resource.
    pub nf: Nullifier,
    /// The commitment to the output resource.
    pub cm: ResourceCommitment,
    /// Resource delta is used to reason about total quantities of different kinds of resources.
    pub delta: DeltaCommitment,
    /// The commitment to input resource application(static) vp
    pub input_vp_commitment: ValidityPredicateCommitment,
    /// The commitment to output resource application(static) vp
    pub output_vp_commitment: ValidityPredicateCommitment,
}

/// The information to build CompliancePublicInputs and ComplianceCircuit.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct ComplianceInfo {
    input_resource: Resource,
    input_merkle_path: MerklePath,
    input_anchor: Anchor,
    output_resource: Resource,
    // rseed is to generate the randomness of the delta commitment and vp commitments
    rseed: RandomSeed,
}

impl CompliancePublicInputs {
    pub fn to_instance(&self) -> Vec<pallas::Base> {
        let input_vp_commitment = self.input_vp_commitment.to_public_inputs();
        let output_vp_commitment = self.output_vp_commitment.to_public_inputs();
        vec![
            self.nf.inner(),
            self.anchor.inner(),
            self.cm.inner(),
            self.delta.get_x(),
            self.delta.get_y(),
            input_vp_commitment[0],
            input_vp_commitment[1],
            output_vp_commitment[0],
            output_vp_commitment[1],
        ]
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for CompliancePublicInputs {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.anchor.to_bytes())?;
        writer.write_all(&self.nf.to_bytes())?;
        writer.write_all(&self.cm.to_bytes())?;
        writer.write_all(&self.delta.to_bytes())?;
        writer.write_all(&self.input_vp_commitment.to_bytes())?;
        writer.write_all(&self.output_vp_commitment.to_bytes())?;
        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for CompliancePublicInputs {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        use std::io;
        let anchor_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let anchor = Option::from(Anchor::from_bytes(anchor_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "anchor not in field"))?;
        let nf_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let nf = Option::from(Nullifier::from_bytes(nf_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "nf not in field"))?;
        let cm_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let cm = Option::from(ResourceCommitment::from_bytes(cm_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cm not in field"))?;
        let detla_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let delta = Option::from(DeltaCommitment::from_bytes(detla_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "delta not in field"))?;
        let input_vp_commitment_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let input_vp_commitment =
            ValidityPredicateCommitment::from_bytes(input_vp_commitment_bytes);
        let output_vp_commitment_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let output_vp_commitment =
            ValidityPredicateCommitment::from_bytes(output_vp_commitment_bytes);

        Ok(CompliancePublicInputs {
            anchor,
            nf,
            cm,
            delta,
            input_vp_commitment,
            output_vp_commitment,
        })
    }
}

impl ComplianceInfo {
    // The dummy input resource must provide a valid custom_anchor, but a random merkle path
    // The normal input resource only needs to provide a valid merkle path. The anchor will be calculated from the resource and path.
    // The nonce of output_resource will be set to the nullifier of input_resource
    pub fn new<R: RngCore>(
        input_resource: Resource,
        input_merkle_path: MerklePath,
        custom_anchor: Option<Anchor>,
        output_resource: &mut Resource,
        mut rng: R,
    ) -> Self {
        let input_anchor = match custom_anchor {
            Some(anchor) => anchor,
            None => input_resource.calculate_root(&input_merkle_path),
        };

        output_resource.set_nonce(&input_resource, &mut rng);

        Self {
            input_resource,
            input_merkle_path,
            input_anchor,
            output_resource: *output_resource,
            rseed: RandomSeed::random(&mut rng),
        }
    }

    // Get the randomness of delta commitment
    pub fn get_rcv(&self) -> pallas::Scalar {
        self.rseed.get_rcv()
    }

    // Get the randomness of input resource application vp commitment
    pub fn get_input_vp_com_r(&self) -> pallas::Base {
        self.rseed.get_vp_cm_r(PRF_EXPAND_INPUT_VP_CM_R)
    }

    // Get the randomness of output resource application vp commitment
    pub fn get_output_vp_com_r(&self) -> pallas::Base {
        self.rseed.get_vp_cm_r(PRF_EXPAND_OUTPUT_VP_CM_R)
    }

    // Only used in transparent scenario: the achor is untrusted, recalculate root when executing it transparently.
    pub fn calculate_root(&self) -> Anchor {
        self.input_resource.calculate_root(&self.input_merkle_path)
    }

    // Get delta commitment
    pub fn get_delta_commitment(&self, blind_r: &pallas::Scalar) -> DeltaCommitment {
        DeltaCommitment::commit(&self.input_resource, &self.output_resource, blind_r)
    }

    pub fn get_input_resource_nullifer(&self) -> Nullifier {
        self.input_resource.get_nf().unwrap()
    }

    pub fn get_output_resource_cm(&self) -> ResourceCommitment {
        self.output_resource.commitment()
    }

    pub fn build(&self) -> (CompliancePublicInputs, ComplianceCircuit) {
        let nf = self.get_input_resource_nullifer();
        assert_eq!(
            nf, self.output_resource.nonce,
            "The nf of input resource must be equal to the nonce of output resource"
        );

        let cm = self.get_output_resource_cm();

        let rcv = self.get_rcv();
        let delta = self.get_delta_commitment(&rcv);

        let input_vp_cm_r = self.get_input_vp_com_r();
        let input_vp_commitment =
            ValidityPredicateCommitment::commit(&self.input_resource.get_logic(), &input_vp_cm_r);

        let output_vp_cm_r = self.get_output_vp_com_r();
        let output_vp_commitment =
            ValidityPredicateCommitment::commit(&self.output_resource.get_logic(), &output_vp_cm_r);

        let compliance = CompliancePublicInputs {
            nf,
            cm,
            anchor: self.input_anchor,
            delta,
            input_vp_commitment,
            output_vp_commitment,
        };

        let compliance_circuit = ComplianceCircuit {
            input_resource: self.input_resource,
            merkle_path: self.input_merkle_path.get_path().try_into().unwrap(),
            output_resource: self.output_resource,
            rcv,
            input_vp_cm_r,
            output_vp_cm_r,
        };

        (compliance, compliance_circuit)
    }
}

#[cfg(test)]
pub mod tests {
    use super::ComplianceInfo;
    use crate::constant::TAIGA_COMMITMENT_TREE_DEPTH;
    use crate::merkle_tree::MerklePath;
    use crate::resource::tests::random_resource;
    use rand::RngCore;

    pub fn random_compliance_info<R: RngCore>(mut rng: R) -> ComplianceInfo {
        let input_resource = random_resource(&mut rng);
        let mut output_resource = random_resource(&mut rng);
        let input_merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        ComplianceInfo::new(
            input_resource,
            input_merkle_path,
            None,
            &mut output_resource,
            &mut rng,
        )
    }
}
