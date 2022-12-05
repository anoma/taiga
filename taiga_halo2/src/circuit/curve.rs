use halo2_proofs::circuit::AssignedCell;
use pasta_curves::pallas;

pub mod iso_map;
pub mod map_to_curve;
pub mod to_affine;

type JacobianCoordinates = (
    AssignedCell<pallas::Base, pallas::Base>,
    AssignedCell<pallas::Base, pallas::Base>,
    AssignedCell<pallas::Base, pallas::Base>,
);
