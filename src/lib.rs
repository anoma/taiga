// Temporary for annoying warning(unused implementation).
#![allow(dead_code)]
#![allow(clippy::type_complexity)]
#![allow(clippy::large_enum_variant)]

pub mod action;
pub mod app;
pub mod circuit;
pub mod constant;
pub mod doc_examples;
pub mod el_gamal;
pub mod error;
pub mod merkle_tree;
pub mod note;
pub mod nullifier;
pub mod poseidon;
pub mod transaction;
pub mod user;
pub mod utils;
pub mod vp_description;

// #[cfg(test)]
// pub mod tests;

// halo2 mod
pub mod halo2;
