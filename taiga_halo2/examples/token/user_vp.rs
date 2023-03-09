use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{self, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas;

extern crate taiga_halo2;
use taiga_halo2::{
    circuit::{
        gadgets::schnorr_signature::SchnorrConfig,
        integrity::{OutputNoteVar, SpendNoteVar},
        note_circuit::NoteConfig,
        vp_circuit::{
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::Note,
    proof::Proof,
    vp_circuit_impl,
    vp_vk::ValidityPredicateVerifyingKey,
};

use rand::rngs::OsRng;

// Different tokens can use the same token application VP but different `app_data` to distinguish the type of token. We can encode “ETH”, “BTC” or other property of the token into `app_data` to make the application type unique.

#[derive(Clone, Debug, Default)]
pub struct UserVP {
    // public key
    pk: pallas::Point,
    // signature (r,s)
    r: pallas::Point,
    s: pallas::Scalar,
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
}

#[derive(Clone, Debug)]
pub struct UserVPConfig {
    note_config: NoteConfig,
    schnorr_config: SchnorrConfig,
}

impl ValidityPredicateConfig for UserVPConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_config.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_config = Self::configure_note(meta);
        let schnorr_config = SchnorrConfig::configure(meta);
        Self {
            note_config,
            schnorr_config,
        }
    }
}

impl UserVP {
    pub fn new(
        pk: pallas::Point,
        r: pallas::Point,
        s: pallas::Scalar,
        spend_notes: [Note; NUM_NOTE],
        output_notes: [Note; NUM_NOTE],
    ) -> Self {
        Self {
            pk,
            r,
            s,
            spend_notes,
            output_notes,
        }
    }
}

impl ValidityPredicateCircuit for UserVP {
    type VPConfig = UserVPConfig;

    fn custom_constraints(
        &self,
        config: Self::VPConfig,
        layouter: impl Layouter<pallas::Base>,
        _spend_note_variables: &[SpendNoteVar],
        _output_note_variables: &[OutputNoteVar],
    ) -> Result<(), plonk::Error> {
        config
            .schnorr_config
            .verify_signature(layouter, self.pk, self.r, self.s)
    }
}

impl ValidityPredicateInfo for UserVP {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        self.get_note_instances()
    }

    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        let pk = keygen_pk(params, vk.clone(), self).expect("keygen_pk should not fail");
        let instance = self.get_instances();
        let proof = Proof::create(&pk, &params, self.clone(), &[&instance], &mut rng).unwrap();
        VPVerifyingInfo {
            vk,
            proof,
            instance,
        }
    }

    fn get_vp_description(&self) -> ValidityPredicateVerifyingKey {
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        ValidityPredicateVerifyingKey::from_vk(vk)
    }
}

vp_circuit_impl!(UserVP);

mod tests {

    use group::Curve;
    use halo2_proofs::{arithmetic::CurveAffine, dev::MockProver};

    use rand::{rngs::OsRng, RngCore};

    use super::UserVP;

    use halo2_proofs::{
        plonk::{self},
        poly::commitment::Params,
    };
    use pasta_curves::pallas;
    use std::time::Instant;
    use taiga_halo2::{
        constant::{NOTE_COMMIT_DOMAIN, NUM_NOTE},
        proof::Proof,
        utils::{mod_r_p, poseidon_hash_n}, note::Note,
    };

    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    fn calculate_hash<T: Hash + ?Sized>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
    #[test]
    fn test_user_vp() {
        let mut rng = OsRng;
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        const K: u32 = 13;
        let generator = NOTE_COMMIT_DOMAIN.R();
        // Message hash: m
        let m = pallas::Base::from(calculate_hash(
            "Every day you play with the light of the universe. Subtle visitor",
        ));
        // Private key: sk
        let sk = pallas::Scalar::from(rng.next_u64());
        // Public key: P = sk*G
        let pk = generator * sk;
        let pk_coord = pk.to_affine().coordinates().unwrap();
        // Generate a random number: z
        let z = pallas::Scalar::from(rng.next_u64());
        // Calculate: R = z*G
        let r = generator * z;
        let r_coord = r.to_affine().coordinates().unwrap();
        // Calculate: s = z + Hash(r||P||m)*sk
        let h = mod_r_p(poseidon_hash_n::<8>([
            *r_coord.x(),
            *r_coord.y(),
            *pk_coord.x(),
            *pk_coord.y(),
            m,
            pallas::Base::zero(),
            pallas::Base::zero(),
            pallas::Base::zero(),
        ]));
        let s = z + h * sk;
        // Signature = (r, s)
        let circuit = UserVP {
            pk,
            r,
            s,
            spend_notes,
            output_notes,
        };

        let pub_instance_vec = vec![m];
        assert_eq!(
            MockProver::run(K, &circuit, vec![pub_instance_vec.clone()])
                .unwrap()
                .verify(),
            Ok(())
        );
        let prover = MockProver::run(K, &circuit, vec![pub_instance_vec]).unwrap();
        prover.assert_satisfied();

        let time = Instant::now();
        let params = Params::new(K);

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();
        println!(
            "key generation: \t{:?}ms",
            (Instant::now() - time).as_millis()
        );

        let time = Instant::now();
        let proof = Proof::create(&pk, &params, circuit, &[&[m]], &mut rng).unwrap();
        println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

        let time = Instant::now();
        assert!(proof.verify(&vk, &params, &[&[m]]).is_ok());
        println!(
            "verification: \t\t{:?}ms",
            (Instant::now() - time).as_millis()
        );
    }
}
