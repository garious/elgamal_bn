#![allow(non_snake_case)]
extern crate rand;

use bn::*;
use crate::errors::ProofError;

use rand::thread_rng;
use solana_sdk::hash::hashv;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::ciphertext::*;

/// The `PublicKey` struct represents an ElGamal public key.
#[derive(Copy, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct PublicKey(G1);

impl PublicKey {
    /// Encrypts a message in the Ristretto group. It has the additive homomorphic property,
    /// allowing addition (and subtraction) by another ciphertext and multiplication (and division)
    /// by scalars.
    ///
    /// #Example
    /// ```
    /// extern crate rand;
    /// use elgamal_bn::public::{PublicKey, };
    /// use elgamal_bn::private::{SecretKey, };
    /// use bn::{Fr, G1, Group};
    ///
    /// # fn main() {
    ///        let mut csprng = rand::thread_rng();
    ///        // Generate key pair
    ///        let sk = SecretKey::new(&mut csprng);
    ///        let pk = PublicKey::from(&sk);
    ///
    ///        // Generate random messages
    ///        let ptxt1 = G1::random(&mut csprng);
    ///        let ptxt2 = G1::random(&mut csprng);
    ///
    ///        // Encrypt messages
    ///        let ctxt1 = pk.encrypt(&ptxt1);
    ///        let ctxt2 = pk.encrypt(&ptxt2);
    ///
    ///        // Add ciphertexts and check that addition is maintained in the plaintexts
    ///        let encrypted_addition = ctxt1 + ctxt2;
    ///        let decrypted_addition = sk.decrypt(&encrypted_addition);
    ///
    ///        assert_eq!(ptxt1 + ptxt2, decrypted_addition);
    ///
    ///        // Multiply by scalar and check that multiplication is maintained in the plaintext
    ///        let scalar_mult = Fr::random(&mut csprng);
    ///        assert_eq!(sk.decrypt(&(ctxt1 * scalar_mult)), ptxt1 * scalar_mult);
    /// # }
    /// ```
    pub fn encrypt(self, message: &G1) -> Ciphertext {
        let rng = &mut thread_rng();
        let random: Fr = Fr::random(rng);

        let random_generator = G1::one() * random;
        let encrypted_plaintext = *message + self.0 * random;
        Ciphertext {
            pk: self,
            points: (random_generator, encrypted_plaintext),
        }
    }

    /// Get the public key point
    pub fn get_point(&self) -> G1 {
        self.0
    }

    /// Get the public key point as an Affine point
    pub fn get_point_affine(&self) -> AffineG1 {
        AffineG1::from_jacobian(self.0).unwrap()
    }

    /// This function is only defined for testing purposes for the
    /// `prove_correct_decryption_no_Merlin`. Verification should
    /// happen in `Solidity`.
    /// Example
    /// ```
    /// extern crate rand;
    /// use elgamal_bn::public::{PublicKey, };
    /// use elgamal_bn::private::{SecretKey, };
    /// use bn::{G1, Group};
    ///
    /// # fn main() {
    ///    let mut csprng = rand::thread_rng();
    ///    let sk = SecretKey::new(&mut csprng);
    ///    let pk = PublicKey::from(&sk);
    ///
    ///    let plaintext = G1::random(&mut csprng);
    ///    let ciphertext = pk.encrypt(&plaintext);
    ///
    ///    let decryption = sk.decrypt(&ciphertext);
    ///    let proof = sk.prove_correct_decryption_no_Merlin(&ciphertext, &decryption).unwrap();
    ///
    ///    assert!(pk.verify_correct_decryption_no_Merlin(proof, ciphertext, decryption).is_ok());
    /// # }
    /// ```
    pub fn verify_correct_decryption_no_Merlin(
        self,
        proof: ((G1, G1), Fr),
        ciphertext: Ciphertext,
        message: G1,
    ) -> Result<(), ProofError> {
        let ((announcement_base_G, announcement_base_ctxtp0), response) = proof;

        let challenge = compute_challenge(&message, &ciphertext, &announcement_base_G, &announcement_base_ctxtp0, &self);

        if !(G1::one() * response == announcement_base_G + self.get_point() * challenge
            && ciphertext.points.0 * response
                == announcement_base_ctxtp0 + (ciphertext.points.1 - message) * challenge) {
            return Err(ProofError::VerificationError);
        }
        Ok(())
    }
}

impl From<G1> for PublicKey {
    /// Given a secret key, compute its corresponding Public key
    fn from(point: G1) -> PublicKey {
        PublicKey(point)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0 == other.0
    }
}

/// Compute challenge for the proof of correct decryption. Used in the variation
/// that does not use Merlin.
pub(crate) fn compute_challenge(
    message: &G1,
    ciphertext: &Ciphertext,
    announcement_base_G: &G1,
    announcement_base_ctxtp0: &G1,
    pk: &PublicKey,
) -> Fr {
    let hash = hashv(&[
        &message.try_to_vec().unwrap(),
        &ciphertext.points.0.try_to_vec().unwrap(),
        &ciphertext.points.1.try_to_vec().unwrap(),
        &announcement_base_G.try_to_vec().unwrap(),
        &announcement_base_ctxtp0.try_to_vec().unwrap(),
        &G1::one().try_to_vec().unwrap(),
        &pk.get_point().try_to_vec().unwrap(),
    ]);
    Fr::from_slice(hash.as_ref()).unwrap()
}
