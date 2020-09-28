#![allow(non_snake_case)]
extern crate rand;

extern crate bincode;
extern crate rustc_serialize;

use bn::*;
use crate::errors::{ConversionError, ProofError};

use rand::thread_rng;
use sha3::{Digest, Keccak256};

use crate::ciphertext::*;
use bincode::{SizeLimit::Infinite, rustc_serialize::encode};


/// The `PublicKey` struct represents an ElGamal public key.
#[derive(Copy, Clone, Debug)]
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

        let message_affine = AffineG1::from_jacobian(message).ok_or(ConversionError::AffineConversionFailure)?;
        let ctx1_affine = AffineG1::from_jacobian(ciphertext.points.0).ok_or(ConversionError::AffineConversionFailure)?;
        let ctx2_affine = AffineG1::from_jacobian(ciphertext.points.1).ok_or(ConversionError::AffineConversionFailure)?;
        let announcement_g_affine = AffineG1::from_jacobian(announcement_base_G).ok_or(ConversionError::AffineConversionFailure)?;
        let announcement_ctxt0_affine = AffineG1::from_jacobian(announcement_base_ctxtp0).ok_or(ConversionError::AffineConversionFailure)?;
        let generator_affine = AffineG1::from_jacobian(G1::one()).ok_or(ConversionError::AffineConversionFailure)?;
        let pk_affine = AffineG1::from_jacobian(self.get_point()).ok_or(ConversionError::AffineConversionFailure)?;

        let hash = Keccak256::new()
            .chain(encode(&message_affine, Infinite).unwrap())
            .chain(encode(&ctx1_affine, Infinite).unwrap())
            .chain(encode(&ctx2_affine, Infinite).unwrap())
            .chain(encode(&announcement_g_affine, Infinite).unwrap())
            .chain(encode(&announcement_ctxt0_affine, Infinite).unwrap())
            .chain(encode(&generator_affine, Infinite).unwrap())
            .chain(encode(&pk_affine, Infinite).unwrap())
        ;

        let challenge = Fr::from_slice(&hash.result()[..]).unwrap();

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
