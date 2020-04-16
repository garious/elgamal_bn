#![allow(non_snake_case)]
use rand::{thread_rng, Rng};

use bincode;
use bincode::rustc_serialize::encode;
use bincode::SizeLimit::Infinite;
use sha2::{Digest, Sha512};

use bn::{Fr, Group, G1};

use crate::ciphertext::*;
use crate::public::*;

/// Secret key is a scalar forming the public Key.
#[derive(Clone)]
pub struct SecretKey(Fr);

// todo: this is important
// /// Overwrite secret key material with null bytes.
// impl Drop for SecretKey {
//     fn drop(&mut self) {
//         self.0.clear();
//     }
// }

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl SecretKey {
    /// Create new SecretKey
    pub fn new<T: Rng>(csprng: &mut T) -> Self {
        let mut bytes = [0u8; 64];
        csprng.fill_bytes(&mut bytes);
        SecretKey(Fr::interpret(&bytes))
    }

    /// Get scalar value
    pub fn get_scalar(&self) -> Fr {
        self.0
    }

    /// Decrypt ciphertexts
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> G1 {
        let (point1, point2) = ciphertext.get_points();
        point2 - point1 * self.0
    }

    /// Prove correct decryption without depending on the zkp toolkit, which
    /// uses Merlin for Transcripts. The latter is hard to mimic in solidity
    /// smart contracts. To this end, we define this alternative proof of correct
    /// decryption which allows us to proceed with the verification in solidity.
    /// This function should only be used in the latter case. If the verification is
    /// performed in rust, `prove_correct_decryption` function should be used.
    pub fn prove_correct_decryption_no_Merlin(
        &self,
        ciphertext: &Ciphertext,
        message: &G1,
    ) -> ((G1, G1), Fr) {
        let mut rng = thread_rng();
        let pk = PublicKey::from(self);
        let announcement_random = Fr::random(&mut rng);
        let announcement_base_G = G1::one() * announcement_random;
        let announcement_base_ctxtp0 = ciphertext.points.0 * announcement_random;

        let hash = Sha512::new()
            .chain(encode(message, Infinite).unwrap())
            .chain(encode(&ciphertext.points.0, Infinite).unwrap())
            .chain(encode(&ciphertext.points.1, Infinite).unwrap())
            .chain(encode(&announcement_base_G, Infinite).unwrap())
            .chain(encode(&announcement_base_ctxtp0, Infinite).unwrap())
            .chain(encode(&G1::one(), Infinite).unwrap())
            .chain(encode(&pk.get_point(), Infinite).unwrap());

        let mut output = [0u8; 64];
        output.copy_from_slice(hash.result().as_slice());
        let challenge = Fr::interpret(&output);

        let response = announcement_random + challenge * self.get_scalar();
        ((announcement_base_G, announcement_base_ctxtp0), response)
    }
}

impl From<Fr> for SecretKey {
    fn from(secret: Fr) -> SecretKey {
        SecretKey(secret)
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Given a secret key, compute its corresponding Public key
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey::from(G1::one() * secret.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_decryption() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);

        let decryption = sk.decrypt(&ciphertext);

        assert!(plaintext == decryption)
    }
    #[test]
    fn prove_correct_decryption_no_Merlin() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);

        let decryption = sk.decrypt(&ciphertext);
        let proof = sk.prove_correct_decryption_no_Merlin(&ciphertext, &decryption);

        assert!(pk.verify_correct_decryption_no_Merlin(proof, ciphertext, decryption));
    }

    #[test]
    fn prove_false_decryption_no_Merlin() {
        let mut csprng = rand::thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);

        let fake_decryption = G1::random(&mut csprng);
        let proof = sk.prove_correct_decryption_no_Merlin(&ciphertext, &fake_decryption);

        assert!(!pk.verify_correct_decryption_no_Merlin(proof, ciphertext, fake_decryption));
    }
}
