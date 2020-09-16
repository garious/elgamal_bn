extern crate sha3;
use bn::{G1, Group};

use rand::thread_rng;
use elgamal_bn::private::SecretKey;
use elgamal_bn::public::PublicKey;


fn main() {
    let mut csprng = thread_rng();
    let sk = SecretKey::new(&mut csprng);
    let pk = PublicKey::from(&sk);

    let plaintext = G1::random(&mut csprng);
    let ciphertext = pk.encrypt(&plaintext);
    let decryption = sk.decrypt(&ciphertext);
    let proof = sk.prove_correct_decryption_no_Merlin(&ciphertext, &decryption).unwrap();
    assert!(pk.verify_correct_decryption_no_Merlin(proof, ciphertext, plaintext).is_ok());
}
