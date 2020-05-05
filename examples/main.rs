extern crate sha3;
extern crate rustc_hex;
use bn::{G1, Group, };
use elgamal_bn::public::{get_scalar_as_hex_str, get_point_as_hex_str, };

use rand::thread_rng;
use elgamal_bn::private::SecretKey;
use elgamal_bn::public::PublicKey;


fn main() {
    let mut csprng = thread_rng();
    let sk = SecretKey::new(&mut csprng);
    let pk = PublicKey::from(&sk);

    println!("Public Key hexadecimal: {:?}", pk.get_point_hex_string().unwrap());

    let plaintext = G1::random(&mut csprng);
    println!("Plaintext hexadecimal: {:?}", get_point_as_hex_str(plaintext).unwrap());

    let ciphertext = pk.encrypt(&plaintext);
    println!("Ciphertext hexadecimal: {:?}", ciphertext.get_points_hex_string());

    let decryption = sk.decrypt(&ciphertext);
    let proof = sk.prove_correct_decryption_no_Merlin(&ciphertext, &decryption).unwrap();
    println!("Generator times response: {:?}", get_point_as_hex_str(G1::one() * proof.1));
    println!("Announcement G: {:?}", get_point_as_hex_str((proof.0).0));
    println!("Announcement Ctxt: {:?}", get_point_as_hex_str((proof.0).1));
    println!("Response: {:?}", get_scalar_as_hex_str(proof.1));

    assert!(pk.verify_correct_decryption_no_Merlin(proof, ciphertext, plaintext).is_ok());
}