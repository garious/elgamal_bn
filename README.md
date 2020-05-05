# ElGamal crate using BN-128 curve

This crate implements basic ElGamal functionality over BN-128 curve. 
The motivation of the choice of the curve is to be able to exploit 
the homomorphic property and verify proofs of decryption on-chain. 

For a more complete library based on the `ristretto` group over
`curve25519`, see the [elgamal_ristretto](https://crates.io/crates/elgamal_ristretto)

## Disclaimer
This is experimental code meant for research projects only. Please do not
use this code in production.
