use bn::{Fr, G1, AffineG1, Fq};
use core::ops::{Add, Mul, Sub};

use crate::public::*;
use crate::errors::ConversionError;

#[derive(Copy, Clone, Debug)]
pub struct Ciphertext {
    pub pk: PublicKey,
    pub points: (G1, G1),
}

type PointStr = (String, String);

impl Ciphertext {
    /// Get the points of the ciphertext
    pub fn get_points(self) -> (G1, G1) {
        (self.points.0, self.points.1)
    }

    /// Convert decimal string points to Ciphertext
    pub fn from_dec_string((point1, point2): (PointStr, PointStr), pk: PublicKey)
                           -> Result<Self, ConversionError> {

        let point_1_x = Fq::from_str(&point1.0);
        let point_1_y = Fq::from_str(&point1.1);
        let point_2_x = Fq::from_str(&point2.0);
        let point_2_y = Fq::from_str(&point2.1);

        let affine_point_1 = AffineG1::new(
            point_1_x.ok_or(ConversionError::ErrorIntegerFromString)?,
            point_1_y.ok_or(ConversionError::ErrorIntegerFromString)?
        )?;

        let affine_point_2 = AffineG1::new(
            point_2_x.ok_or(ConversionError::ErrorIntegerFromString)?,
            point_2_y.ok_or(ConversionError::ErrorIntegerFromString)?
        )?;

        Ok(Ciphertext{
            pk,
            points: (
                G1::from(affine_point_1),
                G1::from(affine_point_2)
            )
        })
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Ciphertext) -> bool {
        self.pk == other.pk &&
            self.points.0 == other.points.0 &&
            self.points.1 == other.points.1
    }
}

impl Add<Ciphertext> for Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: Ciphertext) -> Ciphertext {
        if self.pk != other.pk {
            panic!("Abort! Ciphertexts can only be added if public keys equal");
        }
        Ciphertext {
            pk: self.pk,
            points: (
                self.points.0 + other.points.0,
                self.points.1 + other.points.1,
            ),
        }
    }
}

impl Sub<Ciphertext> for Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: Ciphertext) -> Ciphertext {
        if self.pk != other.pk {
            panic!("Abort! Ciphertexts can only be subtracted if public keys equal");
        }
        Ciphertext {
            pk: self.pk,
            points: (
                self.points.0 - other.points.0,
                self.points.1 - other.points.1,
            ),
        }
    }
}

impl Add<Ciphertext> for G1 {
    type Output = Ciphertext;

    fn add(self, other: Ciphertext) -> Ciphertext {
        Ciphertext {
            pk: other.pk,
            points: (other.points.0, self + other.points.1),
        }
    }
}

impl Add<G1> for Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: G1) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0, self.points.1 + other),
        }
    }
}

impl Sub<Ciphertext> for G1 {
    type Output = Ciphertext;

    fn sub(self, other: Ciphertext) -> Ciphertext {
        Ciphertext {
            pk: other.pk,
            points: (-other.points.0, self - other.points.1),
        }
    }
}

impl Sub<G1> for Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: G1) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0, self.points.1 - other),
        }
    }
}

impl Mul<Fr> for Ciphertext {
    type Output = Ciphertext;

    fn mul(self, other: Fr) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0 * other, self.points.1 * other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bn::Group;
    use crate::private::SecretKey;
    use rand::thread_rng;

    #[test]
    fn test_homomorphic_addition() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt1 = G1::random(&mut csprng);
        let ptxt2 = G1::random(&mut csprng);

        let ctxt1 = pk.encrypt(&ptxt1);
        let ctxt2 = pk.encrypt(&ptxt2);

        let encrypted_addition = ctxt1 + ctxt2;
        let decrypted_addition = sk.decrypt(&encrypted_addition);

        let check = ptxt1 + ptxt2 == decrypted_addition;
        assert!(check);
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt1 = G1::random(&mut csprng);
        let ptxt2 = G1::random(&mut csprng);

        let ctxt1 = pk.encrypt(&ptxt1);
        let ctxt2 = pk.encrypt(&ptxt2);

        let encrypted_addition = ctxt1 - ctxt2;
        let decrypted_addition = sk.decrypt(&encrypted_addition);

        let check = ptxt1 - ptxt2 == decrypted_addition;
        assert!(check);
    }

    #[test]
    fn test_add_of_ciphertext_and_plaintext() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);
        let plaintext2 = G1::random(&mut csprng);

        assert!(sk.decrypt(&(plaintext2 + ciphertext)) == plaintext + plaintext2);
        assert!(sk.decrypt(&(ciphertext + plaintext2)) == plaintext + plaintext2);
    }

    #[test]
    fn test_sub_of_ciphertext_and_plaintext() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);
        let plaintext2 = G1::random(&mut csprng);

        assert!(sk.decrypt(&(plaintext2 - ciphertext)) == plaintext2 - plaintext);
        assert!(sk.decrypt(&(ciphertext - plaintext2)) == plaintext - plaintext2);
    }

    #[test]
    fn test_multiplication_by_scalar() {
        // generates public private pair
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let pltxt: G1 = G1::random(&mut csprng);
        let enc_pltxt = pk.encrypt(&pltxt);

        let mult_factor: Fr = Fr::random(&mut csprng);
        let mult_pltxt = pltxt * mult_factor;
        let mult_ctxt = enc_pltxt * mult_factor;
        let mult_dec_pltxt = sk.decrypt(&mult_ctxt);

        let check = mult_dec_pltxt == mult_pltxt;
        assert!(check);
    }

    #[test]
    fn test_from_int_conversion() {
        let sk = SecretKey::new(&mut thread_rng());
        let pk = PublicKey::from(&sk);

        // This should work, (1, 2) is in the curve.
        let ctxt_dec_1 = (("1".to_owned(), "2".to_owned()), ("1".to_owned(), "2".to_owned()));
        let ctxt_from_dec_1 = Ciphertext::from_dec_string(ctxt_dec_1, pk);
        assert!(ctxt_from_dec_1.is_ok());

        // This shouldn't work, (2345123541, 1235413465) is not in the curve
        let ctxt_dec_2 = (("2345123541".to_owned(), "1235413465".to_owned()), ("2345123541".to_owned(), "1235413465".to_owned()));
        let ctxt_from_dec_2 = Ciphertext::from_dec_string(ctxt_dec_2, pk);
        assert!(ctxt_from_dec_2.is_err());
    }
}
