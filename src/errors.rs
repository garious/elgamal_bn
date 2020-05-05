#[cfg(feature = "std")]
use thiserror::Error;
use rustc_serialize::hex::FromHexError;
use bincode::rustc_serialize::DecodingError;
use bn::GroupError;

/// Represents an error in hex parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum ConversionError {
    /// This error occurs when a point to hex conversion fails
    #[cfg_attr(feature = "std", error("Failed to convert point to hexadecimal"))]
    InvalidHexConversion,
    /// The input contained a character not part of the hex format
    #[cfg_attr(feature = "std", error("Invalid hexadecimal character"))]
    InvalidHexCharacter,
    /// The input had an invalid length
    #[cfg_attr(feature = "std", error("Invalid hexadecimal length"))]
    InvalidHexLength,
    /// This error occurs when the length of a hex string is unexpected
    #[cfg_attr(feature = "std", error("Expected hex string of length 64"))]
    InvalidHexLengthPoint,
    /// This error occurs when a hex string is incorrect.
    #[cfg_attr(feature = "std", error("Expected a hex string pair in the form (0x..., 0x...)"))]
    IncorrectHexString,
    /// This error occurs when we expect a decimal string but receive hexadecimal
    #[cfg_attr(feature = "std", error("Expected decimal string, received hex"))]
    IncorrectDecString,
    /// This error occurs when we try to generate an Fq element from a string but it fails
    #[cfg_attr(feature = "std", error("Failed to convert decimal string to Fq element"))]
    ErrorIntegerFromString,
    /// This error occurs when we try to generate a point out of coordinates which do not
    /// correspond to a point in the curve
    #[cfg_attr(feature = "std", error("Coordinates given do not correspond to point in curve"))]
    PointNotInCurve,
    /// If the error stems from the reader that is being used
    /// during decoding, that error will be stored and returned here.
    #[cfg_attr(feature = "std", error("Error from the reader"))]
    IoError,
    /// If the bytes in the reader are not decodable because of an invalid
    /// encoding, this error will be returned.  This error is only possible
    /// if a stream is corrupted.  A stream produced from `encode` or `encode_into`
    /// should **never** produce an InvalidEncoding error.
    #[cfg_attr(feature = "std", error("Invalid encoding"))]
    InvalidEncoding,
    /// If decoding a message takes more than the provided size limit, this
    /// error is returned.
    #[cfg_attr(feature = "std", error("Decoding message takes more than the provided size limit"))]
    SizeLimit,
    /// This error happens when a none value is return when converting jacobian coordinates to an
    /// affine points
    #[cfg_attr(feature = "std", error("Affine conversion failed"))]
    AffineConversionFailure

}

/// Represents an error in proof creation, verification, or parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofError {
    /// This error occurs when a proof failed to verify.
    #[cfg_attr(feature = "std", error = "Proof verification failed.")]
    VerificationError,

    /// This error occurs when a proof fails to verify due to a conversion error
    #[cfg_attr(feature = "std", error = "Proof verification failed due to conversion error.")]
    ConversionVerificationError,
}

impl From<ConversionError> for ProofError {
    fn from (_e: ConversionError) -> ProofError {
        return ProofError::ConversionVerificationError
    }
}

impl From<FromHexError> for ConversionError {
    fn from(e: FromHexError) -> ConversionError {
        match e {
            FromHexError::InvalidHexCharacter(_, _) => ConversionError::InvalidHexLength,
            FromHexError::InvalidHexLength => ConversionError::InvalidHexLength,
        }
    }
}


impl From<DecodingError> for ConversionError {
    fn from(e: DecodingError) -> ConversionError {
        match e {
            DecodingError::IoError(_) => ConversionError::IoError,
            DecodingError::InvalidEncoding(_) => ConversionError::InvalidEncoding,
            DecodingError::SizeLimit => ConversionError::SizeLimit,
        }
    }
}

impl From<bn::GroupError> for ConversionError {
    fn from(e: GroupError) -> ConversionError {
        match e {
            GroupError::NotOnCurve => ConversionError::PointNotInCurve,
            GroupError::NotInSubgroup => ConversionError::PointNotInCurve,
        }
    }
}
