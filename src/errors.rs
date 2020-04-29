#[cfg(feature = "std")]
use thiserror::Error;

/// Represents an error in hex parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum ConversionError {
    /// This error occurs when a hex string is incorrect.
    #[cfg_attr(feature = "std", error("Expected a hex string pair in the form (0x..., 0x...)"))]
    IncorrectHexString,
    // This error occurs when the length of a hex string is unexpected
    #[cfg_attr(feature = "std", error("Expected hex string of length 64"))]
    IncorrectHexLength,
    // This error occurs when we expect a decimal string but receive hexadecimal
    #[cfg_attr(feature = "std", error("Expected decimal string, received hex"))]
    IncorrectDecString,
    // This error occurs when we try to generate an Fq element from a string but it fails
    #[cfg_attr(feature = "std", error("Failed to convert decimal string to Fq element"))]
    ErrorIntegerFromString,
    // This error occurs when we try to generate a point out of coordinates which do not
    // correspond to a point in the curve
    #[cfg_attr(feature = "std", error("Coordinates given do not correspond to point in curve"))]
    PointNotInCurve,
}