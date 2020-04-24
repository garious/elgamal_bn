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
    IncorrectHexLength
}