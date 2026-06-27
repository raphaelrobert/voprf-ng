// SPDX-License-Identifier: MIT OR Apache-2.0

//! Errors which are produced during an execution of the protocol

/// [`Result`](core::result::Result) shorthand that uses [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Clone, Copy, Debug, displaydoc::Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// Size of info is longer then [`u16::MAX`].
    Info,
    /// Size of input is empty or longer then [`u16::MAX`].
    Input,
    /// Size of info and seed together are longer then `u16::MAX - 3`.
    DeriveKeyPair,
    /// Failure to deserialize bytes
    Deserialization,
    /// Batched items are more then [`u16::MAX`] or length don't match.
    Batch,
    /// In verifiable mode, occurs when the proof failed to verify
    ProofVerification,
    /// The protocol has failed and can't be completed.
    Protocol,
    /// Random number generator failure.
    Rng,
}

/// Only used to implement [`Group`](crate::Group).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InternalError {
    /// Size of input is empty or longer then [`u16::MAX`].
    Input,
    /// `input` is longer then [`u16::MAX`].
    I2osp,
}

impl core::error::Error for Error {}
