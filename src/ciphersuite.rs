// SPDX-License-Identifier: MIT OR Apache-2.0

//! Defines the CipherSuite trait to specify the underlying primitives for VOPRF

use digest::block_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker, OutputSizeUser};
use hash2curve::{ExpandMsg, MapToCurve, OprfParameters};
use hybrid_array::typenum::{IsGreaterOrEqual, IsLessOrEqual, Prod, True, U2};

use crate::Group;

/// Configures the underlying primitives used in VOPRF
pub trait CipherSuite
where
    // `expand_message_xmd` requires the hash output to fit into one block and
    // to be at least twice the target security level of the group. See
    // <https://www.rfc-editor.org/rfc/rfc9380.html#section-5.3.1>.
    <Self::Hash as OutputSizeUser>::OutputSize:
        IsLessOrEqual<<Self::Hash as BlockSizeUser>::BlockSize, Output = True>,
    <Self::Hash as OutputSizeUser>::OutputSize:
        IsGreaterOrEqual<Prod<<Self::Group as Group>::SecurityLevel, U2>, Output = True>,
{
    /// The ciphersuite identifier as dictated by
    /// <https://www.rfc-editor.org/rfc/rfc9497>
    const ID: &'static [u8];

    /// A finite cyclic group along with a point representation that allows some
    /// customization on how to hash an input to a curve point. See [`Group`].
    type Group: Group;

    /// The main hash function to use (for HKDF computations and hashing
    /// transcripts).
    type Hash: BlockSizeUser + Default + FixedOutput + HashMarker;
}

impl<T> CipherSuite for T
where
    T: Group + OprfParameters,
    OprfHash<T>: BlockSizeUser + Default + FixedOutput + HashMarker,
    <OprfHash<T> as OutputSizeUser>::OutputSize:
        IsLessOrEqual<<OprfHash<T> as BlockSizeUser>::BlockSize, Output = True>,
    <OprfHash<T> as OutputSizeUser>::OutputSize:
        IsGreaterOrEqual<Prod<<T as Group>::SecurityLevel, U2>, Output = True>,
{
    const ID: &'static [u8] = <T as OprfParameters>::ID;

    type Group = T;

    type Hash = OprfHash<T>;
}

/// The hash function that [`OprfParameters`] selects for a curve.
type OprfHash<T> = <<T as hash2curve::GroupDigest>::ExpandMsg as ExpandMsg<
    <T as MapToCurve>::SecurityLevel,
>>::Hash;
