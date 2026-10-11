// SPDX-License-Identifier: MIT OR Apache-2.0

use core::num::NonZeroU16;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::block_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use hybrid_array::typenum::{IsGreaterOrEqual, IsLessOrEqual, Prod, True, U16, U2, U32};
use hybrid_array::Array;
use rand_core::{TryCryptoRng, TryRng};
use subtle::ConstantTimeEq;

use super::Group;
use crate::{Error, InternalError, Result};

/// [`Group`] implementation for Ristretto255.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ristretto255;

#[cfg(feature = "ristretto255-ciphersuite")]
impl crate::CipherSuite for Ristretto255 {
    const ID: &'static [u8] = b"ristretto255-SHA512";

    type Group = Ristretto255;

    type Hash = sha2::Sha512;
}

impl Group for Ristretto255 {
    type Elem = RistrettoPoint;

    type ElemLen = U32;

    type Scalar = Scalar;

    type ScalarLen = U32;

    // The 128-bit target security level of
    // https://www.rfc-editor.org/rfc/rfc9380.html#appendix-B
    type SecurityLevel = U16;

    // Implements the `hash_to_ristretto255()` function from
    // https://www.rfc-editor.org/rfc/rfc9380.html#appendix-B
    fn hash_to_curve<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Elem, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLessOrEqual<H::BlockSize, Output = True>
            + IsGreaterOrEqual<Prod<Self::SecurityLevel, U2>, Output = True>,
    {
        let uniform_bytes = expand_message::<H>(input, dst)?;

        Ok(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    // Implements the `HashToScalar()` function from
    // https://www.rfc-editor.org/rfc/rfc9497#section-4.1
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLessOrEqual<H::BlockSize, Output = True>
            + IsGreaterOrEqual<Prod<Self::SecurityLevel, U2>, Output = True>,
    {
        let uniform_bytes = expand_message::<H>(input, dst)?;

        Ok(Scalar::from_bytes_mod_order_wide(&uniform_bytes))
    }

    fn base_elem() -> Self::Elem {
        RISTRETTO_BASEPOINT_POINT
    }

    fn identity_elem() -> Self::Elem {
        RistrettoPoint::identity()
    }

    // serialization of a group element
    fn serialize_elem(elem: Self::Elem) -> Array<u8, Self::ElemLen> {
        elem.compress().to_bytes().into()
    }

    fn deserialize_elem(element_bits: &[u8]) -> Result<Self::Elem> {
        CompressedRistretto::from_slice(element_bits)
            .map_err(|_| Error::Deserialization)?
            .decompress()
            .filter(|point| point != &RistrettoPoint::identity())
            .ok_or(Error::Deserialization)
    }

    fn random_scalar<R: TryRng + TryCryptoRng>(rng: &mut R) -> Result<Self::Scalar> {
        loop {
            let mut scalar_bytes = [0u8; 32];
            rng.try_fill_bytes(&mut scalar_bytes)
                .map_err(|_| Error::Rng)?;

            if let Ok(scalar) = Self::deserialize_scalar(&scalar_bytes) {
                break Ok(scalar);
            }
        }
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> subtle::Choice {
        scalar.ct_eq(&Scalar::ZERO)
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        Scalar::ZERO
    }

    fn serialize_scalar(scalar: Self::Scalar) -> Array<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> Result<Self::Scalar> {
        scalar_bits
            .try_into()
            .ok()
            .and_then(|bytes| Scalar::from_canonical_bytes(bytes).into())
            .filter(|scalar| scalar != &Scalar::ZERO)
            .ok_or(Error::Deserialization)
    }
}

/// Both `hash_to_ristretto255()` and `HashToScalar()` expand the input to 64
/// uniform bytes.
const UNIFORM_BYTES_LEN: NonZeroU16 = NonZeroU16::new(64).unwrap();

fn expand_message<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<[u8; 64], InternalError>
where
    H: BlockSizeUser + Default + FixedOutput + HashMarker,
    H::OutputSize: IsLessOrEqual<H::BlockSize, Output = True>
        + IsGreaterOrEqual<Prod<<Ristretto255 as Group>::SecurityLevel, U2>, Output = True>,
{
    let mut uniform_bytes = [0; 64];
    <ExpandMsgXmd<H> as ExpandMsg<<Ristretto255 as Group>::SecurityLevel>>::expand_message(
        input,
        dst,
        UNIFORM_BYTES_LEN,
    )
    .map_err(|_| InternalError::Input)?
    .fill_bytes(&mut uniform_bytes)
    .map_err(|_| InternalError::Input)?;
    Ok(uniform_bytes)
}
