// SPDX-License-Identifier: MIT OR Apache-2.0

use core::ops::Add;

use digest::core_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest};
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{
    AffinePoint, Field, FieldBytes, FieldBytesSize, Group as _, ProjectivePoint, PublicKey, Scalar,
    SecretKey,
};
use generic_array::typenum::{IsLess, IsLessOrEqual, Sum, U256};
use generic_array::{ArrayLength, GenericArray};
use rand_core::{TryCryptoRng, TryRng};

use super::Group;
use crate::{Error, InternalError, Result};

type ElemLen<C> = <ScalarLen<C> as ModulusSize>::CompressedPointSize;
type ScalarLen<C> = FieldBytesSize<C>;

impl<C> Group for C
where
    C: GroupDigest,
    ProjectivePoint<Self>: CofactorGroup + ToEncodedPoint<Self>,
    ScalarLen<Self>: ModulusSize,
    ScalarLen<Self>: ArrayLength,
    AffinePoint<Self>: FromEncodedPoint<Self> + ToEncodedPoint<Self>,
    Scalar<Self>: FromOkm,
    // `VoprfClientLen`, `PoprfClientLen`, `VoprfServerLen`, `PoprfServerLen`
    ScalarLen<Self>: Add<ElemLen<Self>>,
    Sum<ScalarLen<Self>, ElemLen<Self>>: ArrayLength,
    // `ProofLen`
    ScalarLen<Self>: Add<ScalarLen<Self>>,
    Sum<ScalarLen<Self>, ScalarLen<Self>>: ArrayLength,
    ElemLen<Self>: ArrayLength,
{
    type Elem = ProjectivePoint<Self>;

    type ElemLen = ElemLen<Self>;

    type Scalar = Scalar<Self>;

    type ScalarLen = ScalarLen<Self>;

    // Implements the `hash_to_curve()` function from
    // https://www.rfc-editor.org/rfc/rfc9380.html#section-3
    fn hash_to_curve<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Elem, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        Self::hash_from_bytes::<ExpandMsgXmd<H>>(input, dst).map_err(|_| InternalError::Input)
    }

    // Implements the `HashToScalar()` function
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        <Self as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<H>>(input, dst)
            .map_err(|_| InternalError::Input)
    }

    fn base_elem() -> Self::Elem {
        ProjectivePoint::<Self>::generator()
    }

    fn identity_elem() -> Self::Elem {
        ProjectivePoint::<Self>::identity()
    }

    fn serialize_elem(elem: Self::Elem) -> GenericArray<u8, Self::ElemLen> {
        let bytes = elem.to_encoded_point(true);
        let bytes = bytes.as_bytes();
        let mut result = GenericArray::default();
        result[..bytes.len()].copy_from_slice(bytes);
        result
    }

    fn deserialize_elem(element_bits: &[u8]) -> Result<Self::Elem> {
        PublicKey::<Self>::from_sec1_bytes(element_bits)
            .map(|public_key| public_key.to_projective())
            .map_err(|_| Error::Deserialization)
    }

    fn random_scalar<R: TryRng + TryCryptoRng>(rng: &mut R) -> Result<Self::Scalar> {
        let mut compat = CompatRng { rng, failed: false };
        let scalar = *SecretKey::<Self>::random(&mut compat).to_nonzero_scalar();
        // `SecretKey::random` drives an infallible RNG, so a failure of the
        // wrapped fallible RNG is recorded in `failed` instead of panicking. The
        // sentinel scalar produced on that path is discarded here.
        if compat.failed {
            return Err(Error::Rng);
        }
        Ok(scalar)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        Option::from(scalar.invert()).unwrap()
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> subtle::Choice {
        scalar.is_zero()
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        Scalar::<Self>::ZERO
    }

    fn serialize_scalar(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        let bytes: FieldBytes<Self> = scalar.into();
        let mut result = GenericArray::<u8, Self::ScalarLen>::default();
        result.as_mut_slice().copy_from_slice(bytes.as_ref());
        result
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> Result<Self::Scalar> {
        SecretKey::<Self>::from_slice(scalar_bits)
            .map(|secret_key| *secret_key.to_nonzero_scalar())
            .map_err(|_| Error::Deserialization)
    }
}

/// Adapter allowing `rand_core 0.10` RNGs to satisfy the `elliptic_curve` 0.13
/// requirement for `rand_core 0.6` traits.
///
/// `elliptic_curve` 0.13 drives key generation through the infallible
/// `rand_core 0.6` `RngCore` trait, but this crate accepts the fallible
/// `TryRng`. Rather than panicking when the wrapped RNG fails, we record the
/// failure in `failed` and emit a valid sentinel value so the infallible caller
/// terminates promptly. The caller then maps `failed` to
/// [`Error::Rng`] and discards the sentinel-derived scalar.
///
/// TODO #150: Remove this adapter when `elliptic_curve` migrates to a current
/// `rand_core`.
struct CompatRng<'a, R> {
    rng: &'a mut R,
    failed: bool,
}

impl<'a, R> CompatRng<'a, R> {
    /// Fills `dest` with a canonical, non-zero scalar representation (the
    /// big-endian value `1`). This keeps `elliptic_curve`'s rejection sampling
    /// from looping forever on the failure path: zero would be rejected as a
    /// scalar and an all-ones buffer could exceed the group order.
    fn fill_sentinel(dest: &mut [u8]) {
        dest.fill(0);
        if let Some(last) = dest.last_mut() {
            *last = 1;
        }
    }
}

impl<'a, R> elliptic_curve::rand_core::RngCore for CompatRng<'a, R>
where
    R: TryRng,
{
    fn next_u32(&mut self) -> u32 {
        self.rng.try_next_u32().unwrap_or_else(|_| {
            self.failed = true;
            1
        })
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.try_next_u64().unwrap_or_else(|_| {
            self.failed = true;
            1
        })
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.rng.try_fill_bytes(dest).is_err() {
            self.failed = true;
            Self::fill_sentinel(dest);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), elliptic_curve::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<'a, R> elliptic_curve::rand_core::CryptoRng for CompatRng<'a, R> where R: TryCryptoRng {}
