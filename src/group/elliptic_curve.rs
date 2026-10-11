// SPDX-License-Identifier: MIT OR Apache-2.0

use core::ops::{Add, Mul};

use digest::block_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use elliptic_curve::ops::Reduce;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{
    AffinePoint, Field, FieldBytesSize, Generate, Group as _, NonZeroScalar, PrimeField,
    ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use hash2curve::{ExpandMsgXmd, MapToCurve};
use hybrid_array::typenum::{IsGreaterOrEqual, IsLessOrEqual, Prod, Sum, True, U2};
use hybrid_array::{Array, ArraySize};
use rand_core::{TryCryptoRng, TryRng};

use super::Group;
use crate::{Error, InternalError, Result};

type ElemLen<C> = <ScalarLen<C> as ModulusSize>::CompressedPointSize;
type ScalarLen<C> = FieldBytesSize<C>;
type HashToFieldLen<C> = <C as MapToCurve>::Length;

impl<C> Group for C
where
    C: MapToCurve,
    <C as MapToCurve>::SecurityLevel: Mul<U2>,
    ProjectivePoint<Self>: ToSec1Point<Self>,
    ScalarLen<Self>: ModulusSize,
    AffinePoint<Self>: FromSec1Point<Self> + ToSec1Point<Self>,
    Scalar<Self>: Reduce<Array<u8, HashToFieldLen<Self>>>,
    // `VoprfClientLen`, `PoprfClientLen`, `VoprfServerLen`, `PoprfServerLen`
    ScalarLen<Self>: Add<ElemLen<Self>>,
    Sum<ScalarLen<Self>, ElemLen<Self>>: ArraySize,
    // `ProofLen`
    ScalarLen<Self>: Add<ScalarLen<Self>>,
    Sum<ScalarLen<Self>, ScalarLen<Self>>: ArraySize,
{
    type Elem = ProjectivePoint<Self>;

    type ElemLen = ElemLen<Self>;

    type Scalar = Scalar<Self>;

    type ScalarLen = ScalarLen<Self>;

    type SecurityLevel = <C as MapToCurve>::SecurityLevel;

    // Implements the `hash_to_curve()` function from
    // https://www.rfc-editor.org/rfc/rfc9380.html#section-3
    fn hash_to_curve<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Elem, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLessOrEqual<H::BlockSize, Output = True>
            + IsGreaterOrEqual<Prod<<Self as Group>::SecurityLevel, U2>, Output = True>,
    {
        hash2curve::hash_from_bytes::<Self, ExpandMsgXmd<H>>(input, dst)
            .map_err(|_| InternalError::Input)
    }

    // Implements the `HashToScalar()` function from
    // https://www.rfc-editor.org/rfc/rfc9497#section-4. RFC 9497 picks the
    // same `L` for scalars that RFC 9380 picks for base field elements of
    // each NIST curve, so we reuse `MapToCurve::Length`.
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLessOrEqual<H::BlockSize, Output = True>
            + IsGreaterOrEqual<Prod<<Self as Group>::SecurityLevel, U2>, Output = True>,
    {
        hash2curve::hash_to_scalar::<Self, ExpandMsgXmd<H>, HashToFieldLen<Self>>(input, dst)
            .map_err(|_| InternalError::Input)
    }

    fn base_elem() -> Self::Elem {
        ProjectivePoint::<Self>::generator()
    }

    fn identity_elem() -> Self::Elem {
        ProjectivePoint::<Self>::identity()
    }

    fn serialize_elem(elem: Self::Elem) -> Array<u8, Self::ElemLen> {
        let bytes = elem.to_sec1_point(true);
        let bytes = bytes.as_bytes();
        let mut result = Array::default();
        result[..bytes.len()].copy_from_slice(bytes);
        result
    }

    fn deserialize_elem(element_bits: &[u8]) -> Result<Self::Elem> {
        PublicKey::<Self>::from_sec1_bytes(element_bits)
            .map(|public_key| public_key.to_projective())
            .map_err(|_| Error::Deserialization)
    }

    fn random_scalar<R: TryRng + TryCryptoRng>(rng: &mut R) -> Result<Self::Scalar> {
        NonZeroScalar::<Self>::try_generate_from_rng(rng)
            .map(|scalar| *scalar)
            .map_err(|_| Error::Rng)
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

    fn serialize_scalar(scalar: Self::Scalar) -> Array<u8, Self::ScalarLen> {
        scalar.to_repr()
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> Result<Self::Scalar> {
        SecretKey::<Self>::from_slice(scalar_bits)
            .map(|secret_key| *secret_key.to_nonzero_scalar())
            .map_err(|_| Error::Deserialization)
    }
}
