// SPDX-License-Identifier: MIT OR Apache-2.0

//! Includes a series of tests for the group implementations

use rand_core::{TryCryptoRng, TryRng};

use crate::{Error, Group, Result};

// Test that the deserialization of a group element should throw an error if the
// identity element can be deserialized properly

#[test]
fn test_group_properties() -> Result<()> {
    use p256::NistP256;
    use p384::NistP384;
    use p521::NistP521;

    #[cfg(feature = "ristretto255")]
    {
        use crate::Ristretto255;

        test_identity_element_error::<Ristretto255>()?;
        test_zero_scalar_error::<Ristretto255>()?;
    }

    test_identity_element_error::<NistP256>()?;
    test_zero_scalar_error::<NistP256>()?;

    test_identity_element_error::<NistP384>()?;
    test_zero_scalar_error::<NistP384>()?;

    test_identity_element_error::<NistP521>()?;
    test_zero_scalar_error::<NistP521>()?;

    Ok(())
}

// Checks that the identity element cannot be deserialized
fn test_identity_element_error<G: Group>() -> Result<()> {
    let identity = G::identity_elem();
    let result = G::deserialize_elem(&G::serialize_elem(identity));
    assert!(matches!(result, Err(Error::Deserialization)));

    Ok(())
}

// Checks that the zero scalar cannot be deserialized
fn test_zero_scalar_error<G: Group>() -> Result<()> {
    let zero_scalar = G::zero_scalar();
    let result = G::deserialize_scalar(&G::serialize_scalar(zero_scalar));
    assert!(matches!(result, Err(Error::Deserialization)));

    Ok(())
}

/// A fallible RNG whose every operation fails, used to verify that RNG failures
/// surface as [`Error::Rng`] rather than panicking.
#[derive(Debug)]
struct FailingRng;

#[derive(Debug)]
struct FailingRngError;

impl core::fmt::Display for FailingRngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the test RNG always fails")
    }
}

// `rand_core 0.10` requires the `TryRng::Error` type to implement
// `core::error::Error`, which in turn needs `Debug` and `Display`.
impl core::error::Error for FailingRngError {}

impl TryRng for FailingRng {
    type Error = FailingRngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(FailingRngError)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(FailingRngError)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(FailingRngError)
    }
}

impl TryCryptoRng for FailingRng {}

// Checks that a failing RNG yields `Error::Rng` instead of panicking.
fn test_random_scalar_rng_failure<G: Group>() -> Result<()> {
    assert!(matches!(G::random_scalar(&mut FailingRng), Err(Error::Rng)));

    Ok(())
}

#[test]
fn test_random_scalar_rng_failure_all() -> Result<()> {
    use p256::NistP256;
    use p384::NistP384;
    use p521::NistP521;

    #[cfg(feature = "ristretto255")]
    test_random_scalar_rng_failure::<crate::Ristretto255>()?;

    test_random_scalar_rng_failure::<NistP256>()?;
    test_random_scalar_rng_failure::<NistP384>()?;
    test_random_scalar_rng_failure::<NistP521>()?;

    Ok(())
}
