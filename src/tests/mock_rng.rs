// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::vec::Vec;
use core::cmp::min;
use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

/// A simple infallible RNG for testing purposes.
///
/// This generates a cyclic sequence (i.e. cycles over an initial buffer)
#[derive(Debug, Clone)]
pub struct CycleRng {
    v: Vec<u8>,
}

impl CycleRng {
    /// Create a `CycleRng`, yielding a sequence starting with `initial` and
    /// looping thereafter
    pub fn new(initial: Vec<u8>) -> Self {
        CycleRng { v: initial }
    }
}

fn rotate_left<T>(data: &mut [T], steps: usize) {
    if data.is_empty() {
        return;
    }
    let steps = steps % data.len();

    data[..steps].reverse();
    data[steps..].reverse();
    data.reverse();
}

impl TryRng for CycleRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!()
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!()
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let len = min(self.v.len(), dest.len());
        dest[..len].copy_from_slice(&self.v[..len]);
        rotate_left(&mut self.v, len);
        Ok(())
    }
}

// This is meant for testing only
impl TryCryptoRng for CycleRng {}
