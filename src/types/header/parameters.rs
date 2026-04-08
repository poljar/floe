// Copyright 2026 Damir Jelić
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{FloeAead, FloeKdf};

/// Information about the parameters a Floe session is using.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct Parameters {
    aead_id: u8,
    kdf_id: u8,
    segment_length: zerocopy::U32<BigEndian>,
    floe_iv_size: zerocopy::U32<BigEndian>,
}

impl Parameters {
    /// The length of the parameter info in the header, in bytes.
    pub const LENGTH: usize = 10;

    /// Create a new set of Floe parameters.
    ///
    /// This is the `PARAM_ENCODE(params) -> bytes` function from the [spec].
    ///
    /// # Panics
    ///
    /// This function will panic if the Floe IV length (N) is too large, it
    /// needs to fit into a `u32`.
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#internal-functions
    pub(crate) fn new<A, K, const N: usize, const S: u32>() -> Self
    where
        A: FloeAead,
        K: FloeKdf,
    {
        // The floe IV length, needs to converted to an u32 as the Floe spec expects 4
        // bytes. See the TODO item in the floe_iv.rs file how we can avoid this
        // panic in the future.
        #[allow(clippy::expect_used)]
        let floe_iv_length =
            u32::try_from(N).expect("the Floe IV is too long, it must be smaller than u32::MAX");
        let floe_iv_length = zerocopy::U32::new(floe_iv_length);

        Self {
            aead_id: A::AEAD_ID,
            kdf_id: K::KDF_ID,
            segment_length: zerocopy::U32::new(S),
            floe_iv_size: floe_iv_length,
        }
    }

    /// Get the unique ID of the AEAD that is used for this Floe session.
    pub fn aead_id(&self) -> u8 {
        self.aead_id
    }

    /// Get the unique ID of the KDF implementation that is used for this Floe
    /// session.
    pub fn kdf_id(&self) -> u8 {
        self.kdf_id
    }

    /// Get configured segment length of this Floe session.
    pub fn segment_length(&self) -> u32 {
        self.segment_length.get()
    }

    /// Get the size of the Floe initialization vector of this Floe session.
    pub fn floe_iv_size(&self) -> u32 {
        self.floe_iv_size.get()
    }
}
