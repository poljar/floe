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

use core::marker::PhantomData;

use aead::{array::Array, consts::U32};
use digest::typenum::Unsigned;
use subtle::ConstantTimeEq;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{FloeAead, FloeKdf, result::HeaderDecodeError, types::floe_iv::FloeIv};

/// The size of the header tag.
type HeaderTagSize = U32;

/// The length of the encoded parameters.
///
/// Is always 10 bytes long.
const PARAMETER_INFO_LENGTH: usize = 10;

#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C)]
pub struct Parameters {
    aead_id: u8,
    kdf_id: u8,
    segment_length: zerocopy::U32<BigEndian>,
    floe_iv_length: zerocopy::U32<BigEndian>,
}

impl Parameters {
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
            floe_iv_length,
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct HeaderTag {
    pub(crate) inner: Array<u8, HeaderTagSize>,
}

impl HeaderTag {
    pub fn as_bytes(&self) -> &[u8; HeaderTagSize::USIZE] {
        #[allow(clippy::expect_used)]
        self.inner.as_array().expect("We should be able to convert the Array to a primitive array")
    }
}

impl ConstantTimeEq for HeaderTag {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

#[derive(Debug, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C)]
struct InnerHeader<A, H, const N: usize, const S: u32>
where
    A: FloeAead,
    H: FloeKdf,
{
    parameters: Parameters,
    floe_iv: FloeIv<N>,
    tag: HeaderTag,
    aead: PhantomData<A>,
    kdf: PhantomData<H>,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Header<A, H, const N: usize, const S: u32>
where
    A: FloeAead,
    H: FloeKdf,
{
    inner: InnerHeader<A, H, N, S>,
}

impl<A, H, const N: usize, const S: u32> Header<A, H, N, S>
where
    A: FloeAead,
    H: FloeKdf,
{
    pub const fn length() -> usize {
        PARAMETER_INFO_LENGTH + N + HeaderTagSize::USIZE
    }

    pub(crate) fn new(floe_iv: FloeIv<N>, header_tag: HeaderTag) -> Self {
        let parameters = Parameters::new::<A, H, N, S>();

        Self {
            inner: InnerHeader {
                parameters,
                floe_iv,
                tag: header_tag,
                aead: PhantomData,
                kdf: PhantomData,
            },
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderDecodeError> {
        let inner = InnerHeader::read_from_bytes(bytes).map_err(|_| {
            HeaderDecodeError::InvalidLength { expected: Self::length(), got: bytes.len() }
        })?;

        let expected_parameters = Parameters::new::<A, H, N, S>();

        if expected_parameters != inner.parameters {
            Err(HeaderDecodeError::InvalidParameters {
                expected: expected_parameters,
                got: inner.parameters,
            })
        } else {
            Ok(Self { inner })
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Get the encoded parameters of this header.
    pub fn parameters(&self) -> &Parameters {
        &self.inner.parameters
    }

    /// Get the Floe initialization vector contained in this header.
    pub fn iv(&self) -> &FloeIv<N> {
        &self.inner.floe_iv
    }

    /// Get the tag of this header.
    pub fn tag(&self) -> &HeaderTag {
        &self.inner.tag
    }
}
