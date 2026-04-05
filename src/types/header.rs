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
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    FloeAead, FloeKdf,
    result::HeaderDecodeError,
    types::floe_iv::FloeIv,
    utils::{PARAMETER_INFO_LENGTH, encoded_parameters},
};

/// The size of the header tag.
pub(crate) type HeaderTagSize = U32;

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
    parameter_info: [u8; PARAMETER_INFO_LENGTH],
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
        let parameter_info = encoded_parameters::<A, H, N, S>();

        Self {
            inner: InnerHeader {
                parameter_info,
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

        let expected_parameters = encoded_parameters::<A, H, N, S>();

        if expected_parameters != inner.parameter_info {
            Err(HeaderDecodeError::InvalidParameters)
        } else {
            Ok(Self { inner })
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    pub fn parameters(&self) -> &[u8; PARAMETER_INFO_LENGTH] {
        &self.inner.parameter_info
    }

    pub fn iv(&self) -> &FloeIv<N> {
        &self.inner.floe_iv
    }

    pub fn tag(&self) -> &HeaderTag {
        &self.inner.tag
    }
}
