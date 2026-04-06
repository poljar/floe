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

pub(crate) mod parameters;
pub(crate) mod tag;

use core::marker::PhantomData;

use digest::typenum::Unsigned;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    FloeAead, FloeKdf, HeaderTag, Parameters,
    result::HeaderDecodeError,
    types::{
        floe_iv::FloeIv,
        header::{parameters::PARAMETER_INFO_LENGTH, tag::HeaderTagSize},
    },
};

#[derive(Debug, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C)]
struct InnerHeader<A, K, const N: usize>
where
    A: FloeAead,
    K: FloeKdf,
{
    parameters: Parameters,
    floe_iv: FloeIv<N>,
    tag: HeaderTag,
    aead: PhantomData<A>,
    kdf: PhantomData<K>,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Header<A, K, const N: usize>
where
    A: FloeAead,
    K: FloeKdf,
{
    inner: InnerHeader<A, K, N>,
}

impl<A, K, const N: usize> Header<A, K, N>
where
    A: FloeAead,
    K: FloeKdf,
{
    pub const fn length() -> usize {
        PARAMETER_INFO_LENGTH + N + HeaderTagSize::USIZE
    }

    pub(crate) fn new<const S: u32>(floe_iv: FloeIv<N>, header_tag: HeaderTag) -> Self {
        let parameters = Parameters::new::<A, K, N, S>();

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

        Ok(Self { inner })
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
