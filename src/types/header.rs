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

use std::marker::PhantomData;

use aead::{array::Array, consts::U32};
use digest::typenum::Unsigned;
use subtle::ConstantTimeEq;

use crate::{
    FloeKdf,
    result::HeaderDecodeError,
    types::floe_iv::FloeIv,
    utils::{PARAMETER_INFO_LENGTH, encoded_parameters},
};

pub(crate) type HeaderTagSize = U32;

#[derive(Debug)]
pub struct HeaderTag {
    pub(crate) inner: Array<u8, HeaderTagSize>,
}

impl HeaderTag {
    pub(crate) fn new() -> Self {
        Self {
            inner: Array::from([0u8; HeaderTagSize::USIZE]),
        }
    }

    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8; HeaderTagSize::USIZE] {
        #[allow(clippy::expect_used)]
        self.inner
            .as_mut_array()
            .expect("We should be able to convert the Array to an primitive array")
    }

    pub fn as_bytes(&self) -> &[u8; HeaderTagSize::USIZE] {
        #[allow(clippy::expect_used)]
        self.inner
            .as_array()
            .expect("We should be able to convert the Array to an primitive array")
    }
}

impl ConstantTimeEq for HeaderTag {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

#[derive(Debug)]
pub struct Header<H: FloeKdf, const N: usize, const S: u32> {
    pub(crate) parameter_info: [u8; PARAMETER_INFO_LENGTH],
    pub(crate) floe_iv: FloeIv<N>,
    pub(crate) tag: HeaderTag,
    pub(crate) phantom_data: PhantomData<H>,
}

impl<H: FloeKdf, const N: usize, const S: u32> Header<H, N, S> {
    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderDecodeError> {
        let expected_length = Self::length();
        let slice_length = bytes.len();

        if slice_length != expected_length {
            return Err(HeaderDecodeError::InvalidLength {
                expected: expected_length,
                got: slice_length,
            });
        }

        let mut parameter_info = [0u8; PARAMETER_INFO_LENGTH];
        parameter_info.copy_from_slice(&bytes[..PARAMETER_INFO_LENGTH]);

        let mut floe_iv = FloeIv::<N>::new();
        floe_iv
            .as_bytes_mut()
            .copy_from_slice(&bytes[PARAMETER_INFO_LENGTH..N + PARAMETER_INFO_LENGTH]);

        let mut tag = HeaderTag::new();

        tag.as_bytes_mut()
            .copy_from_slice(&bytes[PARAMETER_INFO_LENGTH + N..]);

        let expected_parameters = encoded_parameters::<H, N, S>();

        if expected_parameters != parameter_info {
            Err(HeaderDecodeError::InvalidParameters)
        } else {
            Ok(Self {
                parameter_info,
                floe_iv,
                tag,
                phantom_data: PhantomData,
            })
        }
    }

    // TODO: This should go behind an alloc feature flag.
    #[cfg(feature = "std")]
    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: We could return an array here, but as with the FloeIv type, we would need the
        // `generic_const_exprs` feature.
        // let output = [0u8; Self::length()];
        [
            self.parameter_info.as_slice(),
            self.floe_iv.as_bytes().as_slice(),
            self.tag.as_bytes().as_slice(),
        ]
        .concat()
    }

    pub fn parameters(&self) -> &[u8; PARAMETER_INFO_LENGTH] {
        &self.parameter_info
    }

    pub fn iv(&self) -> &FloeIv<N> {
        &self.floe_iv
    }

    pub fn tag(&self) -> &HeaderTag {
        &self.tag
    }

    pub const fn length() -> usize {
        PARAMETER_INFO_LENGTH + N + HeaderTagSize::USIZE
    }
}
