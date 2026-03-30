// Copyright 2026 Damir Jelić, Snowflake Inc.
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

use std::{marker::PhantomData, ops::Sub};

use aead::{
    AeadInOut, Key,
    array::{Array, ArraySize},
    consts::U32,
};
use digest::{KeyInit, OutputSizeUser};

use super::message_key::MessageKey;

use crate::{
    FloeKdf,
    types::{FloeIv, HeaderTag},
    utils::floe_kdf,
};

/// The main input key for a Floe session.
///
/// As per [spec], must be the same size as the AEAD key.
///
/// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#key-generation
pub struct FloeKey<'a, A, H>
where
    A: AeadInOut + KeyInit,
    H: FloeKdf,
{
    key: &'a Key<A>,
    _phantom_aead: PhantomData<A>,
    _phantom: PhantomData<H>,
}

impl<'a, A, H> FloeKey<'a, A, H>
where
    A: AeadInOut + KeyInit,
    H: FloeKdf,
{
    /// Create a new [`FloeKey`] from an array of bytes.
    pub(crate) fn new(key: &'a Key<A>) -> Self {
        Self {
            key,
            _phantom_aead: PhantomData::default(),
            _phantom: PhantomData::default(),
        }
    }

    /// Derive the header tag using this [`FloeKey`] as the input key material of the `FLOE_KDF`
    /// operation.
    ///
    /// From the [spec]:
    ///
    /// ```text
    /// HeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)
    /// ```
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    pub(crate) fn derive_header_tag<const N: usize, const S: u32>(
        &self,
        floe_iv: &FloeIv<N>,
        associated_data: &[u8],
    ) -> HeaderTag
    where
        <H as OutputSizeUser>::OutputSize: Sub<U32>,
        <<H as OutputSizeUser>::OutputSize as Sub<U32>>::Output: ArraySize,
    {
        const PURPOSE: &[u8] = b"HEADER_TAG:";

        let output = floe_kdf::<A, H, N, S>(&self.key, floe_iv, associated_data, PURPOSE);
        let (inner, _) = Array::split::<U32>(output.into_bytes());

        HeaderTag { inner }
    }

    /// Derive the [`MessageKey`] using this [`FloeKey`] as the input key material of the `FLOE_KDF`
    /// operation.
    ///
    /// From the [spec]:
    ///
    /// ```text
    /// MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_KEY_LEN)
    /// ```
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    pub(crate) fn derive_message_key<const N: usize, const S: u32>(
        &self,
        floe_iv: &FloeIv<N>,
        associated_data: &[u8],
    ) -> MessageKey<A, H>
    where
        <H as OutputSizeUser>::OutputSize: Sub<<H as FloeKdf>::KeySize>,
        <<H as OutputSizeUser>::OutputSize as Sub<<H as FloeKdf>::KeySize>>::Output: ArraySize,
    {
        const PURPOSE: &[u8] = b"MESSAGE_KEY:";

        let output = floe_kdf::<A, H, N, S>(&self.key, floe_iv, associated_data, PURPOSE);
        let (key, _) = Array::split::<<H as FloeKdf>::KeySize>(output.into_bytes());

        MessageKey {
            key,
            _phantom_aead: PhantomData::default(),
            _phantom: PhantomData::default(),
        }
    }
}
