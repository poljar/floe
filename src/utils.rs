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

use aead::{AeadCore, Key, KeySizeUser};
use digest::{KeyInit, typenum::Unsigned};

use crate::{
    FloeKdf,
    types::{floe_iv::FloeIv, segment::SEGMENT_HEADER_LENGTH},
};

/// The length of the encoded parameters.
///
/// Is always 10 bytes long.
pub(crate) const PARAMETER_INFO_LENGTH: usize = 10;

/// Calculate how many bytes an encrypted segment would contain in addition to the ciphertext.
///
/// This value depends on the chosen AEAD as a segment will contain a nonce and a AEAD tag. For
/// more info about an segment, take a look at the [`crate::types::segment::Segment`] struct.
pub(crate) const fn segment_overhead<A>() -> usize
where
    A: AeadCore,
{
    let nonce_size = <A as AeadCore>::NonceSize::USIZE;
    let tag_size = <A as AeadCore>::TagSize::USIZE;

    nonce_size + tag_size + SEGMENT_HEADER_LENGTH
}

/// Encode the set of Floe parameters into a byte array.
///
/// This is the `PARAM_ENCODE(params) -> bytes` function from the [spec].
///
/// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#internal-functions
pub(crate) fn encoded_parameters<H, const N: usize, const S: u32>() -> [u8; PARAMETER_INFO_LENGTH]
where
    H: FloeKdf,
{
    let mut output = [0u8; PARAMETER_INFO_LENGTH];

    // AEAD_ID
    output[0] = 0x00;
    // KDF_IF
    output[1] = <H as FloeKdf>::KDF_ID;

    // The segment length, encoded as a big-endian value.
    let segment_length = S.to_be_bytes();
    output[2..6].copy_from_slice(&segment_length);

    // The floe IV length, needs to converted to an u32 as the Floe spec expects 4 bytes.
    // See the TODO item in the floe_iv.rs file how we can avoid this panic in the future.
    let floe_iv_length = u32::try_from(N).unwrap();
    let floe_iv_length = floe_iv_length.to_be_bytes();
    output[6..].copy_from_slice(&floe_iv_length);

    output
}

pub(crate) fn floe_kdf<A, H, const N: usize, const S: u32>(
    key: &Key<A>,
    floe_iv: &FloeIv<N>,
    associated_data: &[u8],
    purpose: &[u8],
) -> digest::CtOutput<H>
where
    A: AeadCore + KeySizeUser,
    H: FloeKdf,
{
    let params = encoded_parameters::<H, N, S>();

    // TODO: This should probably use the Hkdf crate to make it more clear that this should be a
    // KDF, not a MAC.
    // Shouldn't matter for correctness, but would make this more obvious.
    

    // TODO: This is a move of an Array so likely a memcpy under the hood. `finalize_into()` might
    // be the thing we want, or if we switch to the Hkdf crate, that'll have the right API shape.
    <H as KeyInit>::new_from_slice(key)
        .unwrap()
        .chain_update(params)
        .chain_update(floe_iv.as_bytes())
        .chain_update(purpose)
        .chain_update(associated_data)
        .chain_update([1])
        .finalize()
}
