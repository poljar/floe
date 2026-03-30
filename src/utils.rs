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
    types::{FloeIv, segment::SEGMENT_HEADER_LENGTH},
};

pub(crate) const PARAMETER_INFO_LENGTH: usize = 10;

pub(crate) const fn segment_overhead<A>() -> usize
where
    A: AeadCore,
{
    let nonce_size = <A as AeadCore>::NonceSize::USIZE;
    let tag_size = <A as AeadCore>::TagSize::USIZE;

    nonce_size + tag_size + SEGMENT_HEADER_LENGTH
}

pub(crate) fn encoded_parameters<H, const N: usize, const S: u32>() -> [u8; PARAMETER_INFO_LENGTH]
where
    H: FloeKdf,
{
    let mut output = [0u8; PARAMETER_INFO_LENGTH];

    // AEAD_ID
    output[0] = 0x00;
    // KDF_IF
    output[1] = <H as FloeKdf>::KDF_ID;

    let segment_length = S.to_be_bytes();
    output[2..6].copy_from_slice(&segment_length);

    // TODO: This try_from call probably means that our IV length parameter needs to be a USIZE
    // type with a Sub<u32> constraint like we have for the header tag size. Or make N just a u32?
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

    // TODO: This should probably use the HKDF crate to make it more clear that this should be a
    // KDF, not a MAC.
    // Shouldn't matter for correctness, but would make this more obvious.
    let output = <H as KeyInit>::new_from_slice(key)
        .unwrap()
        .chain_update(params)
        .chain_update(floe_iv.as_bytes())
        .chain_update(purpose)
        .chain_update(associated_data)
        .chain_update(&[1])
        .finalize();

    // TODO: This is a move of an Array.
    output
}
