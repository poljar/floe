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

use std::ops::Sub;

use aead::{AeadInOut, Key, KeyInit, KeySizeUser, Result, array::ArraySize, consts::U32};
use digest::OutputSizeUser;
use subtle::ConstantTimeEq;

use crate::{
    FloeKdf,
    keys::{FloeKey, MessageKey},
    types::{FloeIv, Header, segment::Segment},
    utils::{encoded_parameters, segment_overhead},
};

pub struct FloeDecryptor<A, H, const N: usize, const S: u32>
where
    A: AeadInOut + KeyInit,
    H: FloeKdf,
{
    message_key: MessageKey<A, H>,
    floe_iv: FloeIv<N>,
    associated_data: Vec<u8>,
}

impl<A, H, const N: usize, const S: u32> FloeDecryptor<A, H, N, S>
where
    A: AeadInOut + KeyInit,
    H: FloeKdf,
    <H as OutputSizeUser>::OutputSize: Sub<<A as KeySizeUser>::KeySize>,
    <<H as OutputSizeUser>::OutputSize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize,
    <H as OutputSizeUser>::OutputSize: Sub<U32>,
    <<H as OutputSizeUser>::OutputSize as Sub<U32>>::Output: ArraySize,
    <H as OutputSizeUser>::OutputSize: Sub<<H as FloeKdf>::KeySize>,
    <<H as OutputSizeUser>::OutputSize as Sub<<H as FloeKdf>::KeySize>>::Output: ArraySize,
{
    pub fn new(key: &Key<A>, associated_data: &[u8], header: &Header<N>) -> Result<Self> {
        let floe_key = FloeKey::new(key);

        let expected_parameters = encoded_parameters::<N, S>();
        let expected_tag = floe_key.derive_header_tag::<N, S>(&header.floe_iv, associated_data);
        // TODO: Should we use Mac::verify() here?
        let is_header_tag_valid: bool = expected_tag.ct_eq(&header.tag).into();

        if header.parameter_info != expected_parameters {
            todo!("The parameters don't match")
        } else if !is_header_tag_valid {
            todo!("Header tag is not valid")
        } else {
            let message_key = floe_key.derive_message_key::<N, S>(&header.floe_iv, associated_data);
            let floe_iv = header.floe_iv;

            Ok(Self {
                message_key,
                floe_iv,
                associated_data: associated_data.to_owned(),
            })
        }
    }

    pub fn output_size() -> usize {
        // TODO: unsafe cast
        S as usize - segment_overhead::<A>()
    }

    pub const fn final_segment_output_size(segment: &[u8]) -> usize {
        segment.len() - segment_overhead::<A>()
    }

    pub fn decrypt_segment(
        &self,
        segment: &[u8],
        buffer: &mut [u8],
        segment_number: u64,
        is_final: bool,
    ) -> Result<()> {
        // TODO: Make the Segment public and let users decode it outside of the decrypt method?
        let segment = Segment::from_bytes(segment, is_final).unwrap();

        if segment.ciphertext.len() == buffer.len() {
            let epoch_key = self.message_key.derive_epoch_key::<N, S>(
                &self.floe_iv,
                &self.associated_data,
                segment_number,
                is_final,
            );

            epoch_key.decrypt_segment(segment, buffer)?;

            Ok(())
        } else {
            todo!("Error invalid buffer length")
        }
    }
}
