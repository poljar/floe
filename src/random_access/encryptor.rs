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

use core::ops::Sub;

use aead::{AeadInOut, Key, KeyInit, KeySizeUser, Result, array::ArraySize, consts::U32};
use digest::OutputSizeUser;

use crate::{
    FloeKdf, Header,
    keys::{FloeKey, MessageKey},
    types::{floe_iv::FloeIv, segment::SegmentMut},
    utils::{encoded_parameters, segment_overhead},
};

pub struct FloeEncryptor<'a, A, H, const N: usize, const S: u32>
where
    A: AeadInOut + KeyInit,
    H: FloeKdf,
{
    message_key: MessageKey<A, H>,
    header: Header<N>,
    associated_data: &'a [u8],
}

impl<'a, A, H, const N: usize, const S: u32> FloeEncryptor<'a, A, H, N, S>
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
    pub fn new(key: &Key<A>, associated_data: &'a [u8]) -> Self {
        let floe_key = FloeKey::new(key);
        let floe_iv = FloeIv::generate();

        let header_tag = floe_key.derive_header_tag::<N, S>(&floe_iv, associated_data);
        let message_key = floe_key.derive_message_key::<N, S>(&floe_iv, associated_data);

        let header = Header {
            parameter_info: encoded_parameters::<H, N, S>(),
            floe_iv,
            tag: header_tag,
        };

        Self {
            message_key,
            header,
            associated_data,
        }
    }

    pub const fn output_size(&self, plaintext: &[u8]) -> usize {
        segment_overhead::<A>() + plaintext.len()
    }

    pub fn header(&self) -> &Header<N> {
        &self.header
    }

    pub fn encrypt_segment(
        &self,
        plaintext: &[u8],
        buffer: &mut [u8],
        segment_number: u64,
        is_final: bool,
    ) -> Result<()> {
        // TODO: This cast might truncate bits if S::Max > usize::Max.
        let allowed_plaintext_length = S as usize - segment_overhead::<A>();

        if is_final {
            if plaintext.len() > allowed_plaintext_length {
                todo!("The final segment is larger")
            }
        } else {
            if plaintext.len() != allowed_plaintext_length {
                todo!("The plaintext has an incorrect length");
            }
        }

        // TODO: Check if we reached the max number of allowed segments.

        let segment = SegmentMut::from_buffer(buffer).unwrap();

        // If our plaintext doesn't fit into the output buffer, return an error.
        if segment.ciphertext.len() != plaintext.len() {
            todo!("The output buffer is too small")
        } else {
            // Now copy the plaintext into the ciphertext part of the output buffer, the AEAD will
            // replace the plaintext bytes in-place with the ciphertext bytes.
            segment.ciphertext.copy_from_slice(plaintext);

            // Now we derive an epoch key for this segment.
            let epoch_key = self.message_key.derive_epoch_key::<N, S>(
                &self.header.floe_iv,
                &self.associated_data,
                segment_number,
                is_final,
            );

            // And finally we encrypt the segment.
            epoch_key.encrypt_segment(segment)
        }
    }
}
