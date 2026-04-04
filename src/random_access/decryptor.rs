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

use aead::{AeadInOut, Key, KeyInit, KeySizeUser, array::ArraySize, consts::U32};
use digest::OutputSizeUser;
use subtle::ConstantTimeEq;

use crate::{
    DecryptionError, FloeKdf,
    keys::{FloeKey, MessageKey},
    types::{AEAD_MAX_SEGMENTS, floe_iv::FloeIv, header::Header, segment::Segment},
    utils::{check_segment_size, plaintext_size},
};

pub struct FloeDecryptor<'a, A, H, const N: usize, const S: u32>
where
    A: AeadInOut + KeyInit,
    H: FloeKdf,
{
    message_key: MessageKey<A, H>,
    floe_iv: FloeIv<N>,
    associated_data: &'a [u8],
}

impl<'a, A, H, const N: usize, const S: u32> FloeDecryptor<'a, A, H, N, S>
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
    pub fn new(
        key: &Key<A>,
        associated_data: &'a [u8],
        header: &Header<H, N, S>,
    ) -> Result<Self, DecryptionError> {
        check_segment_size::<A, S>();

        let floe_key = FloeKey::new(key);

        // TODO: Should we use Mac::verify() here?
        let expected_tag = floe_key.derive_header_tag::<N, S>(&header.floe_iv, associated_data);
        let is_header_tag_valid: bool = expected_tag.ct_eq(&header.tag).into();

        if !is_header_tag_valid {
            Err(DecryptionError::InvalidHeaderTag)
        } else {
            let message_key = floe_key.derive_message_key::<N, S>(&header.floe_iv, associated_data);
            let floe_iv = header.floe_iv;

            Ok(Self { message_key, floe_iv, associated_data })
        }
    }

    pub fn plaintext_size(&self) -> usize {
        // SAFETY: The constructor of the FloeDecryptor checks that the segment size
        // fits into an usize and that it's bigger than the overhead.
        plaintext_size::<A, S>()
    }

    pub fn decrypt_segment(
        &self,
        segment: &Segment<'_, A>,
        buffer: &mut [u8],
        segment_number: u64,
        is_final: bool,
    ) -> Result<(), DecryptionError> {
        if is_final != segment.is_final() {
            return Err(DecryptionError::MalformedSegment);
        }

        let ciphertext_length = segment.ciphertext.len();
        let buffer_length = buffer.len();
        let allowed_ciphertext_length = self.plaintext_size();

        if is_final {
            if segment.ciphertext.len() > allowed_ciphertext_length {
                return Err(DecryptionError::MalformedSegment);
            }

            if segment_number > AEAD_MAX_SEGMENTS {
                return Err(DecryptionError::MaxSegmentsReached(AEAD_MAX_SEGMENTS));
            }
        } else {
            if segment.ciphertext.len() != allowed_ciphertext_length {
                return Err(DecryptionError::MalformedSegment);
            }

            if segment_number > (AEAD_MAX_SEGMENTS - 1) {
                return Err(DecryptionError::MaxSegmentsReached(AEAD_MAX_SEGMENTS));
            }
        }

        if ciphertext_length != buffer_length {
            return Err(DecryptionError::InvalidBuffer {
                got: buffer_length,
                expected: ciphertext_length,
            });
        }

        let epoch_key = self.message_key.derive_epoch_key::<N, S>(
            &self.floe_iv,
            self.associated_data,
            segment_number,
            is_final,
        );

        epoch_key.decrypt_segment(segment, buffer)
    }
}
