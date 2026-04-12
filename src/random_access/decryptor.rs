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

use aead::{AeadCore, Key, KeySizeUser, array::ArraySize, consts::U32};
use digest::OutputSizeUser;
use subtle::ConstantTimeEq;
use zerocopy::{FromBytes, Immutable};

use crate::{
    DecryptionError, FloeAead, FloeKdf,
    keys::{FloeKey, MessageKey},
    types::{FloeIv, Header, Parameters, Segment, SegmentSize},
    utils::{check_segment_size, plaintext_size},
};

/// Generic implementation of the Floe random-access decryption APIs.
pub struct FloeDecryptor<'a, A, K, const N: usize, const S: SegmentSize>
where
    A: FloeAead,
    K: FloeKdf,
{
    /// The message key, used to derive the AEAD key for the segments.
    message_key: MessageKey<A, K>,

    /// The Floe initialization vector.
    ///
    /// This was created when the Floe session was created while the segments
    /// were encrypted.
    floe_iv: FloeIv<N>,

    /// The user-provided additional associated data.
    associated_data: &'a [u8],
}

impl<'a, A, K, const N: usize, const S: SegmentSize> FloeDecryptor<'a, A, K, N, S>
where
    A: FloeAead,
    K: FloeKdf,
    <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
    <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
    <K as OutputSizeUser>::OutputSize: Sub<<A as KeySizeUser>::KeySize>,
    <<K as OutputSizeUser>::OutputSize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize,
    <K as OutputSizeUser>::OutputSize: Sub<U32>,
    <<K as OutputSizeUser>::OutputSize as Sub<U32>>::Output: ArraySize,
    <K as OutputSizeUser>::OutputSize: Sub<<K as FloeKdf>::KeySize>,
    <<K as OutputSizeUser>::OutputSize as Sub<<K as FloeKdf>::KeySize>>::Output: ArraySize,
{
    pub fn new(
        key: &Key<A>,
        associated_data: &'a [u8],
        header: &Header<N>,
    ) -> Result<Self, DecryptionError> {
        check_segment_size::<A, S>();

        let expected_parameters = Parameters::new::<A, K, N, S>();

        if &expected_parameters != header.parameters() {
            return Err(DecryptionError::InvalidParameters {
                expected: expected_parameters,
                got: *header.parameters(),
            });
        }

        let floe_key = FloeKey::new(key);

        // TODO: Should we use Mac::verify() here?
        let expected_tag = floe_key.derive_header_tag::<N, S>(header.iv(), associated_data);
        let is_header_tag_valid: bool = expected_tag.ct_eq(header.tag()).into();

        if !is_header_tag_valid {
            Err(DecryptionError::InvalidHeaderTag)
        } else {
            let message_key = floe_key.derive_message_key::<N, S>(header.iv(), associated_data);
            let floe_iv = *header.iv();

            Ok(Self { message_key, floe_iv, associated_data })
        }
    }

    /// The length of the plaintext decrypting any non-final segment will
    /// produce.
    ///
    /// The length of the plaintext the final segment will produce can be found
    /// using the [`Segment::plaintext_size`] method.
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

        let ciphertext_length = segment.ciphertext().len();
        let buffer_length = buffer.len();
        let allowed_ciphertext_length = self.plaintext_size();

        if is_final {
            if segment.ciphertext().len() > allowed_ciphertext_length {
                return Err(DecryptionError::MalformedSegment);
            }

            if segment_number > A::AEAD_MAX_SEGMENTS.get() {
                return Err(DecryptionError::MaxSegmentsReached(A::AEAD_MAX_SEGMENTS.get()));
            }
        } else {
            if segment.ciphertext().len() != allowed_ciphertext_length {
                return Err(DecryptionError::MalformedSegment);
            }

            // SAFETY: This subtraction is always fine since AEAD_MAX_SEGMENTS is NonZero.
            if segment_number > (A::AEAD_MAX_SEGMENTS.get() - 1) {
                return Err(DecryptionError::MaxSegmentsReached(A::AEAD_MAX_SEGMENTS.get()));
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
