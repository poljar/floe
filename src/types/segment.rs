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

use core::ops::Range;

use aead::{AeadInOut, Nonce, Tag};
use digest::typenum::Unsigned;

use crate::{EncryptionError, result::SegmentDecodeError, utils::segment_overhead};

/// The length of the segment header.
///
/// The segment header contains the length of a segment if the segment is the
/// final segment or a placeholder in case the segment is non-final, namely
/// [`NON_FINAL_SEGMENT_HEADER`].
///
/// Since this is 4 bytes long, this limits the encrypted segment size to
/// [u32::MAX]. This means that the ciphertext and consequently the plaintext
/// segment need to smaller than u32::MAX because the encrypted segment needs to
/// fit the header, nonce, and tag into the allocated buffer.
pub(crate) const SEGMENT_HEADER_LENGTH: usize = 4;

/// The segment header for any non-final encrypted segment.
pub(crate) const NON_FINAL_SEGMENT_HEADER: [u8; SEGMENT_HEADER_LENGTH] =
    [0xFFu8; SEGMENT_HEADER_LENGTH];

/// Given a byte slice, this range determines where we should expect the header
/// of the encrypted segment.
const HEADER_RANGE: Range<usize> = 0..SEGMENT_HEADER_LENGTH;

/// Given a byte slice, this range determines where we should expect the nonce
/// of the encrypted segment.
const fn nonce_range<A: AeadInOut>() -> Range<usize> {
    SEGMENT_HEADER_LENGTH..SEGMENT_HEADER_LENGTH + A::NonceSize::USIZE
}

/// Given a byte slice, this range determines where we should expect the AEAD
/// tag of the encrypted segment.
///
/// Since we're using a postfix tag, meaning the AEAD tag is appended at the end
/// of the encrypted segment, the range depends on the length of the message.
const fn tag_range<A: AeadInOut>(message_length: usize) -> Range<usize> {
    message_length - A::TagSize::USIZE..message_length
}

/// Given a byte slice, this range determines where we should expect the
/// ciphertext of the encrypted segment.
const fn ciphertext_range<A: AeadInOut>(message_length: usize) -> Range<usize> {
    SEGMENT_HEADER_LENGTH + A::NonceSize::USIZE..message_length - A::TagSize::USIZE
}

// TODO: Should the segment know about the expected segment size?
pub struct Segment<'a, A>
where
    A: AeadInOut,
{
    pub(crate) header: &'a [u8; SEGMENT_HEADER_LENGTH],
    pub(crate) nonce: &'a Nonce<A>,
    pub(crate) ciphertext: &'a [u8],
    pub(crate) tag: &'a Tag<A>,
}

impl<'a, A> Segment<'a, A>
where
    A: AeadInOut,
{
    pub fn from_bytes(segment: &'a [u8]) -> Result<Self, SegmentDecodeError> {
        let segment_length = segment.len();
        let expected_length = segment_overhead::<A>() + 1;

        if segment_length < expected_length {
            return Err(SegmentDecodeError::InvalidSliceLength {
                expected: expected_length,
                got: segment_length,
            });
        }

        let header_slice = &segment[HEADER_RANGE];
        let nonce = &segment[nonce_range::<A>()];
        let tag = &segment[tag_range::<A>(segment_length)];
        let ciphertext = &segment[ciphertext_range::<A>(segment_length)];

        #[allow(clippy::expect_used)]
        let header: &[u8; SEGMENT_HEADER_LENGTH] = header_slice.try_into().expect(
            "should be able to interpret the header slice as an \
                array, the range has the correct size",
        );

        #[allow(clippy::expect_used)]
        let nonce = nonce.try_into().expect(
            "should be able to interpret the nonce \
                slice as an array since the range has the correct size",
        );

        #[allow(clippy::expect_used)]
        let tag = tag.try_into().expect(
            "should be able to interpret the tag slice as \
                an array since the range has the correct size",
        );

        let is_final = header != &NON_FINAL_SEGMENT_HEADER;

        if is_final {
            let length: usize = u32::from_be_bytes(*header)
                .try_into()
                .map_err(|_| SegmentDecodeError::MalformedSegment)?;

            if length != segment.len() {
                return Err(SegmentDecodeError::MalformedSegment);
            }
        }

        Ok(Self { header, nonce, ciphertext, tag })
    }

    pub fn is_final(&self) -> bool {
        self.header != &NON_FINAL_SEGMENT_HEADER
    }

    pub const fn plaintext_size(&self) -> usize {
        self.ciphertext.len()
    }
}

pub(crate) struct SegmentMut<'a, A>
where
    A: AeadInOut,
{
    pub(crate) header: &'a mut [u8; SEGMENT_HEADER_LENGTH],
    pub(crate) nonce: &'a mut Nonce<A>,
    pub(crate) ciphertext: &'a mut [u8],
    pub(crate) tag: &'a mut Tag<A>,
}

impl<'a, A> SegmentMut<'a, A>
where
    A: AeadInOut,
{
    pub(crate) const fn output_size(plaintext: &[u8]) -> usize {
        plaintext.len() + segment_overhead::<A>()
    }

    pub(crate) fn from_buffer_and_plaintext(
        plaintext: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<Self, EncryptionError> {
        let expected_buffer_size = Self::output_size(plaintext);
        let buffer_length = buffer.len();

        if buffer_length != expected_buffer_size {
            // If our plaintext doesn't fit into the output buffer, return an error.
            Err(EncryptionError::InvalidBuffer {
                expected: expected_buffer_size,
                got: buffer_length,
            })
        } else {
            #[allow(clippy::expect_used)]
            let [header, nonce, ciphertext, tag] = buffer
                .get_disjoint_mut([
                    HEADER_RANGE,
                    nonce_range::<A>(),
                    ciphertext_range::<A>(buffer.len()),
                    tag_range::<A>(buffer.len()),
                ])
                .expect(
                    "the buffer length was already checked and the ranges are disjoint, \
                    we should be able to get disjoint mut slices of the output buffer",
                );

            #[allow(clippy::expect_used)]
            let header = header
                .try_into()
                .expect("the disjoint header slice should have the correct length");

            #[allow(clippy::expect_used)]
            let nonce =
                nonce.try_into().expect("the disjoint nonce slice should have the correct length");

            #[allow(clippy::expect_used)]
            let tag =
                tag.try_into().expect("the disjoint tag slice should have the correct length");

            // Now copy the plaintext into the ciphertext part of the output buffer, the
            // AEAD will later replace the plaintext bytes in-place with the
            // ciphertext bytes.
            ciphertext.copy_from_slice(plaintext);

            Ok(Self { header, nonce, ciphertext, tag })
        }
    }
}
