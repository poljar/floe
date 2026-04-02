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

use aead::{AeadInOut, Nonce, Result, Tag};
use digest::typenum::Unsigned;

use crate::utils::segment_overhead;

/// The length of the segment header.
///
/// The segment header contains the length of a segment if the segment is the final segment or a
/// placeholder in case the segment is non-final, namely [`NON_FINAL_SEGMENT_HEADER`].
///
/// Since this is 4 bytes long, this limits the encrypted segment size to [u32::MAX]. This means
/// that the ciphertext and consequently the plaintext segment need to smaller than u32::MAX
/// because the encrypted segment needs to fit the header, nonce, and tag into the allocated buffer.
pub(crate) const SEGMENT_HEADER_LENGTH: usize = 4;

/// The segment header for any non-final encrypted segment.
pub(crate) const NON_FINAL_SEGMENT_HEADER: [u8; SEGMENT_HEADER_LENGTH] =
    [0xFFu8; SEGMENT_HEADER_LENGTH];

/// Given a byte slice, this range determines where we should expect the header of the
/// encrypted segment.
const HEADER_RANGE: Range<usize> = 0..SEGMENT_HEADER_LENGTH;

/// Given a byte slice, this range determines where we should expect the nonce of the
/// encrypted segment.
const fn nonce_range<A: AeadInOut>() -> Range<usize> {
    SEGMENT_HEADER_LENGTH..SEGMENT_HEADER_LENGTH + A::NonceSize::USIZE
}

/// Given a byte slice, this range determines where we should expect the AEAD tag of the encrypted
/// segment.
///
/// Since we're using a postfix tag, meaning the AEAD tag is appended at the end of the encrypted
/// segment, the range depends on the length of the message.
const fn tag_range<A: AeadInOut>(message_length: usize) -> Range<usize> {
    message_length - A::TagSize::USIZE..message_length
}

/// Given a byte slice, this range determines where we should expect the ciphertext of the
/// encrypted segment.
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
    pub fn from_bytes(message: &'a [u8]) -> Result<Self> {
        // TODO: Check the message length here.

        let header_slice = &message[HEADER_RANGE];
        let nonce = &message[nonce_range::<A>()];
        let tag = &message[tag_range::<A>(message.len())];

        let ciphertext = &message
            [SEGMENT_HEADER_LENGTH + A::NonceSize::USIZE..message.len() - A::TagSize::USIZE];

        let nonce = nonce.try_into().unwrap();
        let tag = tag.try_into().unwrap();

        let header: &[u8; SEGMENT_HEADER_LENGTH] = header_slice.try_into().unwrap();

        let segment = Self {
            header,
            nonce,
            ciphertext,
            tag,
        };

        Ok(segment)
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
    pub(crate) fn from_buffer(buffer: &'a mut [u8]) -> Result<Self> {
        // If the buffer can't fit at least the overhead and a single ciphertext byte, then return
        // an error.
        if buffer.len() < segment_overhead::<A>() + 1 {
            todo!("Too small buffer error")
        } else {
            let [header, nonce, ciphertext, tag] = buffer
                .get_disjoint_mut([
                    HEADER_RANGE,
                    nonce_range::<A>(),
                    ciphertext_range::<A>(buffer.len()),
                    tag_range::<A>(buffer.len()),
                ])
                .unwrap();

            Ok(Self {
                header: header.try_into().unwrap(),
                nonce: nonce.try_into().unwrap(),
                ciphertext,
                tag: tag.try_into().unwrap(),
            })
        }
    }
}
