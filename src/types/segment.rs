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

use std::ops::Range;

use aead::{AeadInOut, Nonce, Result, Tag};
use digest::typenum::Unsigned;

use crate::utils::segment_overhead;

pub(crate) const SEGMENT_HEADER_LENGTH: usize = 4;
pub(crate) const HEADER_RANGE: Range<usize> = 0..SEGMENT_HEADER_LENGTH;
pub(crate) const NON_FINAL_SEGMENT_HEADER: [u8; SEGMENT_HEADER_LENGTH] =
    [0xFFu8; SEGMENT_HEADER_LENGTH];

fn nonce_range<A: AeadInOut>() -> Range<usize> {
    SEGMENT_HEADER_LENGTH..SEGMENT_HEADER_LENGTH + A::NonceSize::USIZE
}

fn tag_range<A: AeadInOut>(message_length: usize) -> Range<usize> {
    message_length - A::TagSize::USIZE..message_length
}

fn ciphertext_range<A: AeadInOut>(message_length: usize) -> Range<usize> {
    SEGMENT_HEADER_LENGTH + A::NonceSize::USIZE..message_length - A::TagSize::USIZE
}

pub(crate) struct Segment<'a, A>
where
    A: AeadInOut,
{
    pub(crate) header: [u8; SEGMENT_HEADER_LENGTH],
    pub(crate) nonce: Nonce<A>,
    pub(crate) ciphertext: &'a [u8],
    pub(crate) tag: Tag<A>,
}

impl<'a, A> Segment<'a, A>
where
    A: AeadInOut,
{
    pub(crate) fn from_bytes(message: &'a [u8], is_final: bool) -> Result<Self> {
        // TODO: Check the message length here.

        let header_slice = &message[HEADER_RANGE];
        let nonce = &message[nonce_range::<A>()];
        let tag = &message[tag_range::<A>(message.len())];

        let ciphertext = &message
            [SEGMENT_HEADER_LENGTH + A::NonceSize::USIZE..message.len() - A::TagSize::USIZE];

        let nonce = Nonce::<A>::from_iter(nonce.into_iter().map(|b| *b));
        let tag = Tag::<A>::from_iter(tag.into_iter().map(|b| *b));

        let mut header = [0u8; SEGMENT_HEADER_LENGTH];
        header.copy_from_slice(header_slice);

        let segment = Self {
            header,
            nonce,
            ciphertext,
            tag,
        };

        if is_final != segment.is_final() {
            todo!(
                "Error if the segment header tells us that the segment is final but the caller tells us otherwise"
            )
        }

        Ok(segment)
    }

    fn is_final(&self) -> bool {
        self.header != NON_FINAL_SEGMENT_HEADER
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
