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

use aead::{AeadCore, AeadInOut, Nonce, Tag, array::ArraySize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

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

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct InnerSegment<A>
where
    A: AeadInOut,
{
    header: [u8; SEGMENT_HEADER_LENGTH],
    nonce: Nonce<A>,
    ciphertext: [u8],
}

pub struct Segment<'a, A>
where
    A: AeadInOut,
    <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
    <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
{
    pub(crate) header: &'a [u8; SEGMENT_HEADER_LENGTH],
    pub(crate) nonce: &'a Nonce<A>,
    pub(crate) ciphertext: &'a [u8],
    pub(crate) tag: &'a Tag<A>,
}

impl<'a, A> Segment<'a, A>
where
    A: AeadInOut + 'a,
    <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
    <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
{
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, SegmentDecodeError> {
        let invalid_length_err = || SegmentDecodeError::InvalidSliceLength {
            expected: segment_overhead::<A>(),
            got: bytes.len(),
        };

        let (rest, tag) = Tag::<A>::ref_from_suffix(bytes).map_err(|_| invalid_length_err())?;
        let InnerSegment { header, nonce, ciphertext } =
            InnerSegment::<A>::ref_from_bytes(rest).map_err(|_| invalid_length_err())?;

        let segment = Segment { header, nonce, ciphertext, tag };

        if segment.is_final() {
            let length: usize = u32::from_be_bytes(*segment.header)
                .try_into()
                .map_err(|_| SegmentDecodeError::MalformedSegment)?;

            if length != bytes.len() {
                return Err(SegmentDecodeError::MalformedSegment);
            }
        }

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
    A: AeadInOut + 'a,
{
    pub(crate) const fn output_size(plaintext: &[u8]) -> usize {
        plaintext.len() + segment_overhead::<A>()
    }

    pub(crate) fn from_buffer_and_plaintext(
        plaintext: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<Self, EncryptionError>
    where
        <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + IntoBytes + Immutable,
        <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>:
            FromBytes + IntoBytes + Unaligned + Immutable,
    {
        let buffer_length = buffer.len();
        let invalid_length_err = || EncryptionError::InvalidBuffer {
            expected: Self::output_size(plaintext),
            got: buffer_length,
        };

        let (rest, tag) = Tag::<A>::mut_from_suffix(buffer).map_err(|_| invalid_length_err())?;

        let InnerSegment { header, nonce, ciphertext } =
            InnerSegment::<A>::mut_from_bytes(rest).map_err(|_| invalid_length_err())?;

        let segment = SegmentMut { header, nonce, ciphertext, tag };

        // Now copy the plaintext into the ciphertext part of the output buffer, the
        // AEAD will later replace the plaintext bytes in-place with the
        // ciphertext bytes.
        segment.ciphertext.copy_from_slice(plaintext);

        Ok(segment)
    }
}
