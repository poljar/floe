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

use aead::{AeadInOut, Generate, Key, KeyInit, Nonce, Result, rand_core::UnwrapErr};
use digest::typenum::Unsigned;
use rand::rngs::SysRng;

use crate::types::segment::{NON_FINAL_SEGMENT_HEADER, SEGMENT_HEADER_LENGTH, Segment, SegmentMut};

/// The key to encrypt or decrypt a segment.
///
/// The epoch key is derived on a per-segment basis from the [`crate::keys::MessageKey`].
/// This key is used as the input-key material for the AEAD, as such its length depends on the
/// picked AEAD.
///
/// The `AEAD_ROTATION_MASK` determines how many segments will use the same [`EpochKey`].
// TODO: Derive zeroize under a feature flag.
pub(crate) struct EpochKey<A>
where
    A: AeadInOut,
    A: KeyInit,
{
    /// The AEAD key used for encrypt or decrypt operations.
    pub(super) key: Key<A>,
    /// The number of the segment this [`EpochKey`] operates on.
    pub(super) segment_number: u64,
    /// Is this [`EpochKey`] used for the last segment?
    pub(super) is_final: bool,
}

impl<A: AeadInOut + KeyInit> EpochKey<A> {
    /// Encrypt a single segment using this [`EpochKey`].
    ///
    /// The segment needs to be prepared before this method is called. Namely the
    /// [`SegmentMut::ciphertext`] field needs to contain the plaintext. This will be in-place
    /// replaced with the ciphertext by the AEAD.
    ///
    /// The [`SegmentMut::header`], [`SegmentMut::nonce`], and [`SegmentMut::tag`] on the other hand
    /// will be filled out by this method.
    ///
    /// This implements the second part of the `encryptSegment` method from the [spec].
    ///
    /// # Panics
    ///
    /// Panics if the length of the [`SegmentMut::ciphertext`] and plaintext buffers aren't the
    /// same.
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    pub(crate) fn encrypt_segment(
        self,
        segment: SegmentMut<'_, A>,
        plaintext: &[u8],
    ) -> Result<()> {
        // Generate a new random AEAD nonce.
        // TODO: We should let the user provide the RNG?
        let mut rng = UnwrapErr(SysRng);
        let nonce = Nonce::<A>::generate_from_rng(&mut rng);

        // Create the AEAD and build the associated data for this segment.
        let aead = A::new(&self.key);
        let associated_data = self.build_segment_associated_data();

        // Now copy the plaintext into the ciphertext part of the output buffer, the AEAD will
        // replace the plaintext bytes in-place with the ciphertext bytes.
        //
        // We expect the caller to have checked that the buffer sizes are the same, otherwise we
        // panic here.
        let plaintext_buffer = segment.ciphertext;
        plaintext_buffer.copy_from_slice(plaintext);

        // Encrypt the plaintext and return the AEAD tag.
        let tag = aead
            .encrypt_inout_detached(&nonce, &associated_data, plaintext_buffer.into())
            .unwrap();

        // Calculate the correct header, depending on if the segment is final or not.
        //
        // If it's the final segment, we're putting the length of the segment into the header,
        // otherwise a static placeholder header is used.
        let header = if self.is_final {
            // TODO: This can overflow if someone sets the segment size to u32::MAX;
            let final_segment_length = SEGMENT_HEADER_LENGTH
                + A::NonceSize::USIZE
                + plaintext_buffer.len()
                + A::TagSize::USIZE;

            // TODO: We shouldn't just cast here.
            (final_segment_length as u32).to_be_bytes()
        } else {
            NON_FINAL_SEGMENT_HEADER
        };

        // Copy the rest of the important data into the segment.
        segment.header.copy_from_slice(&header);
        segment.nonce.copy_from_slice(&nonce);
        segment.tag.copy_from_slice(&tag);

        Ok(())
    }

    /// Decrypt a single segment using this [`EpochKey`].
    ///
    /// This implements the second part of the `decryptSegment` method from the [spec].
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    pub(crate) fn decrypt_segment(self, segment: &Segment<'_, A>, buffer: &mut [u8]) -> Result<()> {
        debug_assert_eq!(
            segment.ciphertext.len(),
            buffer.len(),
            "The ciphertext and output buffer for the plaintext should have the same size"
        );

        // Create the AEAD and build the associated data for this segment.
        let aead = A::new(&self.key);
        let associated_data = self.build_segment_associated_data();

        // Copy the ciphertext into the output buffer, the AEAD will replace the ciphertext with
        // the plaintext.
        buffer.copy_from_slice(segment.ciphertext);

        // Finally, decrypt the ciphertext.
        aead.decrypt_inout_detached(segment.nonce, &associated_data, buffer.into(), segment.tag)
    }

    /// Create an array of associated data for the segment encryption/decryption.
    ///
    /// This is not the same associated data the caller has given us. This associated data binds
    /// the segment number and whether the segment is the final one to the ciphertext.
    ///
    /// This implements a part of the `encryptSegment` and `decryptSegment` function from the [spec].
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    fn build_segment_associated_data(&self) -> [u8; 9] {
        let mut aad = [0u8; 9];

        // SAFETY: Casting a bool to an u8 [is fine]:
        //
        // > The bool represents a value, which could only
        // > be either true or false. If you cast a bool into an integer, true will be 1 and false
        // > will be 0.
        //
        // [is fine]: https://doc.rust-lang.org/std/primitive.bool.html
        let aad_tail = self.is_final as u8;

        aad[0..8].copy_from_slice(&self.segment_number.to_be_bytes());
        aad[8] = aad_tail;

        aad
    }
}
