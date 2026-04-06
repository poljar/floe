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
#[cfg(feature = "getrandom")]
use getrandom::SysRng;
use rand_core::CryptoRng;
#[cfg(feature = "getrandom")]
use rand_core::UnwrapErr;
use zerocopy::{FromBytes, Immutable, IntoBytes, Unaligned};

use crate::{
    EncryptionError, FloeAead, FloeKdf, Header,
    keys::{FloeKey, MessageKey},
    types::{floe_iv::FloeIv, segment::SegmentMut},
    utils::{check_segment_size, plaintext_size},
};

/// Exposes the FLOE random-access encryption APIs.
///  
/// The random-access APIs do not directly protect you against truncation
/// attacks or prevent you from incorrectly encrypting the same segment multiple
/// times.
pub struct FloeEncryptor<'a, A, H, const N: usize, const S: u32>
where
    A: FloeAead,
    H: FloeKdf,
{
    /// The header of the Floe session.
    header: Header<A, H, N>,
    /// The user-provided additional associated data.
    associated_data: &'a [u8],
    /// The message key, used to derive the AEAD key for the segments.
    message_key: MessageKey<A, H>,
}

impl<'a, A, H, const N: usize, const S: u32> FloeEncryptor<'a, A, H, N, S>
where
    A: FloeAead,
    H: FloeKdf,
    <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable + IntoBytes,
    <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>:
        FromBytes + Immutable + IntoBytes + Unaligned,
    <H as OutputSizeUser>::OutputSize: Sub<<A as KeySizeUser>::KeySize>,
    <<H as OutputSizeUser>::OutputSize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize,
    <H as OutputSizeUser>::OutputSize: Sub<U32>,
    <<H as OutputSizeUser>::OutputSize as Sub<U32>>::Output: ArraySize,
    <H as OutputSizeUser>::OutputSize: Sub<<H as FloeKdf>::KeySize>,
    <<H as OutputSizeUser>::OutputSize as Sub<<H as FloeKdf>::KeySize>>::Output: ArraySize,
{
    #[cfg(feature = "getrandom")]
    pub fn new(key: &Key<A>, associated_data: &'a [u8]) -> Self {
        #[allow(clippy::expect_used)]
        Self::with_rng(key, associated_data, &mut UnwrapErr(SysRng))
            .expect("should be able to generate enough randomness for the Floe IV")
    }

    pub fn with_rng<R: CryptoRng>(
        key: &Key<A>,
        associated_data: &'a [u8],
        rng: &mut R,
    ) -> Result<Self, R::Error> {
        check_segment_size::<A, S>();

        let floe_key = FloeKey::new(key);
        let floe_iv = FloeIv::generate(rng)?;

        let header_tag = floe_key.derive_header_tag::<N, S>(&floe_iv, associated_data);
        let message_key = floe_key.derive_message_key::<N, S>(&floe_iv, associated_data);

        let header = Header::new::<S>(floe_iv, header_tag);

        Ok(Self { message_key, header, associated_data })
    }

    pub fn input_size(&self) -> usize {
        // SAFETY: The constructor of the FloeEncryptor checks that the segment size
        // fits into an usize and that it's bigger than the overhead.
        plaintext_size::<A, S>()
    }

    pub fn output_size(&self, plaintext: &[u8]) -> usize {
        assert!(
            plaintext.len() <= self.input_size(),
            "The plaintext size can't be bigger than the input size"
        );

        SegmentMut::<A>::output_size(plaintext)
    }

    /// Get the header of this Floe encryption session.
    ///
    /// The header is usually prepended to the first encrypted segment. It will
    /// be needed to start decrypting segments.
    pub fn header(&self) -> &Header<A, H, N> {
        &self.header
    }

    #[cfg(feature = "getrandom")]
    pub fn encrypt_segment(
        &self,
        plaintext: &[u8],
        buffer: &mut [u8],
        segment_number: u64,
        is_final: bool,
    ) -> Result<(), EncryptionError> {
        let mut rng = UnwrapErr(SysRng);
        self.encrypt_segment_with_rng(plaintext, buffer, segment_number, is_final, &mut rng)
    }

    pub fn encrypt_segment_with_rng<R>(
        &self,
        plaintext: &[u8],
        buffer: &mut [u8],
        segment_number: u64,
        is_final: bool,
        rng: &mut R,
    ) -> Result<(), EncryptionError>
    where
        R: CryptoRng,
    {
        let allowed_plaintext_length = self.input_size();
        let plaintext_length = plaintext.len();

        if is_final {
            if plaintext_length > allowed_plaintext_length {
                return Err(EncryptionError::InvalidPlaintextLength {
                    expected: allowed_plaintext_length,
                    got: plaintext_length,
                });
            }

            if segment_number >= A::AEAD_MAX_SEGMENTS {
                return Err(EncryptionError::MaxSegmentsReached(A::AEAD_MAX_SEGMENTS));
            }
        } else {
            if plaintext_length != allowed_plaintext_length {
                return Err(EncryptionError::InvalidPlaintextLength {
                    expected: allowed_plaintext_length,
                    got: plaintext_length,
                });
            }

            if segment_number >= (A::AEAD_MAX_SEGMENTS - 1) {
                return Err(EncryptionError::MaxSegmentsReached(A::AEAD_MAX_SEGMENTS));
            }
        }

        // Parse the output buffer as a SegmentMut, this copies the plaintext into the
        // output buffer as well.
        let segment = SegmentMut::from_buffer_and_plaintext(plaintext, buffer)?;

        // Now we derive an epoch key for this segment.
        let epoch_key = self.message_key.derive_epoch_key::<N, S>(
            self.header.iv(),
            self.associated_data,
            segment_number,
            is_final,
        );

        // And finally we encrypt the segment.
        epoch_key.encrypt_segment(segment, rng)
    }
}
