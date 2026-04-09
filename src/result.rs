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

use thiserror::Error;

use crate::types::Parameters;

/// Error type for Floe decryption operations.
#[derive(Debug, Error)]
pub enum DecryptionError {
    /// The ciphertext couldn't be decrypted, most likely because the AEAD tag
    /// is invalid.
    #[error("the ciphertext couldn't be decrypted")]
    Aead(#[from] aead::Error),

    /// The header failed to be verified, the header tag is invalid.
    #[error("the Floe header contains an invalid tag")]
    InvalidHeaderTag,

    /// The given output buffer was either too big or too small.
    #[error("the output buffer has an incorrect length, expected: {expected}, got {got}")]
    InvalidBuffer {
        /// The expected output buffer size.
        expected: usize,
        /// The size of the buffer which was given to the decrypt method.
        got: usize,
    },

    /// The maximum number of segments was reached for this Floe decryption
    /// session.
    #[error("we have reached the maximal number of segments the configured AEAD supports ({0})")]
    MaxSegmentsReached(u64),

    /// The encrypted segment is malformed and couldn't be decrypted.
    ///
    /// This may happen because the segment is of an incorrect size for the
    /// configured decryptor or the segment claims to be the final segment
    /// while the caller stated otherwise.
    #[error("the given encrypted segment is malformed")]
    MalformedSegment,

    /// The parameters of the decryptor and the parameters defined in the header
    /// of the Floe ciphertext don't match.
    #[error(
        "the given header has different Floe parameters compared to what was configured \
        in the decryptor, expected: {expected:?}, got: {got:?}"
    )]
    InvalidParameters {
        /// The expected parameters, the one the decryptor was configured with.
        expected: Parameters,
        /// The parameters contained in the header.
        got: Parameters,
    },
}

/// Error type for Floe encryption operations.
#[derive(Debug, Error)]
pub enum EncryptionError {
    /// The AEAD couldn't encrypt the plaintext.
    #[error("the ciphertext couldn't be encrypted")]
    Aead(#[from] aead::Error),

    /// The maximum number of segments was reached for this Floe encryption
    /// session.
    #[error("we have reached the maximal number of segments the configured AEAD supports ({0})")]
    MaxSegmentsReached(u64),

    /// The given output buffer was either too big or too small.
    #[error("the output buffer has an incorrect length, expected: {expected}, got {got}")]
    InvalidBuffer {
        /// The expected output buffer size.
        expected: usize,
        /// The size of the buffer which was given to the encrypt method.
        got: usize,
    },

    /// The given plaintext has an incorrect length.
    #[error("the plaintext has an incorrect length, expected: {expected}, got {got}")]
    InvalidPlaintextLength {
        /// The expected plaintext length, as configured by the segment size.
        expected: usize,
        /// The plaintext length the encrypt method received.
        got: usize,
    },

    /// Encryption failed because a new random nonce for the segment couldn't be
    /// generated.
    #[error("the random nonce for the segment couldn't be generated")]
    NonceGenerationFailed,
}

/// Error type header decoding operations.
#[derive(Debug, Error)]
pub enum HeaderDecodeError {
    /// The given byte slice couldn't be decoded into a Floe header.
    ///
    /// The length of the byte-slice is invalid.
    #[error("the given header has an incorrect length, expected {expected}, got {got}")]
    InvalidLength {
        /// The expected size of slice containing a Floe header.
        expected: usize,
        /// The size of the slice we tried to decode.
        got: usize,
    },
}

/// Error type segment decoding operations.
#[derive(Debug, Error)]
pub enum SegmentDecodeError {
    /// The given byte slice couldn't be decoded into an encrypted segment.
    ///
    /// The length of the byte-slice is invalid.
    #[error(
        "the given slice is too small to be interpreted as a segment, expected at least {expected} bytes, got {got}"
    )]
    InvalidSliceLength {
        /// The minimal expected size of a segment.
        expected: usize,
        /// The size of the slice we tried to decode.
        got: usize,
    },

    /// The encrypted segment is malformed and couldn't be decoded.
    ///
    /// This may happen if the segment claims to be the final segment, but the
    /// length of the segment presented in the header is not correct.
    #[error("the given encrypted segment is malformed")]
    MalformedSegment,
}
