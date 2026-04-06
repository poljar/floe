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

use crate::Parameters;

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("the ciphertext couldn't be decrypted")]
    Aead(#[from] aead::Error),

    #[error("the Floe header contains an invalid tag")]
    InvalidHeaderTag,

    #[error("the output buffer has an incorrect length, expected: {expected}, got {got}")]
    InvalidBuffer { expected: usize, got: usize },

    #[error("the ciphertext has an incorrect length, expected: {expected}, got {got}")]
    InvalidCiphertextLength { expected: usize, got: usize },

    #[error("we have reached the maximal number of segments the configured AEAD supports ({0})")]
    MaxSegmentsReached(u64),

    #[error("the segment is too big")]
    MalformedSegment,

    #[error(
        "the given header has different Floe parameters compared to what was configured \
        in the decryptor, expected: {expected:?}, got: {got:?}"
    )]
    InvalidParameters { expected: Parameters, got: Parameters },
}

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("the ciphertext couldn't be decrypted")]
    Aead(#[from] aead::Error),

    #[error("we have reached the maximal number of segments the configured AEAD supports ({0})")]
    MaxSegmentsReached(u64),

    #[error("the output buffer has an incorrect length, expected: {expected}, got {got}")]
    InvalidBuffer { expected: usize, got: usize },

    #[error("the plaintext has an incorrect length, expected: {expected}, got {got}")]
    InvalidPlaintextLength { expected: usize, got: usize },

    #[error("the random nonce for the segment couldn't be generated")]
    NonceGenerationFailed,
}

#[derive(Debug, Error)]
pub enum HeaderDecodeError {
    #[error("the given header has an incorrect length, expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

#[derive(Debug, Error)]
pub enum SegmentDecodeError {
    #[error(
        "the given slice is too small to be interpreted as a segment, expected at least {expected} bytes, got {got}"
    )]
    InvalidSliceLength { expected: usize, got: usize },

    #[error("the segment is corrupted")]
    MalformedSegment,
}
