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

#![cfg_attr(not(feature = "std"), no_std)]

mod keys;
mod result;
mod types;
mod utils;

pub mod random_access;

use aead::{AeadInOut, array::ArraySize};
use digest::{KeyInit, Mac};

pub use crate::{
    result::{DecryptionError, EncryptionError},
    types::{header::Header, segment::Segment},
};

pub trait FloeKdf: Mac + KeyInit {
    /// The length of the KDF key.
    ///
    /// This is called the `KDF_KEY_LEN` in the Floe [specification].
    ///
    /// [specification]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#parameters
    type KeySize: ArraySize;

    /// The unique numeric identifier of this KDF implementation.
    ///
    /// Will be used in the [Floe header] as part of the parameters.
    ///
    /// [Floe header]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#floe-ciphertext-layout
    const KDF_ID: u8;
}

pub trait FloeAead: AeadInOut + KeyInit {
    const AEAD_ID: u8;
    const AEAD_ROTATION_MASK: u64;
    const AEAD_MAX_SEGMENTS: u64;
}

#[cfg(feature = "floe-gcm")]
impl FloeKdf for hmac::Hmac<sha2::Sha384> {
    // As per the Floe spec defined in the derived parameters part:
    // https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#derived-parameters
    type KeySize = aead::consts::U48;
    const KDF_ID: u8 = 0;
}

#[cfg(feature = "floe-gcm")]
impl FloeAead for aes_gcm::Aes256Gcm {
    // As per the Floe spec defined in the derived parameters part:
    // https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#derived-parameters
    const AEAD_ID: u8 = 0;
    const AEAD_ROTATION_MASK: u64 = !((1u64 << 20) - 1);
    const AEAD_MAX_SEGMENTS: u64 = 1 << 40;
}

#[cfg(feature = "floe-gcm")]
// TODO: Put the FLOE_IV_LEN into the trait as well.

// TODO: Add the higher level public streaming/online functions
// https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#public-streamingonline-function

// TODO: Add methods where the user doesn't need to allocate buffers manually.
#[cfg(all(test, feature = "std", feature = "floe-gcm"))]
mod tests;
