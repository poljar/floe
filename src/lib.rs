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
mod types;
mod utils;

pub mod random_access;

use aead::{array::ArraySize, consts::U48};
use digest::{KeyInit, Mac};
use hmac::Hmac;
use sha2::Sha384;

pub use types::{header::Header, segment::Segment};

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

impl FloeKdf for Hmac<Sha384> {
    // As per the Floe spec defined in the derived parameters part:
    // https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#derived-parameters
    type KeySize = U48;
    const KDF_ID: u8 = 0;
}

// TODO: Add a similar trait for the AEAD as we need to encode the AEAD_ID, AEAD_ROTATION_MASK,
// AEAD_MAX_SEGMENTS .
// TODO: Should we put the FLOE_IV_LEN into the trait as well?

// TODO: Add the higher level public streaming/online functions
// https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#public-streamingonline-function
//
// TODO: Additionally add methods where the user doesn't need to allocate buffers.

#[cfg(all(test, feature = "std"))]
mod tests;
