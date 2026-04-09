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

use core::num::NonZero;

use aead::{AeadInOut, array::ArraySize};
use digest::{KeyInit, Mac};

/// Trait for any Floe-compatible KDF implementation.
///
/// This is almost a marker trait. The trait does not provide any functions it
/// only defines constants a Floe-compatible KDF implementation should use.
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

/// Trait for any Floe-compatible AEAD implementation.
///
/// This is almost a marker trait. The trait does not provide any functions it
/// only defines constants a Floe-compatible AEAD implementation should use.
pub trait FloeAead: AeadInOut + KeyInit {
    /// The unique numeric identifier of this AEAD implementation.
    ///
    /// Will be used in the [Floe header] as part of the parameters.
    ///
    /// [Floe header]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#floe-ciphertext-layout
    const AEAD_ID: u8;

    /// A non-negative integer value designating how many segments can be
    /// encrypted before deriving a new encryption key.
    ///
    /// Specifically, 2^AEAD_ROTATION_MASK segments are encrypted under a single
    /// key.
    const AEAD_ROTATION_MASK: u64;

    /// The maximum number of segments in a Floe ciphertext.
    const AEAD_MAX_SEGMENTS: NonZero<u64>;
}
