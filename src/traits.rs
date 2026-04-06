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

use aead::{AeadInOut, array::ArraySize};
use digest::{KeyInit, Mac};

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
    /// The unique numeric identifier of this AEAD implementation.
    ///
    /// Will be used in the [Floe header] as part of the parameters.
    ///
    /// [Floe header]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#floe-ciphertext-layout
    const AEAD_ID: u8;

    const AEAD_ROTATION_MASK: u64;

    const AEAD_MAX_SEGMENTS: u64;
}
