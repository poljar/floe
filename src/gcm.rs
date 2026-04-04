// Copyright 2026 Damir Jelić.
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

use aead::Key;
use aes_gcm::Aes256Gcm;
use hmac::Hmac;
use sha2::Sha384;

use crate::{FloeAead, FloeKdf};

const FLOE_IV_LENGTH: usize = 32;

impl FloeKdf for Hmac<Sha384> {
    // As per the Floe spec defined in the derived parameters part:
    // https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#derived-parameters
    type KeySize = aead::consts::U48;
    const KDF_ID: u8 = 0;
}

impl FloeAead for Aes256Gcm {
    // As per the Floe spec defined in the derived parameters part:
    // https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#derived-parameters
    const AEAD_ID: u8 = 0;
    const AEAD_ROTATION_MASK: u64 = !((1u64 << 20) - 1);
    const AEAD_MAX_SEGMENTS: u64 = 1 << 40;
}

pub type FloeEncryptor<'a, const S: u32> =
    crate::random_access::FloeEncryptor<'a, Aes256Gcm, Hmac<Sha384>, FLOE_IV_LENGTH, S>;

pub type FloeDecryptor<'a, const S: u32> =
    crate::random_access::FloeDecryptor<'a, Aes256Gcm, Hmac<Sha384>, FLOE_IV_LENGTH, S>;

pub type Header<const S: u32> = crate::Header<Aes256Gcm, Hmac<Sha384>, FLOE_IV_LENGTH, S>;

pub type FloeKey = Key<Aes256Gcm>;
