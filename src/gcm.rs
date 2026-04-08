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

//! Implementation of Floe using the AES-GCM variant.
//!
//! The crate offers a generic Floe implementation. This module specializes it
//! by providing type aliases for the GCM-based variant.

use aead::{Key, consts::U48};
use aes_gcm::Aes256Gcm;
use hmac::Hmac;
use sha2::Sha384;

use crate::{FloeAead, FloeKdf};

const FLOE_IV_LENGTH: usize = 32;

impl FloeKdf for Hmac<Sha384> {
    // As per the Floe spec defined in the derived parameters part:
    // https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#derived-parameters
    type KeySize = U48;
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

pub type Header = crate::types::Header<FLOE_IV_LENGTH>;

pub type FloeKey = Key<Aes256Gcm>;

/// Attempt to decode a slice of bytes as a Floe-Gcm [`Segment`]
///
/// *Note*: This only attempts to reinterpret the bytes as a valid
/// [`Segment`], as such it does not copy any data.
///
/// # Examples
///
/// ```no_run
/// use floe_rs::gcm::Segment;
///
/// # let bytes: &[u8] = unimplemented!();
/// let segment = Segment::from_bytes(bytes)?;
/// let buffer = vec![0u8; segment.plaintext_size()];
///
/// // Now you can attempt to decrypt the segment.
/// # Ok::<(), anyhow::Error>(())
/// ```
pub type Segment<'a> = crate::types::segment::Segment<'a, Aes256Gcm>;
