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

use aead::{array::Array, consts::U32};
use digest::typenum::Unsigned;
use subtle::ConstantTimeEq;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The size of the header tag.
pub(crate) type HeaderTagSize = U32;

#[derive(Debug, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct HeaderTag {
    pub(crate) inner: Array<u8, HeaderTagSize>,
}

impl HeaderTag {
    pub fn as_bytes(&self) -> &[u8; HeaderTagSize::USIZE] {
        #[allow(clippy::expect_used)]
        self.inner.as_array().expect("We should be able to convert the Array to a primitive array")
    }
}

impl ConstantTimeEq for HeaderTag {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}
