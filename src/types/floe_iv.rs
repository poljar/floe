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

use aead::rand_core::UnwrapErr;
use rand::{Rng, rngs::SysRng};

// TODO: We could use `const N: u16` for the generics here, this would be enough
// for any IV someone would like to configure and would have `Into`
// implementations for `usize` as well as `u32`. This would ensure at compile
// time that the IV isn't too big. Sadly this requires the `generic_const_exprs`
// feature which is only available on Rust nightly.

/// The initialization vector of a Floe session.
///
/// This initialization vector is randomly generated at the start of the
/// encryption operation.
#[derive(Debug, Clone, Copy)]
pub struct FloeIv<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> FloeIv<N> {
    /// Create a new zero-initialized [`FloeIv`].
    ///
    /// This should only be used when we're parsing an existing [`FloeIv`] from
    /// a bytestring.
    pub(crate) fn from_slice(slice: &[u8]) -> Self {
        let mut floe_iv = Self { inner: [0u8; N] };
        floe_iv.inner.copy_from_slice(slice);

        floe_iv
    }

    /// Generate a new random [`FloeIv`].
    pub fn generate() -> Self {
        let mut rng = UnwrapErr(SysRng);
        let mut floe_iv = [0u8; N];
        rng.fill_bytes(&mut floe_iv);

        Self { inner: floe_iv }
    }

    /// Get the underlying raw byte array of this [`FloeIv`].
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.inner
    }
}
