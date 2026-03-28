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

#[derive(Debug, Clone, Copy)]
pub struct FloeIv<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> FloeIv<N> {
    pub(crate) fn new() -> Self {
        Self { inner: [0u8; N] }
    }

    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.inner
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.inner
    }

    pub fn generate() -> Self {
        let mut rng = UnwrapErr(SysRng);
        let mut floe_iv = [0u8; N];
        rng.fill_bytes(&mut floe_iv);

        Self { inner: floe_iv }
    }
}
