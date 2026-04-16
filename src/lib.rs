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

// TODO: Add the higher level public streaming/online functions
// https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#public-streamingonline-function

// TODO: Add methods where the user doesn't need to allocate buffers manually.

// TODO: Add a higher level interface which uses std::io::Read

mod keys;
mod result;
mod traits;
mod utils;

#[cfg(feature = "floe-gcm")]
pub mod gcm;
pub mod random_access;
pub mod types;

pub use crate::{
    result::{DecryptionError, EncryptionError, HeaderDecodeError, SegmentDecodeError},
    traits::{FloeAead, FloeKdf},
};

#[cfg(all(test, feature = "std", feature = "floe-gcm", feature = "getrandom"))]
mod tests;
