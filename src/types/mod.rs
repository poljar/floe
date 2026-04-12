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

//! Data types for the generic Floe implementation.

pub(crate) mod floe_iv;
pub(crate) mod header;
pub(crate) mod segment;

pub use floe_iv::FloeIv;
pub use header::{Header, parameters::Parameters, tag::HeaderTag};
pub use segment::Segment;

/// Type alias for the encrypted segment size.
///
/// The encrypted segment size is expressed as an [`u32`].
pub type SegmentSize = u32;
