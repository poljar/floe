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

use aead::{AeadCore, Key};
use digest::KeyInit;
use zerocopy::IntoBytes;

use crate::{FloeAead, FloeIv, FloeKdf, Parameters, Segment};

pub(crate) fn plaintext_size<A, const S: u32>() -> usize
where
    A: AeadCore,
{
    #[allow(clippy::expect_used)]
    (TryInto::<usize>::try_into(S).expect("The encrypted segment size should fit into a u32"))
        .checked_sub(Segment::<'static, A>::overhead())
        .expect("The encrypted segment size should be bigger than the segment overhead")
}

/// Check the user-provided encrypted segment size has left enough space for the
/// segment header an encrypted segment requires.
///
/// # Panics
///
/// The size of an encrypted segment is limited by the fact that the length of
/// the final segment needs to put into the segment header. The length of the
/// final segment is converted into a `u32` and encoded into 4 bytes as a
/// big-endian value.
///
/// This limits the size of the plaintext segment into `u32::MAX -
/// segment_overhead()`.
///
/// The function will panic if the segment size (S) is bigger than this limit.
/// Realistically, nobody will pick [`u32::MAX`] bytes for the segment size.
/// This would be a 4GiB segment size.
pub(crate) fn check_segment_size<A, const S: u32>()
where
    A: AeadCore,
{
    #[allow(clippy::panic)]
    if S > u32::MAX - (Segment::<A>::overhead() as u32) {
        panic!("Segment size is too large, the length of the segment doesn't fit into a u32");
    } else if TryInto::<usize>::try_into(S).is_err() {
        panic!("Segment size is too large, the length of the segment doesn't fit into a usize");
    } else if S < ((Segment::<A>::overhead()) as u32) {
        panic!(
            "Segment size is too small, the segment doesn't have enough space for the segment header"
        );
    }
}

pub(crate) fn floe_kdf<A, K, const N: usize, const S: u32>(
    key: &Key<A>,
    floe_iv: &FloeIv<N>,
    associated_data: &[u8],
    purpose: &[u8],
) -> digest::CtOutput<K>
where
    A: FloeAead,
    K: FloeKdf,
{
    let params = Parameters::new::<A, K, N, S>();

    // TODO: This should probably use the Hkdf crate to make it more clear that this
    // should be a KDF, not a MAC. Shouldn't matter for correctness as we're
    // partially reimplementing HKDF and not asking for too much output, but
    // would make this more obvious.

    #[allow(clippy::expect_used)]
    <K as KeyInit>::new_from_slice(key)
        .expect(
            "the KDF input key material should be big enough as this is determined by AEAD_KEY_LEN",
        )
        .chain_update(params.as_bytes())
        .chain_update(floe_iv.as_array())
        .chain_update(purpose)
        .chain_update(associated_data)
        .chain_update([1])
        .finalize()
}
