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

use core::{marker::PhantomData, ops::Sub};

use aead::{
    KeySizeUser,
    array::{Array, ArraySize},
};
use digest::{KeyInit, OutputSizeUser};
use zerocopy::IntoBytes;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use super::epoch_key::EpochKey;
use crate::{
    FloeAead, FloeKdf,
    keys::FloeKdfKey,
    types::{AeadRotationMask, FloeIv, Parameters, SegmentSize},
};

/// The [`MessageKey`] of a Floe session.
///
/// The message key is used as the root key for deriving the per-segment
/// [`EpochKey`]s. The message key itself is derived from the
/// [`crate::keys::FloeKey`].
///
/// The length of this key is determined by the picked KDF and defined in the
/// `KDF_KEY_LEN` constant in the spec, or in the [`FloeKdf::KeySize`] type in
/// this implementation.
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub(crate) struct MessageKey<A, H>
where
    A: FloeAead,
    H: FloeKdf,
{
    pub(super) key: FloeKdfKey<H>,
    pub(super) _phantom_aead: PhantomData<A>,
    pub(super) _phantom: PhantomData<H>,
}

impl<A, K> MessageKey<A, K>
where
    A: FloeAead,
    K: FloeKdf,
{
    /// Create an [`EpochKey`] for the given segment.
    ///
    /// This implements the `DERIVE_KEY()` function from the [spec], defined as:
    ///
    /// ```text
    /// FLOE_KDF(key, iv, aad, "DEK:" || I2BE(MASK(segmentNumber, AEAD_ROTATION_MASK), 8), AEAD_KEY_LEN)
    /// ```
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#internal-functions
    pub(crate) fn derive_epoch_key<const N: usize, const S: SegmentSize>(
        &self,
        floe_iv: &FloeIv<N>,
        associated_data: &[u8],
        segment_number: u64,
        rotation_mask: AeadRotationMask,
        is_final: bool,
    ) -> EpochKey<A>
    where
        <K as OutputSizeUser>::OutputSize: Sub<<A as KeySizeUser>::KeySize>,
        <<K as OutputSizeUser>::OutputSize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize,
    {
        // The rotation mask decides how many segments will be encrypted using the same
        // epoch key.
        let masked_counter = segment_number & rotation_mask;

        // The purpose will include the segment number, this binds the key to this
        // specific segment.
        let mut purpose = [0u8; 12];
        purpose[..4].copy_from_slice(b"DEK:");
        purpose[4..].copy_from_slice(&masked_counter.to_be_bytes());

        let parameters = Parameters::new::<A, K, N, S>();

        // We're not reusing the `crate::utils::floe_kdf` function here for type safety
        // reasons. We're using the `FloeKdfKey<H>` here, while the `floe_kdf`
        // function expects a `Key<A>`.
        #[allow(clippy::expect_used)]
        let output = <K as KeyInit>::new_from_slice(&self.key)
            .expect(
                "the KDF input key material should be big enough as this is determined \
                 by KDF_KEY_LEN parameter",
            )
            .chain_update(parameters.as_bytes())
            .chain_update(floe_iv.as_array())
            .chain_update(purpose)
            .chain_update(associated_data)
            .chain_update([1])
            .finalize();

        // Split the output. The key will reuse the same memory the original output
        // used, avoiding any copying. We discard the rest of the output.
        let (key, mut _rest) = Array::split::<<A as KeySizeUser>::KeySize>(output.into_bytes());

        #[cfg(feature = "zeroize")]
        _rest.zeroize();

        EpochKey { key, segment_number, is_final }
    }
}
