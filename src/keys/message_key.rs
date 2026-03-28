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

use std::{marker::PhantomData, ops::Sub};

use crate::{FloeKdf, keys::FloeKdfKey, types::FloeIv, utils::encoded_parameters};

use aead::{
    AeadInOut, KeySizeUser,
    array::{Array, ArraySize},
};
use digest::{KeyInit, OutputSizeUser};

use super::epoch_key::EpochKey;

// TODO: Derive zeroize under a feature flag.
pub struct MessageKey<A, H>
where
    A: AeadInOut + KeyInit,
    H: FloeKdf,
{
    pub(super) key: FloeKdfKey<H>,
    pub(super) _phantom_aead: PhantomData<A>,
    pub(super) _phantom: PhantomData<H>,
}

impl<A, H> MessageKey<A, H>
where
    A: AeadInOut + KeyInit,
    H: FloeKdf,
{
    pub(crate) fn derive_epoch_key<const N: usize, const S: u32>(
        &self,
        floe_iv: &FloeIv<N>,
        associated_data: &[u8],
        segment_number: u64,
        is_final: bool,
    ) -> EpochKey<A>
    where
        <H as OutputSizeUser>::OutputSize: Sub<<A as KeySizeUser>::KeySize>,
        <<H as OutputSizeUser>::OutputSize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize,
    {
        // TODO: Make the rotation mask configurable.
        const ROTATION_MASK: u64 = !((1u64 << 20) - 1);

        let masked_counter = segment_number & ROTATION_MASK;

        let mut purpose = [0u8; 12];
        purpose[..4].copy_from_slice(b"DEK:");
        purpose[4..].copy_from_slice(&masked_counter.to_be_bytes());

        let output = <H as KeyInit>::new_from_slice(&self.key)
            .unwrap()
            .chain_update(encoded_parameters::<N, S>())
            .chain_update(floe_iv.as_bytes())
            .chain_update(purpose)
            .chain_update(associated_data)
            .chain_update(&[1])
            .finalize();

        let (key, _) = Array::split::<<A as KeySizeUser>::KeySize>(output.into_bytes());

        EpochKey {
            key,
            segment_number,
            is_final,
        }
    }
}
