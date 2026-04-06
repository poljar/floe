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

mod helpers;

use crate::{gcm::FloeKey, test_vector, tests::helpers::encrypt_decrypt_single_segment};

#[test]
fn test_aes_gcm() {
    let plaintext = b"Hello world";
    encrypt_decrypt_single_segment::<64>(plaintext);
}

#[test]
fn test_aes_gcm_empty_plaintext() {
    let plaintext = b"";
    encrypt_decrypt_single_segment::<32>(plaintext);
}

#[test]
fn test_invalid_key_length() {
    let key = FloeKey::try_from([0u8; 33].as_slice());
    key.expect_err("We should not be able to create a floe KDF key with an invalid size");
}

test_vector!("rust_GCM256_IV256_64", 64);
test_vector!("rust_GCM256_IV256_4K", 4096);
test_vector!("rust_GCM256_IV256_1M", 1024 * 1024);

test_vector!("go_GCM256_IV256_64", 64);
test_vector!("go_GCM256_IV256_4K", 4096);
test_vector!("go_GCM256_IV256_1M", 1024 * 1024);

test_vector!("cpp_GCM256_IV256_64", 64);
test_vector!("cpp_GCM256_IV256_4K", 4096);
test_vector!("cpp_GCM256_IV256_1M", 1024 * 1024);

test_vector!("java_GCM256_IV256_64", 64);
test_vector!("java_GCM256_IV256_4K", 4096);
test_vector!("java_GCM256_IV256_1M", 1024 * 1024);

test_vector!("pub_java_GCM256_IV256_64", 64);
test_vector!("pub_java_GCM256_IV256_4K", 4096);
test_vector!("pub_java_GCM256_IV256_1M", 1024 * 1024);
test_vector!("java_lastSegAligned", 40);
test_vector!("java_lastSegEmpty", 40);

// TODO: We need to be able to specify a custom AEAD_ROTATION_MASK for the test
// vectors with a rotation suffix.
//
// create_test!("rust_rotation", 1024 * 1024);
