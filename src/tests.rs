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

use pastey::paste;

use crate::{
    Segment,
    gcm::{FloeDecryptor, FloeEncryptor, FloeKey, Header},
};

/// Helper to read and decode a test vector.
fn read_hex_file(file_name: &str) -> Vec<u8> {
    #[allow(clippy::expect_used)]
    let data = std::fs::read_to_string(file_name).expect("should be able to read the test vector");

    #[allow(clippy::expect_used)]
    hex::decode(data.trim()).expect("should be able to decode the test vector")
}

fn encrypt_decrypt_single_segment<const S: u32>(plaintext: &[u8]) {
    assert!(plaintext.len() <= S as usize);

    let key = FloeKey::from([0u8; 32]);
    let encryptor = FloeEncryptor::<S>::new(&key, &[]);

    let output_size = encryptor.output_size(plaintext);
    let mut buffer = vec![0u8; output_size];

    encryptor
        .encrypt_segment(plaintext, &mut buffer, 0, true)
        .expect("We should be able to encrypt the segment");

    let decryptor = FloeDecryptor::<S>::new(&key, &[], encryptor.header()).unwrap();

    let segment = Segment::from_bytes(&buffer).expect("We should be able to parse the segment");
    let mut decryption_buffer = vec![0u8; segment.plaintext_size()];

    decryptor.decrypt_segment(&segment, &mut decryption_buffer, 0, true).unwrap();

    assert_eq!(
        plaintext, decryption_buffer,
        "The decrypted plaintext should match the original plaintext"
    );
}

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

fn decrypt_test_vector<const S: u32>(ciphertext: &[u8], plaintext: &[u8]) {
    const AAD: &[u8] = b"This is AAD";

    let header_length = Header::length();
    let header_bytes = &ciphertext[..header_length];

    #[allow(clippy::expect_used)]
    let header = Header::from_bytes(header_bytes).expect("should be able to decode the header");

    #[allow(clippy::expect_used)]
    let key = FloeKey::try_from([0u8; 32].as_slice()).expect("should be able to create a zero key");
    #[allow(clippy::unwrap_used)]
    let decryptor = FloeDecryptor::<S>::new(&key, AAD, &header).unwrap();

    let mut decrypted: Vec<u8> = vec![];
    let mut plaintext_segment = vec![0u8; decryptor.plaintext_size()];
    let segments = ciphertext[header_length..].chunks(S as usize);
    let num_segments = segments.len();

    for (segment_number, segment) in segments.enumerate() {
        let is_final = segment_number == num_segments - 1;
        #[allow(clippy::expect_used)]
        let segment = Segment::from_bytes(segment).expect("We should be able to parse the segment");

        assert_eq!(is_final, segment.is_final());

        let buffer = &mut plaintext_segment[..segment.plaintext_size()];

        #[allow(clippy::expect_used)]
        decryptor
            .decrypt_segment(&segment, buffer, segment_number as u64, is_final)
            .expect("should be able to decrypt the segment");

        decrypted.extend_from_slice(buffer);
    }

    assert_eq!(plaintext, decrypted, "The decrypted plaintext should match the original");
}

macro_rules! create_test {
    ($file:literal, $segment_size:expr) => {
        paste! {
            #[test]
            fn [< # test_$file:lower >]() {
                const SEGMENT_SIZE: u32 = $segment_size;

                let ciphertext = read_hex_file(&format!("test-vectors/{}_ct.txt", $file));
                let plaintext = read_hex_file(&format!("test-vectors/{}_pt.txt", $file));

                decrypt_test_vector::<SEGMENT_SIZE>(&ciphertext, &plaintext);
            }
        }
    };
}

create_test!("rust_GCM256_IV256_64", 64);
create_test!("rust_GCM256_IV256_4K", 4096);
create_test!("rust_GCM256_IV256_1M", 1024 * 1024);

create_test!("go_GCM256_IV256_64", 64);
create_test!("go_GCM256_IV256_4K", 4096);
create_test!("go_GCM256_IV256_1M", 1024 * 1024);

create_test!("cpp_GCM256_IV256_64", 64);
create_test!("cpp_GCM256_IV256_4K", 4096);
create_test!("cpp_GCM256_IV256_1M", 1024 * 1024);

create_test!("java_GCM256_IV256_64", 64);
create_test!("java_GCM256_IV256_4K", 4096);
create_test!("java_GCM256_IV256_1M", 1024 * 1024);

create_test!("pub_java_GCM256_IV256_64", 64);
create_test!("pub_java_GCM256_IV256_4K", 4096);
create_test!("pub_java_GCM256_IV256_1M", 1024 * 1024);
create_test!("java_lastSegAligned", 40);
create_test!("java_lastSegEmpty", 40);

// TODO: We need to be able to specify a custom AEAD_ROTATION_MASK for the test
// vectors with a rotation suffix.
//
// create_test!("rust_rotation", 1024 * 1024);
