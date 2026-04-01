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

use aead::Key;
use aes_gcm::Aes256Gcm;
use hmac::Hmac;
use sha2::Sha384;

use crate::{
    Header, Segment,
    random_access::{FloeDecryptor, FloeEncryptor},
};

type HmacSha384 = Hmac<Sha384>;

type FloeEncryptorAesGcm = FloeEncryptor<'static, Aes256Gcm, HmacSha384, 32, 64>;
type FloeDecryptorAesGcm = FloeDecryptor<'static, Aes256Gcm, HmacSha384, 32, 64>;

/// Helper to read and decode a test vector.
fn read_hex_file(file_name: &str) -> Vec<u8> {
    let data = std::fs::read_to_string(file_name).expect("should be able to read the test vector");

    hex::decode(data.trim()).expect("should be able to decode the test vector")
}

#[test]
fn test_aes_gcm() {
    let key = Key::<Aes256Gcm>::try_from([0u8; 32].as_slice()).unwrap();
    let encryptor = FloeEncryptorAesGcm::new(&key, &[]);

    let plaintext = b"Hello world";
    let output_size = encryptor.output_size(plaintext);
    let mut buffer = vec![0u8; output_size];

    encryptor
        .encrypt_segment(plaintext, &mut buffer, 0, true)
        .expect("We should be able to encrypt the segment");

    let header = encryptor.header();

    let decryptor = FloeDecryptorAesGcm::new(&key, &[], header).unwrap();

    let mut decryption_buffer = vec![0u8; 11];

    let segment = Segment::from_bytes(&buffer).expect("We should be able to parse the segment");

    decryptor
        .decrypt_segment(&segment, &mut decryption_buffer, 0, true)
        .unwrap();

    assert_eq!(
        plaintext.as_slice(),
        decryption_buffer,
        "The decrypted plaintext should match the original plaintext"
    );
}

#[test]
fn test_invalid_key_length() {
    let key = Key::<HmacSha384>::try_from([0u8; 33].as_slice());
    key.expect_err("We should not be able to create a floe KDF key with an invalid size");
}

#[test]
fn test_vectors() {
    const AAD: &[u8] = b"This is AAD";

    let plaintext = read_hex_file("test-vectors/rust_GCM256_IV256_64_pt.txt");
    let ciphertext = read_hex_file("test-vectors/rust_GCM256_IV256_64_ct.txt");

    let header_length = Header::<32>::length();
    let header_bytes = &ciphertext[..header_length];
    let header = Header::from_bytes(header_bytes).expect("should be able to decode the header");

    let key = Key::<Aes256Gcm>::try_from([0u8; 32].as_slice())
        .expect("should be able to create a zero key");
    let decryptor = FloeDecryptorAesGcm::new(&key, AAD, &header).unwrap();

    let mut decrypted: Vec<u8> = vec![];
    let mut plaintext_segment = vec![0u8; FloeDecryptorAesGcm::plaintext_size()];
    let segments = ciphertext[header_length..].chunks(64);
    let num_segments = segments.len();

    for (segment_number, segment) in segments.enumerate() {
        let is_final = segment_number == num_segments - 1;

        let segment = Segment::from_bytes(segment).expect("We should be able to parse the segment");

        assert_eq!(is_final, segment.is_final());

        let buffer = &mut plaintext_segment[..segment.plaintext_size()];

        decryptor
            .decrypt_segment(&segment, buffer, segment_number as u64, is_final)
            .expect("should be able to decrypt the segment");

        decrypted.extend_from_slice(buffer);
    }

    assert_eq!(
        plaintext, decrypted,
        "The decrypted plaintext should match the original"
    );
}
