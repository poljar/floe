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

use crate::{
    Segment,
    gcm::{FloeDecryptor, FloeEncryptor, FloeKey, Header},
};

#[macro_export]
macro_rules! test_vector {
    ($file:literal, $segment_size:expr) => {
        pastey::paste! {
            #[test]
            fn [< # test_$file:lower >]() {
                const SEGMENT_SIZE: u32 = $segment_size;

                let ciphertext = $crate::tests::helpers::read_hex_file(&format!("test-vectors/{}_ct.txt", $file));
                let plaintext = $crate::tests::helpers::read_hex_file(&format!("test-vectors/{}_pt.txt", $file));

                $crate::tests::helpers::decrypt_test_vector::<SEGMENT_SIZE>(&ciphertext, &plaintext);
            }
        }
    };
}

/// Helper to read and decode a test vector.
pub(super) fn read_hex_file(file_name: &str) -> Vec<u8> {
    #[allow(clippy::expect_used)]
    let data = std::fs::read_to_string(file_name).expect("should be able to read the test vector");

    #[allow(clippy::expect_used)]
    hex::decode(data.trim()).expect("should be able to decode the test vector")
}

pub(super) fn encrypt_decrypt_single_segment<const S: u32>(plaintext: &[u8]) {
    assert!(plaintext.len() <= S as usize);

    let key = FloeKey::from([0u8; 32]);
    let encryptor = FloeEncryptor::<S>::new(&key, &[]);

    let output_size = encryptor.output_size(plaintext);
    let mut buffer = vec![0u8; output_size];

    #[allow(clippy::expect_used)]
    encryptor
        .encrypt_segment(plaintext, &mut buffer, 0, true)
        .expect("We should be able to encrypt the segment");

    #[allow(clippy::unwrap_used)]
    let decryptor = FloeDecryptor::<S>::new(&key, &[], encryptor.header()).unwrap();

    #[allow(clippy::expect_used)]
    let segment = Segment::from_bytes(&buffer).expect("We should be able to parse the segment");
    let mut decryption_buffer = vec![0u8; segment.plaintext_size()];

    #[allow(clippy::unwrap_used)]
    decryptor.decrypt_segment(&segment, &mut decryption_buffer, 0, true).unwrap();

    assert_eq!(
        plaintext, decryption_buffer,
        "The decrypted plaintext should match the original plaintext"
    );
}

pub(super) fn decrypt_test_vector<const S: u32>(ciphertext: &[u8], plaintext: &[u8]) {
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
