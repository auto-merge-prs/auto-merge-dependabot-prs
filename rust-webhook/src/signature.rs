//! Copyright (c) 2025 Martin Nordholts
//!
//! This Source Code Form is subject to the terms of the Mozilla Public
//! License, v. 2.0. If a copy of the MPL was not distributed with this
//! file, You can obtain one at https://mozilla.org/MPL/2.0/.


#[derive(Eq, PartialEq, Debug)]
pub enum VerificationResult {
    Success,
    Failure,
}

use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sign::Signer};

/// See <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>
pub fn verify_sha256(signature_header_value: &str, secret: &str, payload: &[u8]) -> VerificationResult {
    let prefix = "sha256=";
    if !signature_header_value.starts_with(prefix) {
        return VerificationResult::Failure;
    }
    let expected_signature = calculate(secret, payload);
    let actual_signature = match hex::decode(&signature_header_value[prefix.len()..]) {
        Ok(sig) => sig,
        Err(_) => return VerificationResult::Failure,
    };

    if memcmp::eq(&expected_signature, &actual_signature) {
        VerificationResult::Success
    } else {
        VerificationResult::Failure
    }
}

fn calculate(secret: &str, payload: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(secret.as_bytes()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(payload).unwrap();
    signer.sign_to_vec().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the example given at
    /// <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation>
    #[test]
    fn test_github_example() {
        assert_eq!(
            VerificationResult::Success,
            verify_sha256(
                "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
                "It's a Secret to Everybody",
                "Hello, World!".as_bytes(),
            )
        );
    }

    #[test]
    fn test_failure() {
        assert_eq!(
            VerificationResult::Failure,
            verify_sha256(
                "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
                "It's NOT a Secret to Everybody",
                "Hello, World!".as_bytes(),
            )
        );
    }
}
