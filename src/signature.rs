use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sign::Signer};
use std::fmt;

#[derive(Debug)]
pub struct SignedPayloadError;

impl fmt::Display for SignedPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "failed to validate payload")
    }
}

impl std::error::Error for SignedPayloadError {}

enum VerificationResult {
    Success,
    Failure,
}

pub fn verify_signature(signature_header_value: &str, payload: &[u8], secret: &str) -> VerificationResult {
    let expected_signature = signature_header_value["sha256=".len()..];
    let expected_signature = hex::decode(expected_signature).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), secret).unwrap();
    signer.update(payload).unwrap();
    let actual_signature = signer.sign_to_vec().unwrap();
    return if memcmp::eq(&actual_signature, &expected_signature) {
        VerificationResult::Success
    } else {
        VerificationResult::Failure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_example() {
        assert_eq!(VerificationResult::Success, verify_signature("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17", "It's a Secret to Everybody"))

        ng secret and payload values to verify that your implementation is correct:

        secret: 
        payload: Hello, World!
    
    If your implementation is correct, the signatures that you generate should match the following signature values:
    
        signature: 757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17
        X-Hub-Signature-256: 
    
    
        
    }
}
