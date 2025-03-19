use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sign::Signer};

#[derive(Eq, PartialEq, Debug)]
pub enum VerificationResult {
    Success,
    Failure,
}

pub fn verify_signature(
    signature_header_value: &str,
    secret: &str,
    payload: &[u8],
) -> VerificationResult {
    let pkey = PKey::hmac(secret.as_bytes()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(payload).unwrap();
    let actual_signature = signer.sign_to_vec().unwrap();

    let expected_signature = hex::decode(&signature_header_value["sha256=".len()..]).unwrap();

    return if memcmp::eq(&actual_signature, &expected_signature) {
        VerificationResult::Success
    } else {
        VerificationResult::Failure
    };
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
            verify_signature(
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
            verify_signature(
                "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
                "It's NOT a Secret to Everybody",
                "Hello, World!".as_bytes(),
            )
        );
    }
}
