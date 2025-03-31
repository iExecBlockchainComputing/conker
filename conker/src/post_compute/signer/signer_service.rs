use ethers::signers::{LocalWallet, Signer};
use ethers::utils::hex::decode;
use futures_executor::block_on;
use log::error;

use crate::post_compute::replicate_status_cause::ReplicateStatusCause;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause::{
    POST_COMPUTE_FAILED_UNKNOWN_ISSUE, POST_COMPUTE_INVALID_TEE_SIGNATURE,
};

pub fn sign_enclave_challenge(
    message_hash: &str,
    enclave_challenge_private_key: &str,
) -> Result<String, ReplicateStatusCause> {
    let wallet = match enclave_challenge_private_key.parse::<LocalWallet>() {
        Ok(wallet) => wallet,
        Err(error) => {
            error!("Failed to get wallet from private key");
            error!("{}", error);
            return Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE); // FIXME: create a new error for this issue
        }
    };

    let message_hash = match decode(message_hash) {
        Ok(message_hash) => message_hash,
        Err(error) => {
            error!("Failed to decode message hash");
            error!("{}", error);
            return Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE); // FIXME: create a new error for this issue
        }
    };

    let signature_future = wallet.sign_message(message_hash.as_slice());
    let enclave_challenge_signature = match block_on(signature_future) {
        Ok(signature) => signature,
        Err(error) => {
            error!("Failed to sign challenge");
            error!("{}", error);
            return Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE); // FIXME: create a new error for this issue
        }
    };
    match enclave_challenge_signature.verify(message_hash, wallet.address()) {
        Ok(_) => (),
        Err(error) => {
            error!("Failed to verify TeeEnclaveChallenge signature");
            error!("{}", error);
            return Err(POST_COMPUTE_INVALID_TEE_SIGNATURE);
        }
    };

    let enclave_challenge_signature = format!("0x{}", enclave_challenge_signature);

    Ok(enclave_challenge_signature.to_string())
}

// region Tests
#[cfg(test)]
mod tests {
    use crate::post_compute::signer::signer_service::sign_enclave_challenge;

    #[test]
    fn should_sign_enclave_challenge() {
        let message_hash = "0x5cd0e9c5180dd35e2b8285d0db4ded193a9b4be6fbfab90cbadccecab130acad";
        let expected_challenge = "0xfcc6bce5eb04284c2eb1ed14405b943574343b1abda33628fbf94a374b18dd16541c6ebf63c6943d8643ff03c7aa17f1cb17b0a8d297d0fd95fc914bdd0e85f81b";

        let enclave_challenge_private_key_1 =
            "0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479";

        let signature = sign_enclave_challenge(message_hash, enclave_challenge_private_key_1);

        assert_eq!(signature.unwrap().to_string(), expected_challenge);
    }
}
// endregion
