use crate::post_compute::computed_file::ComputedFile;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause::{
    POST_COMPUTE_COMPUTED_FILE_NOT_FOUND, POST_COMPUTE_FAILED_UNKNOWN_ISSUE,
    POST_COMPUTE_RESULT_DIGEST_COMPUTATION_FAILED, POST_COMPUTE_TEE_CHALLENGE_PRIVATE_KEY_MISSING,
    POST_COMPUTE_WORKER_ADDRESS_MISSING,
};
use crate::post_compute::signer::signer_service::sign_enclave_challenge;
use crate::post_compute::utils::env_utils::{RESULT_SIGN_TEE_CHALLENGE_PRIVATE_KEY, RESULT_SIGN_WORKER_ADDRESS};
use crate::post_compute::utils::hash_utils::get_message_hash;
use crate::post_compute::utils::post_compute_args::get_env_var;
use crate::post_compute::utils::{hash_utils, result_utils};
use crate::post_compute::worker_api::worker_api_client;

use std::fs;
use tracing::{error, info};

pub fn read_computed_file(task_id: &str) -> Result<ComputedFile, ReplicateStatusCause> {
    info!("ReadComputedFile stage started");

    let path = "/iexec_out/computed.json";
    let file = match fs::read_to_string(path) {
        Ok(f) => f,
        Err(_) => {
            error!(
                "Failed to read compute file (invalid path) [chainTaskId:{}, computedFilePath:{}]",
                task_id, path
            );
            return Err(POST_COMPUTE_COMPUTED_FILE_NOT_FOUND);
        }
    };

    info!("{}", file);

    // Read the JSON contents of the file as an instance of `ComputedFile`.
    let result_computed_file = serde_json::from_str(&file);
    if result_computed_file.is_err() {
        error!(
            "Failed to read compute file (invalid content) [chainTaskId:{}, computedFilePath:{}]",
            task_id, path
        );
        error!("{}", result_computed_file.err().expect("No specific error"));
        return Err(POST_COMPUTE_COMPUTED_FILE_NOT_FOUND);
    }

    let mut computed_file: ComputedFile = result_computed_file.unwrap();
    computed_file.set_task_id(task_id);

    Ok(computed_file)
}

pub fn compute_result_digest(
    computed_file: &ComputedFile,
    should_callback: bool,
) -> Result<String, ReplicateStatusCause> {
    info!(
        "ResultDigest stage started [mode:{}]",
        if should_callback { "web3" } else { "web2" }
    );

    let result_digest;
    if should_callback {
        return Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE);
    } else {
        result_digest = result_utils::compute_web2result_digest(computed_file)?;
    }

    if result_digest.is_empty() {
        error!(
            "Empty result_digest [chainTaskId: {}]",
            computed_file.task_id().as_ref().unwrap()
        );
        return Err(POST_COMPUTE_RESULT_DIGEST_COMPUTATION_FAILED);
    }

    info!("ResultDigest stage completed");
    Ok(result_digest)
}

pub fn sign_computed_file(computed_file: &ComputedFile) -> Result<String, ReplicateStatusCause> {
    info!("Signer stage started");
    let worker_address = match get_env_var(RESULT_SIGN_WORKER_ADDRESS) {
        Ok(address) => address,
        Err(_) => return Err(POST_COMPUTE_WORKER_ADDRESS_MISSING),
    };
    let result_hash_args = [
        computed_file.task_id().as_ref().unwrap().as_str(),
        computed_file.result_digest().as_ref().unwrap().as_str(),
    ];
    let result_hash = hash_utils::concatenate_and_hash(&result_hash_args);
    let result_seal_args = [
        worker_address.as_str(),
        computed_file.task_id().as_ref().unwrap().as_str(),
        computed_file.result_digest().as_ref().unwrap().as_str(),
    ];
    let result_seal = hash_utils::concatenate_and_hash(&result_seal_args);
    let message_hash = get_message_hash(&result_hash, &result_seal);

    let tee_challenge_private_key = match get_env_var(RESULT_SIGN_TEE_CHALLENGE_PRIVATE_KEY) {
        Ok(key) => key,
        Err(_) => return Err(POST_COMPUTE_TEE_CHALLENGE_PRIVATE_KEY_MISSING),
    };

    let enclave_signature = sign_enclave_challenge(&message_hash, &tee_challenge_private_key)?;
    info!("Signer stage completed");

    Ok(enclave_signature)
}

pub fn send_computed_file_to_host(
    computed_file: &ComputedFile,
) -> Result<(), ReplicateStatusCause> {
    info!(
        "Send ComputedFile stage started [computedFile:{}]",
        serde_json::to_string(computed_file).expect("Can't serialize computed_file")
    );
    match worker_api_client::send_computed_file_to_host(
        computed_file.task_id().as_ref().unwrap().as_str(),
        computed_file,
    ) {
        Ok(_) => {}
        Err(error) => {
            error!(
                "Send ComputedFile stage failed [taskId:{}]",
                computed_file.task_id().as_ref().unwrap()
            );
            return Err(error);
        }
    };

    info!("Send ComputedFile stage completed");
    Ok(())
}
