use log::error;

use crate::post_compute::computed_file::ComputedFile;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause::POST_COMPUTE_FAILED_UNKNOWN_ISSUE;
use crate::post_compute::utils::env_utils::RESULT_STORAGE_CALLBACK;
use crate::post_compute::utils::post_compute_args;
use crate::post_compute::web2::web2_result_service;
use crate::post_compute::workflow::flow_service;

pub fn run(chain_task_id: &str) -> Result<(), ReplicateStatusCause> {
    let should_callback =
        post_compute_args::get_yes_or_no_boolean_env_var(RESULT_STORAGE_CALLBACK)?;
    if should_callback {
        error!(
            "Callback mode is not supported! [chainTaskId:{}]",
            chain_task_id
        );
        return Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE);
    }

    let mut computed_file: ComputedFile = flow_service::read_computed_file(chain_task_id)?;
    let result_digest = flow_service::compute_result_digest(&mut computed_file, should_callback)?;
    computed_file.set_result_digest(&result_digest);
    let enclave_signature = flow_service::sign_computed_file(&computed_file)?;
    computed_file.set_enclave_signature(&enclave_signature);

    if !should_callback {
        web2_result_service::encrypt_and_upload_result(&computed_file)?;
    }

    flow_service::send_computed_file_to_host(&computed_file)?;

    Ok(())
}
