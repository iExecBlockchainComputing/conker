use log::{error, info};

use crate::post_compute::computed_file::ComputedFile;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause::{
    POST_COMPUTE_ENCRYPTION_FAILED, POST_COMPUTE_FAILED_UNKNOWN_ISSUE,
    POST_COMPUTE_OUT_FOLDER_ZIP_FAILED, POST_COMPUTE_STORAGE_TOKEN_MISSING,
};
use crate::post_compute::utils::env_utils::{
    RESULT_ENCRYPTION, RESULT_STORAGE_PROVIDER, RESULT_STORAGE_PROXY, RESULT_STORAGE_TOKEN,
};
use crate::post_compute::utils::{post_compute_args, result_utils};
use crate::post_compute::web2::uploader_service;

const IEXEC_OUT: &str = "/iexec_out";
const SLASH_POST_COMPUTE_TMP: &str = "/post-compute-tmp";
const IPFS_RESULT_STORAGE_PROVIDER: &str = "ipfs";
const DROPBOX_RESULT_STORAGE_PROVIDER: &str = "dropbox";

pub fn encrypt_and_upload_result(computed_file: &ComputedFile) -> Result<(), ReplicateStatusCause> {
    // check result file names are not too long (currently disabled)
    let chain_task_id = computed_file
        .task_id()
        .as_ref()
        .ok_or(POST_COMPUTE_FAILED_UNKNOWN_ISSUE)?;
    check_result_files_name(chain_task_id, IEXEC_OUT)?;

    let iexec_out_zip_path = match result_utils::zip_iexec_out(IEXEC_OUT, SLASH_POST_COMPUTE_TMP) {
        Ok(path) => path,
        Err(err) => {
            error!("zipIexecOut stage failed [chainTaskId: {}]", chain_task_id);
            error!("{}", err);
            return Err(POST_COMPUTE_OUT_FOLDER_ZIP_FAILED);
        }
    };

    let result_path = eventually_encrypt_result(&iexec_out_zip_path)?;

    upload_result(computed_file, &result_path)?;

    Ok(())
}

fn check_result_files_name(
    task_id: &str,
    iexec_out_path: &str,
) -> Result<(), ReplicateStatusCause> {
    // Let's say we don't care about long names for now
    Ok(())
}

fn eventually_encrypt_result(in_data_file_path: &str) -> Result<String, ReplicateStatusCause> {
    info!("Encryption stage started");
    let should_encrypt = post_compute_args::get_yes_or_no_boolean_env_var(RESULT_ENCRYPTION)?;

    let file_to_upload: &str;
    if !should_encrypt {
        info!("Encryption stage mode: NO_ENCRYPTION");
        file_to_upload = in_data_file_path;
    } else {
        info!("Encryption stage mode: ENCRYPTION_REQUESTED");
        error!("Encryption NOT SUPPORTED");
        return Err(POST_COMPUTE_ENCRYPTION_FAILED);
    }

    if file_to_upload.is_empty() {
        error!("Encryption stage failed");
        return Err(POST_COMPUTE_ENCRYPTION_FAILED);
    } else {
        info!("Encryption stage completed");
    }

    Ok(String::from(file_to_upload))
}

fn upload_result(
    computed_file: &ComputedFile,
    file_to_upload_path: &str,
) -> Result<String, ReplicateStatusCause> {
    info!("Upload stage started");

    let storage_provider = post_compute_args::get_env_var(RESULT_STORAGE_PROVIDER)?;
    let storage_proxy = post_compute_args::get_env_var(RESULT_STORAGE_PROXY)?;
    let storage_token = match post_compute_args::get_env_var(RESULT_STORAGE_TOKEN) {
        Ok(token) => token,
        Err(_) => {
            return Err(POST_COMPUTE_STORAGE_TOKEN_MISSING);
        }
    };

    let result_link;

    match storage_provider.as_str() {
        DROPBOX_RESULT_STORAGE_PROVIDER => {
            info!("Upload stage mode: DROPBOX_STORAGE");
            error!("Dropbox not supported");
            return Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE);
        }
        IPFS_RESULT_STORAGE_PROVIDER | _ => {
            info!("Upload stage mode: IPFS_STORAGE");
            result_link = uploader_service::upload_to_ipfs_with_iexec_proxy(
                computed_file,
                &storage_proxy,
                &storage_token,
                file_to_upload_path,
            );
        }
    }

    info!("Upload stage completed");
    result_link
}
