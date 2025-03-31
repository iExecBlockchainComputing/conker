use std::fs;
use std::io::Read;

use log::error;
use reqwest::blocking::Response;

use crate::post_compute::computed_file::ComputedFile;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause::{
    POST_COMPUTE_FAILED_UNKNOWN_ISSUE, POST_COMPUTE_IPFS_UPLOAD_FAILED,
    POST_COMPUTE_RESULT_FILE_NOT_FOUND,
};
use crate::post_compute::web2::result_model::ResultModel;

pub fn upload_to_ipfs_with_iexec_proxy(
    computed_file: &ComputedFile,
    base_url: &str,
    token: &str,
    file_to_upload_path: &str,
) -> Result<String, ReplicateStatusCause> {
    let task_id = computed_file
        .task_id()
        .as_ref()
        .ok_or(POST_COMPUTE_FAILED_UNKNOWN_ISSUE)?;

    let file_to_upload = match fs::read(file_to_upload_path) {
        Ok(content) => content,
        Err(err) => {
            error!("Can't uploadToIpfsWithIexecProxy (missing filePath to upload) [taskId:{}, fileToUploadPath:{}]", task_id, file_to_upload_path);
            error!("{}", err);
            return Err(POST_COMPUTE_RESULT_FILE_NOT_FOUND);
        }
    };

    let result_digest = computed_file
        .result_digest()
        .as_ref()
        .ok_or(POST_COMPUTE_FAILED_UNKNOWN_ISSUE)?;
    let enclave_signature = computed_file
        .enclave_signature()
        .as_ref()
        .ok_or(POST_COMPUTE_FAILED_UNKNOWN_ISSUE)?;
    let result_model = ResultModel::build_result_model(
        task_id,
        file_to_upload.as_slice(),
        result_digest,
        enclave_signature,
    );

    let client = reqwest::blocking::Client::new();
    // let body = match serde_json::to_string(&result_model) {
    //     Ok(json) => json,
    //     Err(error) => {
    //         error!("Can't serialize ResultModel");
    //         error!("{}", error);
    //         return Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE);
    //     }
    // };   // FIXME

    let response: &mut Response = &mut match client
        .post(base_url)
        .header("Authorization", token)
        .json(&result_model)
        .send()
    {
        Ok(response) => {
            let status_code = response.status();
            if !status_code.is_success() {
                error!(
                    "Can't uploadToIpfsWithIexecProxy (result proxy issue) \
                [taskId: {}, status: {}]",
                    task_id, status_code
                );
                return Err(POST_COMPUTE_IPFS_UPLOAD_FAILED);
            } else {
                response
            }
        }
        Err(error) => {
            error!(
                "Can't uploadToIpfsWithIexecProxy (result proxy issue) [taskId:{}]",
                task_id
            );
            error!("{}", error);
            return Err(POST_COMPUTE_IPFS_UPLOAD_FAILED);
        }
    };

    let mut content = String::new();
    match response.read_to_string(&mut content) {
        Ok(_) => {}
        Err(error) => {
            error!(
                "Can't read response of uploadToIpfsWithIexecProxy [taskId:{}]",
                task_id
            );
            error!("{}", error);
            return Err(POST_COMPUTE_IPFS_UPLOAD_FAILED);
        }
    };

    Ok(content)
}
