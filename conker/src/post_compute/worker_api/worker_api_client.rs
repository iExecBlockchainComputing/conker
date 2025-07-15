use crate::post_compute::computed_file::ComputedFile;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause::POST_COMPUTE_SEND_COMPUTED_FILE_FAILED;
use log::error;

const WORKER_HOST: &str = "worker:13100";

pub fn send_computed_file_to_host(
    chain_task_id: &str,
    computed_file: &ComputedFile,
) -> Result<(), ReplicateStatusCause> {
    let client = reqwest::blocking::Client::new();
    let url = format!(
        "http://{}/compute/post/{}/computed",
        WORKER_HOST, chain_task_id
    );

    let response = client.post(url).json(&computed_file).send();

    match response {
        Ok(response) => {
            let status_code = response.status();
            if !status_code.is_success() {
                error!(
                    "Failed to send computed file [chainTaskId: {}, status: {}]",
                    chain_task_id, status_code
                );
                Err(POST_COMPUTE_SEND_COMPUTED_FILE_FAILED)
            } else {
                Ok(())
            }
        }
        Err(error) => {
            error!(
                "Failed to send computed file [chainTaskId: {}]",
                chain_task_id
            );
            error!("{}", error);
            Err(POST_COMPUTE_SEND_COMPUTED_FILE_FAILED)
        }
    }
}
