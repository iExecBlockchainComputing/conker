use derive_getters::Getters;
use serde::{Deserialize, Serialize};

#[derive(Getters, Serialize, Deserialize)]
pub struct ComputedFile {
    #[serde(rename = "deterministic-output-path")]
    deterministic_output_path: Option<String>,
    #[serde(rename = "callback-data")]
    callback_data: Option<String>,
    #[serde(rename = "task-id")]
    task_id: Option<String>,
    #[serde(rename = "result-digest")]
    result_digest: Option<String>,
    #[serde(rename = "enclave-signature")]
    enclave_signature: Option<String>,
}

impl ComputedFile {
    pub fn set_task_id(&mut self, task_id: &str) {
        self.task_id = Some(String::from(task_id));
    }

    pub fn set_result_digest(&mut self, result_digest: &str) {
        self.result_digest = Some(String::from(result_digest));
    }

    pub fn set_enclave_signature(&mut self, enclave_signature: &str) {
        self.enclave_signature = Some(String::from(enclave_signature));
    }
}
