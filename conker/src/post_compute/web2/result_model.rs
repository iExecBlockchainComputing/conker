use serde::Serialize;

#[derive(Serialize)]
pub struct ResultModel {
    #[serde(rename = "chainTaskId")]
    chain_task_id: String,
    image: String,
    cmd: String,
    zip: Box<[u8]>,
    #[serde(rename = "deterministHash")]
    determinist_hash: String,
    #[serde(rename = "enclaveSignature")]
    enclave_signature: String,
}

impl ResultModel {
    pub fn build_result_model(
        chain_task_id: &str,
        zip: &[u8],
        determinist_hash: &str,
        enclave_signature: &str,
    ) -> ResultModel {
        ResultModel {
            chain_task_id: chain_task_id.to_string(),
            image: String::from(""),
            cmd: String::from(""),
            zip: Box::from(zip),
            determinist_hash: determinist_hash.to_string(),
            enclave_signature: enclave_signature.to_string(),
        }
    }
}
