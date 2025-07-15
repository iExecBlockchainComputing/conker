use crate::logger_debug;
use crate::pre_compute::multiaddress_helper::IPFS_GATEWAYS;
use crate::pre_compute::pre_compute_args::PreComputeArgs;
use crate::pre_compute::replicate_status_cause::ReplicateStatusCause;
use crate::pre_compute::replicate_status_cause::ReplicateStatusCause::{
    PreComputeDatasetDecryptionFailed, PreComputeDatasetDownloadFailed,
    PreComputeInputFileDownloadFailed, PreComputeInvalidDatasetChecksum,
    PreComputeOutputFolderNotFound, PreComputeSavingPlainDatasetFailed,
};
use base64::Engine;
use libp2p::multiaddr;
use log::{debug, error, info};
use openssl::symm::Cipher;
use reqwest::blocking::{Client, Response};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::ops::Deref;

pub async fn run(chain_task_id: &str) -> Result<(), ReplicateStatusCause> {
  //
  logger_debug!("");

    println!("======================================");
    println!("pre_compute > pre_compute_app.rs > run()");
    println!("======================================");

    let args = PreComputeArgs::read_args(chain_task_id)?;
    //
    debug!("args 1 = {:#?}", args);
    
    check_output_folder(&args)?;
    
    //
    debug!("args 2 = {:#?}", args);
    
    
    if *args.is_dataset_required() {
      let chain_task_id = args.chain_task_id();
      let encrypted_dataset_url = args.dataset_url().as_ref().unwrap();
      let expected_checksum = args.dataset_checksum().as_ref().unwrap();
      let dataset_key = args.dataset_key().as_ref().unwrap();
      let dataset_filename = args.dataset_filename().as_ref().unwrap();
      let output_dir = args.pre_compute_out();
      
      let encrypted_content =
      download_encrypted_dataset(chain_task_id, encrypted_dataset_url, expected_checksum)?;
      let plain_content = decrypt_dataset(chain_task_id, encrypted_content, dataset_key)?;
      save_plain_dataset_file(chain_task_id, output_dir, dataset_filename, &plain_content)?;
    }
    
    //
    debug!("args 3 = {:#?}", args);
    
    download_input_files(&args)
}

fn check_output_folder(args: &PreComputeArgs) -> Result<(), ReplicateStatusCause> {
  //
  logger_debug!("");

    let chain_task_id = args.chain_task_id();
    let output_dir = args.pre_compute_out();
    info!(
        "Checking output folder [chainTaskId:{}, path:{}]",
        chain_task_id, output_dir
    );

    match fs::metadata(output_dir) {
        Ok(metadata) => {
            if metadata.is_dir() {
                Ok(())
            } else {
                error!(
                    "Output path is not a directory [chainTaskId:{}, path:{}]",
                    chain_task_id, output_dir
                );
                Err(PreComputeOutputFolderNotFound)
            }
        }
        Err(_) => {
            error!(
                "Output folder not found [chainTaskId:{}, path:{}]",
                chain_task_id, output_dir
            );
            Err(PreComputeOutputFolderNotFound)
        }
    }
}

// region Dataset
fn download_encrypted_dataset(
    chain_task_id: &str,
    encrypted_dataset_url: &str,
    expected_checksum: &str,
) -> Result<Vec<u8>, ReplicateStatusCause> {
//
logger_debug!("");
  info!(
        "Downloading encrypted dataset file [chainTaskId:{}, url:{}]",
        chain_task_id, encrypted_dataset_url
    );

    let client = &match build_client() {
        Ok(client) => client,
        Err(_) => {
            return Err(PreComputeDatasetDownloadFailed);
        }
    };

    let result = if multiaddr::from_url(encrypted_dataset_url).is_ok() {
        download_from_ipfs(chain_task_id, client, encrypted_dataset_url)
    } else {
        match download_file(chain_task_id, client, encrypted_dataset_url) {
            Ok((_, file_content)) => Ok(file_content),
            Err(_) => Err(()),
        }
    };

    let encrypted_file_content = match result {
        Ok(file_content) => file_content,
        Err(()) => {
            error!(
                "Failed to download encrypted dataset file [chainTaskId:{}, url:{}]",
                chain_task_id, encrypted_dataset_url
            );
            return Err(PreComputeDatasetDownloadFailed);
        }
    };

    info!(
        "Checking encrypted dataset checksum [chainTaskId:{}]",
        chain_task_id
    );
    let actual_checksum = &format!("0x{}", &sha256::digest(encrypted_file_content.deref()));
    if actual_checksum != expected_checksum {
        error!(
            "Invalid dataset checksum [chainTaskId:{}, expected:{}, actual:{}]",
            chain_task_id, expected_checksum, actual_checksum
        );
        return Err(PreComputeInvalidDatasetChecksum);
    }

    Ok(encrypted_file_content)
}

fn download_from_ipfs(
    chain_task_id: &str,
    client: &Client,
    encrypted_dataset_url: &str,
) -> Result<Vec<u8>, ()> {
  //
  logger_debug!("");

    for ipfs_gateway in IPFS_GATEWAYS {
        debug!(
            "Try to download dataset from {} [chainTaskId:{}]",
            ipfs_gateway, chain_task_id
        );
        let full_url = format!("{}{}", ipfs_gateway, encrypted_dataset_url);
        let download_result = download_file(chain_task_id, client, &full_url);
        if download_result.is_ok() {
            let (_, file_content) = download_result.unwrap();
            return Ok(file_content);
        }
    }

    Err(())
}

fn decrypt_dataset(
    chain_task_id: &str,
    encrypted_file_content: Vec<u8>,
    encrypted_dataset_base64_key: &str,
) -> Result<Vec<u8>, ReplicateStatusCause> {
    //
  logger_debug!("");
  
  info!("Decrypting dataset [chainTaskId:{}]", chain_task_id);

    let key = match base64::engine::general_purpose::STANDARD.decode(encrypted_dataset_base64_key) {
        Ok(key) => key,
        Err(_) => {
            error!("Can't decode Base64 key [chainTaskId:{}]", chain_task_id);
            return Err(PreComputeDatasetDecryptionFailed);
        }
    };

    let iv = &encrypted_file_content[0..16];
    let encrypted_data = &encrypted_file_content[16..];

    let cipher = Cipher::aes_256_cbc();
    match openssl::symm::decrypt(cipher, &key, Some(iv), encrypted_data) {
        Ok(plain_dataset_content) => {
            info!("Decrypted dataset [chainTaskId:{}]", chain_task_id);
            Ok(plain_dataset_content)
        }
        Err(error) => {
            error!("Failed to decrypt dataset [chainTaskId:{}]", chain_task_id);
            error!("{}", error);
            Err(PreComputeDatasetDecryptionFailed)
        }
    }
}

fn save_plain_dataset_file(
    chain_task_id: &str,
    output_dir: &str,
    plain_dataset_filename: &str,
    plain_content: &[u8],
) -> Result<(), ReplicateStatusCause> {
    //
  logger_debug!("");
    
    let file_path = &format!("{}/{}", output_dir, plain_dataset_filename);
    info!(
        "Saving plain dataset file [chainTaskId:{}, path:{}]",
        chain_task_id, file_path
    );
    match write_file(chain_task_id, file_path, plain_content) {
        Ok(_) => {
            info!(
                "Saved plain dataset file to disk [chainTaskId:{}]",
                chain_task_id
            );
            Ok(())
        }
        Err(_) => {
            error!(
                "Failed to write plain dataset file [chainTaskId:{}, path:{}]",
                chain_task_id, file_path
            );
            Err(PreComputeSavingPlainDatasetFailed)
        }
    }
}

// endregion

// region Input files
fn download_input_files(args: &PreComputeArgs) -> Result<(), ReplicateStatusCause> {
  //
  logger_debug!("");

    let chain_task_id = args.chain_task_id();
    let pre_compute_out = args.pre_compute_out();

    let client = match build_client() {
        Ok(client) => client,
        Err(_) => {
            error!(
                "Input file download client creation failed [chainTaskId:{}]",
                chain_task_id
            );
            return Err(PreComputeInputFileDownloadFailed);
        }
    };

    for input_file_url in args.input_files() {
        download_input_file(chain_task_id, &client, input_file_url, pre_compute_out)?;
    }

    Ok(())
}

fn download_input_file(
    chain_task_id: &str,
    client: &Client,
    input_file_url: &str,
    output_dir: &str,
) -> Result<(), ReplicateStatusCause> {
  //
  logger_debug!("");

    info!(
        "Downloading input file [chainTaskId:{}, url:{}]",
        chain_task_id, input_file_url
    );

    let (file_name, file_content) = match download_file(chain_task_id, client, input_file_url) {
        Ok((file_name, file_content)) => (file_name, file_content),
        Err(_) => {
            return Err(PreComputeInputFileDownloadFailed);
        }
    };

    let file_path = format!("{}/{}", output_dir, file_name);

    match write_file(chain_task_id, &file_path, &file_content) {
        Ok(_) => Ok(()),
        Err(_) => {
            error!(
                "Input file writing failed [chainTaskId:{}, file:{}]",
                chain_task_id, file_path
            );
            Err(PreComputeInputFileDownloadFailed)
        }
    }
}
// endregion

// region utils
fn build_client() -> Result<Client, ()> {
  //
  logger_debug!("");

    match Client::builder().use_rustls_tls().build() {
        Ok(client) => Ok(client),
        Err(_) => {
            error!("Can't build client");
            Err(())
        }
    }
}

fn download_file(
    chain_task_id: &str,
    client: &Client,
    file_url: &str,
) -> Result<(String, Vec<u8>), ()> {
  //
  logger_debug!("");

    let request = match client.get(file_url).build() {
        Ok(request) => request,
        Err(e) => {
            error!(
                "File download failed [chainTaskId:{}, file:{}]",
                chain_task_id, file_url
            );
            error!("{}", e);
            return Err(());
        }
    };
    let response = match client.execute(request) {
        Ok(response) => response,
        Err(e) => {
            error!(
                "File download failed [chainTaskId:{}, file:{}]",
                chain_task_id, file_url
            );
            error!("{}", e);
            return Err(());
        }
    };

    let file_name = get_filename(&response);

    let file_content = match response.bytes() {
        Ok(file_content) => file_content.to_vec(),
        Err(_) => {
            error!(
                "File content retrieve failed [chainTaskId:{}, file:{}]",
                chain_task_id, file_url
            );
            return Err(());
        }
    };

    Ok((file_name, file_content))
}

fn get_filename(response: &Response) -> String {
  //
  logger_debug!("");

    String::from(
        response
            .url()
            .path_segments()
            .and_then(|segments| segments.last())
            .and_then(|name| if name.is_empty() { None } else { Some(name) })
            .unwrap(),
    ) // FIXME
}

fn write_file(chain_task_id: &str, file_path: &str, file_content: &[u8]) -> Result<(), ()> {
  //
  logger_debug!("");

    let mut file = match File::create(file_path) {
        Ok(file) => file,
        Err(_) => {
            error!(
                "File creation failed [chainTaskId:{}, file:{}]",
                chain_task_id, file_path
            );
            return Err(());
        }
    };

    match file.write_all(file_content) {
        Ok(_) => Ok(()),
        Err(_) => {
            error!(
                "File writing failed [chainTaskId:{}, file:{}]",
                chain_task_id, file_path
            );
            Err(())
        }
    }
}
// endregion

// region Tests
#[cfg(test)]
mod tests {
    use crate::pre_compute::pre_compute_app::decrypt_dataset;
    use test_log::test;

    const CHAIN_TASK_ID: &str =
        "0x59d9b6c36d6db89bae058ff55de6e4d6a6f6e0da3f9ea02297fc8d6d5f5cedf1";
    const KEY: &str = "bfXuX9b4jivYD60sVynJujiTBW+UXEkdtVP+bletqJ8=";

    #[test]
    fn should_decrypt_dataset() {
        let encrypted_file_content = [
            109, 30, 97, 216, 141, 44, 110, 154, 165, 229, 116, 69, 203, 101, 18, 72, 178, 161,
            230, 71, 244, 73, 80, 1, 249, 218, 7, 15, 83, 76, 178, 175, 193, 255, 53, 242, 165,
            228, 19, 170, 40, 26, 132, 147, 210, 157, 117, 26, 59, 8, 255, 102, 50, 72, 168, 187,
            191, 224, 172, 14, 219, 206, 191, 96,
        ]
        .to_vec();

        let decrypted_dataset = decrypt_dataset(
            &String::from(CHAIN_TASK_ID),
            encrypted_file_content,
            &String::from(KEY),
        );

        assert!(decrypted_dataset.is_ok());

        assert_eq!(
            "Hello, if you can read this, well done!",
            String::from_utf8(decrypted_dataset.unwrap()).unwrap()
        );
    }
}
// endregion
