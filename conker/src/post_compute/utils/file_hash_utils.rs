use std::fs;
use std::path::PathBuf;

use log::error;

use crate::post_compute::utils::hash_utils;
use crate::post_compute::utils::hash_utils::concatenate_and_hash;

pub fn get_file_tree_sha_256(file_tree_path: &str) -> Result<String, ()> {
    let metadata = fs::metadata(file_tree_path);
    if metadata.is_err() {
        return Err(());
    }

    let metadata = metadata.unwrap();
    if !metadata.is_dir() {
        return sha256(file_tree_path);
    }

    let files = match fs::read_dir(file_tree_path) {
        Ok(files) => files,
        Err(_) => return Ok("".to_string()),
    };
    let mut hashes: Vec<String> = vec![];

    let mut files: Vec<PathBuf> = files
        .map(|file| file.unwrap().path())
        .map(fs::canonicalize)
        .map(Result::unwrap) // Let's assume file's valid
        .collect();
    // /!\ files MUST be sorted to ensure final concatenateAndHash(..) is always the same (order matters)
    files.sort();

    for file in files {
        let file = match sha256(file.to_str().unwrap()) {
            Ok(file) => file,
            Err(_) => return Err(()),
        };
        hashes.push(file);
    }

    let hashes_as_str: Vec<&str> = hashes.iter().map(String::as_str).collect();
    Ok(concatenate_and_hash(&hashes_as_str))
}

fn sha256(path: &str) -> Result<String, ()> {
    if fs::metadata(path).is_err() {
        return Err(());
    }

    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            error!("{}", error);
            return Err(());
        }
    };

    let hash = hash_utils::sha256(&content);
    let hash_with_prefix = format!("0x{}", hash);
    Ok(hash_with_prefix)
}

// region Tests
#[cfg(test)]
mod tests {
    use crate::post_compute::utils::file_hash_utils::{get_file_tree_sha_256, sha256};

    #[test]
    fn should_get_file_sha256() {
        let file_path =
            "src/test/resources/utils/file-helper/file-hash/output/iexec_out/result1.txt";
        let result = sha256(file_path).unwrap();
        assert_eq!(
            "0xd885f429a59e0816822fc0927be6a6af20ade2c79db49df6c6022f79cb27ac16",
            result
        );
    }

    #[test]
    fn should_not_get_file_sha256_since_invalid_path() {
        let file_path = "/nowhere/nowhere";
        let result = sha256(file_path);
        assert!(result.is_err());
    }

    #[test]
    fn should_get_file_tree_sha256_since_file_tree() {
        let file_path = "src/test/resources/utils/file-helper/file-hash/output/iexec_out/";
        let result = get_file_tree_sha_256(file_path).unwrap();
        assert_eq!(
            "0xcc77508549295dd5de5876a2f4f00d4c3c27a547c6403450e43ab4de191bf1bc",
            result
        );
    }

    #[test]
    fn should_get_file_tree_sha256_since_file() {
        let file_path =
            "src/test/resources/utils/file-helper/file-hash/output/iexec_out/result1.txt";
        let result = get_file_tree_sha_256(file_path).unwrap();
        assert_eq!(
            "0xd885f429a59e0816822fc0927be6a6af20ade2c79db49df6c6022f79cb27ac16",
            result
        );
    }

    #[test]
    fn should_not_get_file_tree_sha256_since_invalid_path() {
        let file_path = "/nowhere/nowhere";
        let result = sha256(file_path);
        assert!(result.is_err());
    }
}
// endregion
