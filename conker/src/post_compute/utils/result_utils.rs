use std::fs;
use std::fs::{DirEntry, File};
use std::io::{Read, Seek, Write};
use std::path::Path;

use log::{error, info};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::post_compute::computed_file::ComputedFile;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause::{
    POST_COMPUTE_OUT_FOLDER_ZIP_FAILED, POST_COMPUTE_RESULT_DIGEST_COMPUTATION_FAILED,
};
use crate::post_compute::utils::file_hash_utils::get_file_tree_sha_256;

pub fn compute_web2result_digest(
    computed_file: &ComputedFile,
) -> Result<String, ReplicateStatusCause> {
    if computed_file.deterministic_output_path().is_none()
        || computed_file
            .deterministic_output_path()
            .as_ref()
            .unwrap()
            .is_empty()
    {
        error!(
            "Failed to computeWeb2ResultDigest (deterministicOutputPath empty)[chainTaskId:{}]",
            computed_file.task_id().as_ref().unwrap()
        );
        return Err(POST_COMPUTE_RESULT_DIGEST_COMPUTATION_FAILED);
    }

    let host_deterministic_output_path = computed_file.deterministic_output_path();
    match fs::metadata(host_deterministic_output_path.as_ref().unwrap()) {
        Ok(_) => {}
        Err(error) => {
            error!("Failed to computeWeb2ResultDigest (hostDeterministicOutputPath missing) [chainTaskId:{}]",
                  computed_file.task_id().as_ref().unwrap());
            error!("{}", error);
            return Err(POST_COMPUTE_RESULT_DIGEST_COMPUTATION_FAILED);
        }
    }

    return match get_file_tree_sha_256(host_deterministic_output_path.as_ref().unwrap().as_str()) {
        Ok(file_tree) => Ok(file_tree),
        Err(_) => {
            return Err(POST_COMPUTE_RESULT_DIGEST_COMPUTATION_FAILED);
        }
    };
}

pub fn zip_iexec_out(iexec_out_path: &str, save_in: &str) -> Result<String, ReplicateStatusCause> {
    let file_name = format!(
        "{}.zip",
        Path::new(iexec_out_path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
    );
    fs::create_dir_all(save_in).unwrap();
    let destination = format!("{}/{}", save_in, file_name);
    let destination_path = Path::new(&destination);
    let destination_file = File::create(destination_path).unwrap();

    let mut files = match fs::read_dir(iexec_out_path) {
        Ok(files) => files.into_iter().map(Result::unwrap),
        Err(_) => return Err(POST_COMPUTE_OUT_FOLDER_ZIP_FAILED),
    };

    match zip_folder(
        &mut files,
        iexec_out_path,
        &destination_file,
        zip::CompressionMethod::Deflated,
    ) {
        Ok(_) => info!(
            "Created iexec_out zip [zipPath:{}]",
            destination_path.to_str().unwrap()
        ),
        Err(error) => {
            error!("Could not zip iexec_out [iexecOutPath:{}]", iexec_out_path);
            error!("{}", error);
            return Err(POST_COMPUTE_OUT_FOLDER_ZIP_FAILED);
        }
    };

    return Ok(destination_path.to_str().unwrap().to_string());
}

fn zip_folder<T>(
    it: &mut dyn Iterator<Item = DirEntry>,
    prefix: &str,
    writer: T,
    method: zip::CompressionMethod,
) -> zip::result::ZipResult<()>
where
    T: Write + Seek,
{
    let mut zip = ZipWriter::new(writer);
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();
    for entry in it {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(prefix)).unwrap();

        // Write file or directory explicitly
        // Some unzip tools unzip files with directory paths correctly, some do not!
        if path.is_file() {
            println!("adding file {path:?} as {name:?} ...");
            #[allow(deprecated)]
            zip.start_file_from_path(name, options)?;
            let mut f = File::open(path)?;

            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            buffer.clear();
        } else if !name.as_os_str().is_empty() {
            // Only if not root! Avoids path spec / warning
            // and mapname conversion failed error on unzip
            println!("adding dir {path:?} as {name:?} ...");
            #[allow(deprecated)]
            zip.add_directory_from_path(name, options)?;
        }
    }
    zip.finish()?;
    Ok(())
}

// region Tests
#[cfg(test)]
mod tests {
    use env_logger::Env;

    use crate::post_compute::utils::result_utils::zip_iexec_out;

    #[test]
    fn test_zip_iexec_out() {
        env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

        let path = "src/test/resources/utils/file-helper/file-hash/output/iexec_out";
        zip_iexec_out(path, "build/").unwrap();
    }
}
// endregion
