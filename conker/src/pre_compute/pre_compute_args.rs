use crate::pre_compute::env_utils::*;
use crate::pre_compute::replicate_status_cause::ReplicateStatusCause::{self, *};
use derive_getters::Getters;
use log::error;
use std::env;
use std::str::FromStr;

#[derive(Getters, Debug)]
pub struct PreComputeArgs {
    chain_task_id: String,
    pre_compute_out: String,
    is_dataset_required: bool,
    dataset_url: Option<String>,
    dataset_key: Option<String>,
    dataset_checksum: Option<String>,
    dataset_filename: Option<String>,
    input_files: Vec<String>,
}

impl PreComputeArgs {
    pub fn read_args(chain_task_id: &str) -> Result<PreComputeArgs, ReplicateStatusCause> {
        let pre_compute_out = match PreComputeArgs::get_env_var(IEXEC_PRE_COMPUTE_OUT) {
            Ok(value) => value,
            Err(_) => return Err(PreComputeOutputPathMissing),
        };
        let is_dataset_required = match PreComputeArgs::get_boolean_env_var(IS_DATASET_REQUIRED) {
            Ok(value) => value,
            Err(_) => return Err(PreComputeIsDatasetRequiredMissing),
        };

        let mut dataset_url: Option<String> = None;
        let mut dataset_key: Option<String> = None;
        let mut dataset_checksum: Option<String> = None;
        let mut dataset_filename: Option<String> = None;

        if is_dataset_required {
            dataset_url = match PreComputeArgs::get_env_var(IEXEC_DATASET_URL) {
                Ok(value) => Some(value),
                Err(_) => return Err(PreComputeDatasetUrlMissing),
            };
            dataset_key = match PreComputeArgs::get_env_var(IEXEC_DATASET_KEY) {
                Ok(value) => Some(value),
                Err(_) => return Err(PreComputeDatasetKeyMissing),
            };
            dataset_checksum = match PreComputeArgs::get_env_var(IEXEC_DATASET_CHECKSUM) {
                Ok(value) => Some(value),
                Err(_) => return Err(PreComputeDatasetChecksumMissing),
            };
            dataset_filename = match PreComputeArgs::get_env_var(IEXEC_DATASET_FILENAME) {
                Ok(value) => Some(value),
                Err(_) => return Err(PreComputeDatasetFilenameMissing),
            };
        }

        let input_files_number = match PreComputeArgs::get_int_env_var(IEXEC_INPUT_FILES_NUMBER) {
            Ok(value) => value,
            Err(_) => return Err(PreComputeInputFilesNumberMissing),
        };
        let mut input_files: Vec<String> = Vec::with_capacity(input_files_number);
        for i in 1..input_files_number + 1 {
            let input_file_url =
                match PreComputeArgs::get_env_var(&format!("{}{}", IEXEC_INPUT_FILE_URL_PREFIX, i))
                {
                    Ok(url) => url,
                    Err(_) => return Err(PreComputeAtLeastOneInputFileUrlMissing),
                };
            input_files.push(input_file_url);
        }

        Ok(PreComputeArgs {
            chain_task_id: chain_task_id.to_string(),
            pre_compute_out,
            is_dataset_required,
            dataset_url,
            dataset_key,
            dataset_checksum,
            dataset_filename,
            input_files,
        })
    }

    pub fn get_env_var(env_var_name: &str) -> Result<String, ReplicateStatusCause> {
        match env::var(env_var_name) {
            Ok(value) => Ok(value),
            Err(_) => {
                error!("Required var is empty [name: {}]", env_var_name);
                Err(PreComputeFailedUnknownIssue) // FIXME
            }
        }
    }

    fn get_boolean_env_var(env_var_name: &str) -> Result<bool, ReplicateStatusCause> {
        let value: String = PreComputeArgs::get_env_var(env_var_name)?;

        match FromStr::from_str(&value.to_lowercase()) {
            Ok(boolean_value) => Ok(boolean_value),
            Err(_) => {
                error!(
                    "Expected 'true' or 'false' but got another value [name:{}, value:{}]",
                    env_var_name,
                    value.as_str()
                );
                Err(PreComputeFailedUnknownIssue) // FIXME
            }
        }
    }

    fn get_int_env_var(env_var_name: &str) -> Result<usize, ReplicateStatusCause> {
        let value: String = PreComputeArgs::get_env_var(env_var_name)?;

        match FromStr::from_str(&value) {
            Ok(int_value) => Ok(int_value),
            Err(_) => {
                error!(
                    "Expected integer but got another value [name:{}, value:{}]",
                    env_var_name,
                    value.as_str()
                );
                Err(PreComputeFailedUnknownIssue) // FIXME
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pre_compute::env_utils::{IEXEC_INPUT_FILES_NUMBER, IS_DATASET_REQUIRED};
    use crate::pre_compute::pre_compute_args::PreComputeArgs;
    use crate::pre_compute::replicate_status_cause::ReplicateStatusCause::PreComputeFailedUnknownIssue;
    use rstest::rstest;
    use std::env;

    fn clear_env_var(env_var_name: &str) {
        env::remove_var(env_var_name);
    }

    // region get_env_var
    #[test]
    fn should_get_env_var() {
        let env_var = "IEXEC_TASK_ID";
        clear_env_var(env_var);

        let task_id = "0x01".to_string();
        env::set_var(env_var, task_id.clone());

        let result = PreComputeArgs::get_env_var(env_var);
        assert!(
            result.is_ok(),
            "Can't get env var [error: {}]",
            result.unwrap_err()
        );
        let result = result.unwrap();
        assert_eq!(
            task_id, result,
            "The result is not as expected [expected: {task_id}, actual: {}]",
            result
        );
    }

    #[test]
    fn should_not_get_env_var_because_does_not_exist() {
        let env_var = "IEXEC_TASK_ID";
        clear_env_var(env_var);

        let expected_error = PreComputeFailedUnknownIssue;

        let result = PreComputeArgs::get_env_var(env_var);
        assert!(result.is_err(), "No value associated with env var");
        let error = result.unwrap_err();
        assert_eq!(
            expected_error, error,
            "The result is not as expected [expected: {expected_error}, actual: {}]",
            error
        );
    }
    // endregion

    // region get_int_env_var
    #[rstest]
    #[case("true", true)]
    #[case("True", true)]
    #[case("TRUE", true)]
    #[case("false", false)]
    #[case("False", false)]
    #[case("FALSE", false)]
    fn should_get_boolean_env_var(
        #[case] string_value: String,
        #[case] expected_boolean_value: bool,
    ) {
        let env_var = IS_DATASET_REQUIRED;
        clear_env_var(env_var);

        env::set_var(env_var, string_value);

        let result = PreComputeArgs::get_boolean_env_var(env_var);
        assert!(
            result.is_ok(),
            "Can't get boolean env var [error: {}]",
            result.unwrap_err()
        );
        let result = result.unwrap();
        assert_eq!(
            expected_boolean_value, result,
            "The result is not as expected [expected: {expected_boolean_value}, actual: {result}]"
        );
    }

    #[test]
    fn should_not_get_boolean_env_var_because_wrong_type() {
        let env_var = IS_DATASET_REQUIRED;
        clear_env_var(env_var);

        let expected_error = PreComputeFailedUnknownIssue;

        env::set_var(env_var, "Random string value");

        let result = PreComputeArgs::get_boolean_env_var(env_var);
        assert!(
            result.is_err(),
            "Random string value has been parsed [result: {}]",
            result.unwrap()
        );
        let error = result.unwrap_err();
        assert_eq!(
            expected_error, error,
            "The result is not as expected [expected: {expected_error}, actual: {}]",
            error
        );
    }
    // endregion

    // region get_int_env_var
    #[test]
    fn should_get_int_env_var() {
        let env_var = IEXEC_INPUT_FILES_NUMBER;
        clear_env_var(env_var);

        let value = 2;

        env::set_var(env_var, format!("{value}"));

        let result = PreComputeArgs::get_int_env_var(env_var);
        assert!(
            result.is_ok(),
            "Can't get int env var [error: {}]",
            result.unwrap_err()
        );
        let result = result.unwrap();
        assert_eq!(
            value, result,
            "The result is not as expected [expected: {value}, actual: {}]",
            result
        );
    }

    #[test]
    fn should_not_get_int_env_var_because_wrong_type() {
        let env_var = IEXEC_INPUT_FILES_NUMBER;
        clear_env_var(env_var);

        let expected_error = PreComputeFailedUnknownIssue;

        env::set_var(env_var, "Random string value");

        let result = PreComputeArgs::get_int_env_var(env_var);
        assert!(
            result.is_err(),
            "Random string value has been parsed [result: {}]",
            result.unwrap()
        );
        let error = result.unwrap_err();
        assert_eq!(
            expected_error, error,
            "The result is not as expected [expected: {expected_error}, actual: {}]",
            error
        );
    }
    // endregion
}
