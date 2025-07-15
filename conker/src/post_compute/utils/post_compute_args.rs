use crate::post_compute::replicate_status_cause::ReplicateStatusCause::{self, *};
use std::env;
use tracing::error;

pub fn get_env_var(env_var_name: &str) -> Result<String, ReplicateStatusCause> {
  match env::var(env_var_name) {
    Ok(value) => Ok(value),
    Err(_) => {
      error!("Required var is empty [name: {}]", env_var_name);
      Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE)
    }
  }
}

pub fn get_yes_or_no_boolean_env_var(env_var_name: &str) -> Result<bool, ReplicateStatusCause> {
    let value: String = get_env_var(env_var_name)?;
    Ok(value.to_ascii_lowercase() == "yes")
}
