use std::env;

use log::error;
use crate::{logger_debug};
use tracing::{debug, /*error, event,*/ info /*, trace, warn*/};

use crate::post_compute::replicate_status_cause::ReplicateStatusCause;
use crate::post_compute::replicate_status_cause::ReplicateStatusCause::*;

pub fn get_env_var(env_var_name: &str) -> Result<String, ReplicateStatusCause> {
  //
  logger_debug!("");
  
  match env::var(env_var_name) {
    Ok(value) => Ok(value),
    Err(_) => {
      error!("Required var is empty [name: {}]", env_var_name);
      Err(POST_COMPUTE_FAILED_UNKNOWN_ISSUE)
    }
  }
}

pub fn get_yes_or_no_boolean_env_var(env_var_name: &str) -> Result<bool, ReplicateStatusCause> {
  //
  logger_debug!("");
    let value: String = get_env_var(env_var_name)?;
    Ok(value.to_ascii_lowercase() == "yes")
}
