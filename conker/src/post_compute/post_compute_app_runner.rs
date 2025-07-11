use std::panic;

use log::{error, info};

use worker_api::worker_api_client;
use worker_api_client::send_exit_cause_for_post_compute_stage;

use crate::post_compute::utils::env_utils::RESULT_TASK_ID;
use crate::post_compute::utils::post_compute_args::get_env_var;
use crate::{post_compute::post_compute_app, post_compute::worker_api};

pub fn start() -> i32 {
    info!("TEE post-compute started");

    let chain_task_id = match get_env_var(RESULT_TASK_ID) {
        Ok(value) => value,
        Err(_) => {
            error!("TEE post-compute cannot go further without taskID context");
            return 3;
        }
    };

    let app_run_caught_result = panic::catch_unwind(|| post_compute_app::run(&chain_task_id));
    let app_run_result = match app_run_caught_result {
        Ok(app_run_caught_result) => app_run_caught_result,
        Err(_) => {
            error!("Unexpected error happened [chainTaskId:{}]", chain_task_id);
            return 2;
        }
    };

    let exit_cause = match app_run_result {
        Ok(_) => {
            info!("TEE post-compute completed");
            return 0;
        }
        Err(exit_cause) => {
            error!(
                "TEE post-compute failed with a known exitCause [exitCause:{}]",
                exit_cause
            );
            exit_cause
        }
    };

    match send_exit_cause_for_post_compute_stage(&chain_task_id, &exit_cause) {
        Ok(_) => 1,
        Err(_) => {
            error!("Failed to report exitCause [exitCause:{}]", exit_cause);
            2
        }
    }
}
