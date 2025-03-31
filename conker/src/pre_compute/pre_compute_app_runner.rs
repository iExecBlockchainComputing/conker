use crate::env_utils::IEXEC_TASK_ID;
use crate::pre_compute_app;
use crate::pre_compute_args::PreComputeArgs;
use crate::worker_api::send_exit_cause_for_pre_compute_stage;
use log::{error, info};
use std::panic;
use tracing::{debug, error, /*event,*/ info /*, trace, warn*/};
use crate::logger_debug;

pub fn start() -> i32 {
    info!("TEE pre-compute started");

    let chain_task_id = match PreComputeArgs::get_env_var(IEXEC_TASK_ID) {
        Ok(value) => value,
        Err(_) => {
            error!("TEE pre-compute cannot go further without taskID context");
            return 3;
        }
    };

    let app_run_caught_result = panic::catch_unwind(|| pre_compute_app::run(&chain_task_id));
    let app_run_result = match app_run_caught_result {
        Ok(app_run_caught_result) => app_run_caught_result,
        Err(_) => {
            error!("Unexpected error happened [chainTaskId:{}]", chain_task_id);
            return 2;
        }
    };

    let exit_cause = match app_run_result {
        Ok(_) => {
            info!("TEE pre-compute completed");
            return 0;
        }
        Err(exit_cause) => {
            error!(
                "TEE pre-compute failed with a known exitCause [exitCause:{}]",
                exit_cause
            );
            exit_cause
        }
    };

    match send_exit_cause_for_pre_compute_stage(&chain_task_id, &exit_cause) {
        Ok(_) => 1,
        Err(_) => {
            error!("Failed to report exit exitCause [exitCause:{}]", exit_cause);
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::env_utils::IEXEC_TASK_ID;
    use crate::pre_compute_app_runner::start;
    use std::env;

    #[test]
    fn should_exit_3_if_no_chain_task_id() {
        env::remove_var(IEXEC_TASK_ID);

        let exit_code = start();
        assert_eq!(3, exit_code);
    }

    #[ignore]
    #[test]
    fn should_exit_2_if_app_run_panicked() {
        // TODO
    }

    #[ignore]
    #[test]
    fn should_exit_0_if_app_run_succeeded() {
        // TODO
    }

    #[ignore]
    #[test]
    fn should_exit_1_if_send_exit_cause_succeeded() {
        // TODO
    }

    #[test]
    fn should_exit_2_if_send_exit_cause_failed() {
        env::set_var(IEXEC_TASK_ID, "0x01");

        let exit_code = start();
        assert_eq!(2, exit_code);
    }
}
