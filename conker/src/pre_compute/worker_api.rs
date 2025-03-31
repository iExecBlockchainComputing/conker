use crate::pre_compute::replicate_status_cause::ReplicateStatusCause;
use log::{error, trace};
use serde_json::json;

use crate::logger_debug;
use tracing::{debug, /*error, event,*/ info /*, trace, warn*/};

const WORKER_HOST: &str = "worker:13100";

pub fn send_exit_cause_for_pre_compute_stage(
    chain_task_id: &str,
    exit_cause: &ReplicateStatusCause,
) -> Result<(), ()> {
  //
  logger_debug!("");

    send_exit_cause_to_host(chain_task_id, exit_cause, WORKER_HOST)
}

fn send_exit_cause_to_host(
    chain_task_id: &str,
    exit_cause: &ReplicateStatusCause,
    host: &str,
) -> Result<(), ()> {
    //
    logger_debug!("");
  
  
    let client = reqwest::blocking::Client::new();
    let url = format!("http://{}/compute/pre/{}/exit", host, chain_task_id);

    let body = json!({
        "exitMessage": exit_cause
    });

    let response = client.post(url).json(&body).send();
    trace!("Exit cause response [response: {:?}]", response);
    if response.is_err() {
        error!("Failed to report exitCause [exitCause:{}]", exit_cause);
        error!("{}", response.unwrap_err());
        return Err(());
    }

    let error_for_status = response.unwrap().error_for_status();
    if error_for_status.is_err() {
        error!("Failed to report exitCause [exitCause:{}]", exit_cause);
        error!("{:?}", error_for_status);
        return Err(());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::pre_compute::replicate_status_cause::ReplicateStatusCause::PreComputeInputFileDownloadFailed;
    use crate::pre_compute::worker_api::send_exit_cause_to_host;
    use std::collections::HashMap;
    use std::path::Path;
    use testcontainers::core::WaitFor;
    use testcontainers::{clients, Image};

    #[test]
    #[cfg_attr(feature = "no-docker", ignore)]
    fn should_send_exit_cause_to_host() {
        let docker = clients::Cli::default();
        let container = docker.run(WireMock::default());
        let port = container.get_host_port_ipv4(WIREMOCK_PORT);

        let url = format!("localhost:{port}");

        let result = send_exit_cause_to_host(
            "0x0000000000000000000000000000000000000000000000000000000000000200",
            &PreComputeInputFileDownloadFailed,
            &url,
        );
        assert!(result.is_ok(), "Exit cause can't be sent: {:?}", result);
    }

    #[test]
    #[cfg_attr(feature = "no-docker", ignore)]
    fn should_not_send_exit_cause_to_host_because_internal_server_error() {
        let docker = clients::Cli::default();
        let container = docker.run(WireMock::default());
        let port = container.get_host_port_ipv4(WIREMOCK_PORT);

        let url = format!("localhost:{port}");

        let result = send_exit_cause_to_host(
            "0x0000000000000000000000000000000000000000000000000000000000000500",
            &PreComputeInputFileDownloadFailed,
            &url,
        );

        assert!(
            result.is_err(),
            "Exit cause should not have been sent: {:?}",
            result
        );
    }

    // region WireMock
    const WIREMOCK_IMAGE_NAME: &str = "wiremock/wiremock";
    const WIREMOCK_IMAGE_TAG: &str = "3.3.1";
    const WIREMOCK_PORT: u16 = 8080;

    #[derive(Debug)]
    pub struct WireMock {
        volumes: HashMap<String, String>,
    }

    impl Default for WireMock {
        fn default() -> Self {
            let test_resources_directory = "resources/test";
            let mappings_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(test_resources_directory)
                .join("mappings");
            let mut volumes = HashMap::new();
            volumes.insert(
                mappings_path.to_str().unwrap().to_owned(),
                "/home/wiremock/mappings".to_owned(),
            );

            Self { volumes }
        }
    }

    impl Image for WireMock {
        type Args = ();

        fn name(&self) -> String {
            WIREMOCK_IMAGE_NAME.to_owned()
        }

        fn tag(&self) -> String {
            WIREMOCK_IMAGE_TAG.to_owned()
        }

        fn ready_conditions(&self) -> Vec<WaitFor> {
            vec![WaitFor::message_on_stdout("extensions:")]
        }

        fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
            Box::new(self.volumes.iter())
        }

        fn expose_ports(&self) -> Vec<u16> {
            vec![WIREMOCK_PORT]
        }
    }
    // endregion
}
