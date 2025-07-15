// ====================================
// import
// ====================================
use crate::{logger_debug, module_utils::util, post_compute, pre_compute};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use bollard::container::{
	Config, CreateContainerOptions, InspectContainerOptions,
	LogOutput, LogsOptions, RemoveContainerOptions, WaitContainerOptions,
};
use bollard::image::{CreateImageOptions, PruneImagesOptions, RemoveImageOptions};
use bollard::models::MountTypeEnum;
use bollard::secret::{
	AuthConfig, HostConfig, ImagePruneResponse, Mount, PortBinding, PortMap, RestartPolicy,
	RestartPolicyNameEnum,
};
use bollard::volume::PruneVolumesOptions;
use bollard::{models::ContainerInspectResponse, Docker};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::stream::StreamExt;
use lazy_static::lazy_static;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::{self};
use tokio::fs::OpenOptions;
use std::collections::HashMap;
use std::fs::{self};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use std::{env, fs::File /*, io::Read*/};
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tracing::{debug, error, /*event,*/ info /*, trace, warn*/};
use uuid::Uuid;

// ====================================
// const
// ====================================
pub const PULLING: &str = "Pulling";
pub const PULLED: &str = "Pulled";
pub const ATTESTING: &str = "Attesting";
pub const ATTESTED: &str = "Attested";
pub const PRECOMPUTE: &str = "Precompute";
pub const CREATING: &str = "Creating";
pub const CREATED: &str = "Created";
pub const STARTING: &str = "Starting";
pub const RUNNING: &str = "Running";
pub const WAITING: &str = "Waiting";
pub const DELETING: &str = "Deleting";
pub const CANCELLED: &str = "Cancelled";
pub const FAILED: &str = "Failed";
pub const SUCCESS: &str = "Success";
pub const POSTCOMPUTE: &str = "Postcompute";

#[derive(Debug, Clone)]
pub enum TaskStatus {
	Starting,
	Running,
	Failed,
}

// ====================================
// global
// ====================================
lazy_static! {
	// The Option<Task> is the data protected by the Mutex.
	// Arc::new() wraps the Mutex with an atomic
	// reference counter so it can be shared.
	pub static ref WORKER: Arc<Mutex<Option<Task>>> = Arc::new(Mutex::new(None));
	pub static ref TASK_MUTEX: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
	pub static ref HAS_PRECOMPUTE_SERVICE: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

// ====================================
// struct
// ====================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Events {
	pub action: String,
	pub message: String,
	pub time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterAuth {
	pub username: String,
	pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PortBind {
	pub published_port: u16, // impossible de get more than 65535 with u16
	pub target_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageInfo {
	pub register_auth_info: Option<RegisterAuth>,
	pub image_name: String,
	pub cmd: String,
	pub max_execution_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Container {
	pub name: String,
	#[serde(default)]
	pub env: Option<Vec<String>>,
	pub image_info: Option<ImageInfo>,
	pub ports: Vec<PortBind>,
	pub mounts: Vec<bollard::models::Mount>,
	pub kms_endpoints: Vec<String>,
	// M - vMain
	pub session_id: String,
	pub worker_host: String,
}

#[derive(Debug, Default)]
pub struct CancelSender {
	sender: Option<oneshot::Sender<()>>,
	receiver: Option<oneshot::Receiver<()>>,
}

impl Clone for CancelSender {
	fn clone(&self) -> Self {
		Self {
			sender: None,
			receiver: None,
		}
	}
}

// =====================================================================
// impl CancelSender
// =====================================================================
impl CancelSender {
	pub fn new() -> Self {
		//
		logger_debug!("");

		// inits both sender and receiver
		let (sender, receiver) = oneshot::channel::<()>();
		Self {
			sender: Some(sender),
			receiver: Some(receiver),
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Task {
	pub id: String,
	pub container_conf: Container,
	pub status: String,
	pub is_cancel: bool,
	#[serde(skip)]
	pub cancel_chan: CancelSender,
	pub events: Vec<Box<Events>>,
	pub container_inspect: Option<ContainerInspectResponse>,
	#[serde(skip)]
	pub save_mutex: Arc<Mutex<()>>,
	#[serde(skip)]
	pub secret_save_dir: String,
	#[serde(skip)]
	pub task_info_save_path: String,
	#[serde(skip)]
	pub secret_provider_agent: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Services {
	#[serde(rename = "pre-compute", skip_serializing_if = "Option::is_none")]
	pre_compute: Option<HashMap<String, String>>,

	app: HashMap<String, String>,

	#[serde(rename = "post-compute")]
	post_compute: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppResponse {
	pub exit_cause: String,
	pub stdout: String,
	pub stderr: String,
	pub exit_code: i64,
}

// ---------------------------------------------------
// F - get_task_status
// ---------------------------------------------------
pub async fn get_task_status() -> Result<Arc<Task>, String> {
	//
	logger_debug!("");

	//
	let mut worker_guard = WORKER.lock().await;

	// Check if there is a Task inside "worker_guard"
	if let Some(ref mut task) = *worker_guard {
		info!("Variable task is instancied.");

		match task.get_container_info().await {
			Ok(Some(info)) => {
				task.container_inspect = Some(info);
			}
			Ok(None) => {
				info!("No container info available.");
			}
			Err(err) => {
				error!("Failed to get container info: {}", err);
			}
		}

		Ok(Arc::new(task.clone()))
	} else {
		info!("Variable task isn't instancied yet, is going to return 'no task now'");
		Err("no task now".to_string())
	}
}

// ---------------------------------------------------
// impl Task
// ---------------------------------------------------
impl Task {
	// ---------------------------------------------------
	// M - get_container_info
	// ---------------------------------------------------
	pub async fn get_container_info(
		&self,
	) -> Result<Option<bollard::models::ContainerInspectResponse>, Box<dyn std::error::Error>> {
		//
		logger_debug!("");

		//
		info!("module_worker.rs > Task > get_container_info()");
		info!("t.Status = {}", self.status);

		//
		if self.status == RUNNING.to_string() || self.status == CREATED.to_string() {
			let docker = Docker::connect_with_local_defaults()?;
			let container_info = docker.inspect_container(&self.container_conf.name, None).await;

			match container_info {
				Ok(info) => {
					info!("get {} container info successful", self.container_conf.name);
					Ok(Some(info))
				}
				Err(err) => {
					tracing::error!("{}", err);
					Err(Box::new(err))
				}
			}
		} else {
			Ok(None)
		}
	}

	// ---------------------------------------------------
	// M - save_task
	// ---------------------------------------------------
	pub async fn save_task(&self) -> Result<(), std::io::Error> {
		//
		logger_debug!("");

		// Mutex lock to avoid many writing at the same time
		let _lock = self.save_mutex.lock().await;

		// Serialization of the Task objet into a JSON format
		let task_info = serde_json::to_vec(self)?;
		let task_info_debug = serde_json::to_string_pretty(self)?;

		warn!("task_info_debug = {:#?}", task_info_debug);

		// File writing
		let mut file = File::create(&self.task_info_save_path)?;
		file.write_all(&task_info)?;

    info!("saving task info successful");

		Ok(())
	}

	// ---------------------------------------------------
	// M - check_param
	// ---------------------------------------------------
	pub async fn check_param(&self) -> Result<(), String> {
		//
		logger_debug!("");

		// Port checking
		for p in &self.container_conf.ports {
			if p.published_port < 30000 || p.published_port > 65534 {
				return Err("host port must be between 30000 and 65534".to_string());
			}
		}

		//
		Ok(())
	}

	// ---------------------------------------------------
	// M - Task - run
	// ---------------------------------------------------
	pub async fn run(&mut self) -> Result<AppResponse, String> {
		//
		logger_debug!("");

		//
		let image_info = &self.container_conf.image_info;

		//
		// pull_image
		//
		if let Err(err) = self.pull_image(image_info.clone()).await {
			error!("ERROR-> Pulling inage , error {}", err);
			return Err(err);
		}

		//
		// attest
		//
		if let Err(err) = self.attest().await {
			self.status = FAILED.to_string();
			error!("Error: {}", err);
			return Err(err);
		}

		//
		// create_dirs
		//
		if let Err(err) = self.create_dirs().await {
			self.status = FAILED.to_string();
			error!("Error: {}", err);
			return Err(err);
		}

		//
		// run_pre_compute
		//
		if let Err(err) = self.run_pre_compute().await {
			self.status = FAILED.to_string();
			error!("Error: {}", err);
			return Err(err);
		}

		//
		// run_compute
		//
    let m_response =  self.run_compute().await;
    let app_response;

    match m_response {
      Ok(response) => {
        info!("response OK from run_compute");
        app_response = response;
        warn!("app_response.stdout = {}", app_response.stdout);
        warn!("app_response.stderr = {}", app_response.stderr);
        warn!("app_response.exit_cause = {}", app_response.exit_cause);
        warn!("app_response.exit_code = {}", app_response.exit_code);
        warn!("app_response = {:?}", app_response);
        warn!("app_response = {:#?}", app_response);

      }
      Err(e) => {
        self.status = FAILED.to_string();
        error!("Error: {}", e);
			  return Err(e);
      }
    }

		// 
		match env::var(util::IEXEC_TASK_ID) {
			Ok(task_id) => {
				info!("Found IEXEC_TASK_ID: {}", task_id);
			}
			Err(e) => {
				error!("Failed to read IEXEC_TASK_ID: {}", e);
			}
		}

		// 
		let chain_task_id = env::var(util::RESULT_TASK_ID).ok();

		//
		// run_post_compute
		//
		if let Err(err) = self.run_post_compute(chain_task_id).await {
			self.status = FAILED.to_string();
			error!("Error: {}", err);
			return Err(err);
		}

    // Event Success
    self.status = SUCCESS.to_string();
		let mesg = format!("post-compute-success");
		if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
			return Err(format!("Event can't be added: {}", err));
		};
		info!("{}", mesg);

    //
		// clear_task_files
		//
		if let Err(err) = self.clear_task_files().await {
			self.status = FAILED.to_string();
			error!("Error: {}", err);
			return Err(err);
		}

		//
		Ok(app_response)
	}

	// ---------------------------------------------------
	// M - Task - clear_task_files
	// ---------------------------------------------------
  pub async fn clear_task_files(&self) -> Result<(), String> {
    // 1. Mounts
    // Remove all directories from the vector of mounts.
    for mount in &self.container_conf.mounts {
      //
        match &mount.source {
            //
            Some(source) => {
                fs::remove_dir_all(source)
                    .map_err(|e| format!("Failed to delete mount directory {}: {}", source, e))? ;
                info!("Directory {} deleted", source);
            }
            //
            None => {
                info!("Skipping mount with no source.");
                continue; // Next mount.
            }
        }
    }

    // 2. Tmp
    // Removing the temporary directory "post-compute-tmp".
    let tmp_dir = "/post-compute-tmp";
    fs::remove_dir_all(tmp_dir)
        .map_err(|e| format!("Failed to delete temporary directory {}: {}", tmp_dir, e))?;
    info!("Directory {} deleted", tmp_dir);

    // 3. Read content directory
    let entries = fs::read_dir(&self.secret_save_dir)
        .map_err(|e| format!("Failed to read directory {}: {}", self.secret_save_dir, e))?;

    // 4. Remove each element in the directory
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?; // For corrupted or missing files and lack of permissions.
        let path = entry.path();
        fs::remove_dir_all(&path)
            .map_err(|e| format!("Failed to delete {}: {}", path.display(), e))?;
        info!("Deleted {}", path.display());
    }

    info!("All Task Files deleted!");

    Ok(())
}

	// ---------------------------------------------------
	// M - Task - run_compute
	// ---------------------------------------------------
	pub async fn run_compute(&mut self) -> Result<AppResponse, String> {
		//
		logger_debug!("");


    		// App response.
		let app_response_default = AppResponse {
			exit_cause: FAILED.to_string(),
			stdout: "".to_string(),
			stderr: "".to_string(),
			exit_code: -1,
		};


		//
		let app_response = self.create_and_start_container().await;


		//
		match app_response {
			Ok(app_resp) => {
				info!("run_compute OK: {:#?}", app_resp);
				Ok(app_resp)
			}
			Err(err) => {
				// Event Failed
				self.status = FAILED.to_string();
				
        //
        let mesg = format!("exit_cause: {:?}, stdout: {:?}, stderr: {:?}, exit_code: {}, run_compute error: {:?}",
        app_response_default.exit_cause, app_response_default.stdout, app_response_default.stderr, app_response_default.exit_code, err);


				if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
					return Err(format!("Event can't be added: {}", err));
				};
				error!("run_compute failed: {:#?}", err);

        //
				Err(mesg)
			}
		}
	}

	// ---------------------------------------------------
	// M - Task - create_and_start_container
	// ---------------------------------------------------
	pub async fn create_and_start_container(&mut self) -> Result<AppResponse, String> {
		//
		logger_debug!("");

		//
		self.status = CREATING.to_string();
		let mesg = "Begin to create container".to_string();
		if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
			return Err(format!("Event can't be added: {}", err));
		}
		//
		info!("mesg = {}", mesg);

		// App response.
		let mut app_response = AppResponse {
			exit_cause: "FAILED".to_string(),
			stdout: "".to_string(),
			stderr: "".to_string(),
			exit_code: -1,
		};

		// Docker client.
		let docker = Docker::connect_with_local_defaults()
			.map_err(|e| format!("Failed to connect to Docker: {}", e))?;

		// HostConfig with "/secret" as mount
		let host_config = HostConfig {
			mounts: Some(self.build_mounts()),
			port_bindings: Some(self.build_port_bindings()),
			restart_policy: Some(RestartPolicy {
				name: Some(RestartPolicyNameEnum::ALWAYS),
				maximum_retry_count: None,
			}),
			..Default::default()
		};

		//
		let cmd_string = self.container_conf.image_info.clone().unwrap().cmd;
		debug!("cmd_string = {:#?}", cmd_string);

		let vec_cmd = vec![cmd_string];
		debug!("vec_cmd = {:#?}", vec_cmd);

		// Container config with HostConfig integrated
		let config = Config {
			image: Some(self.container_conf.image_info.clone().unwrap().image_name.clone()),
			cmd: Some(vec_cmd), // M - Added v2
			stop_timeout: Some(self.container_conf.image_info.clone().unwrap().max_execution_time), // M - Added v2
			env: self.container_conf.env.clone(),
			exposed_ports: self.build_exposed_ports(),
			host_config: Some(host_config), // HostConfig added here
			..Default::default()
		};

		//
		// Config
		//
		debug!("config = {:#?}", config);

		let create_options = CreateContainerOptions {
			name: &self.container_conf.name,
			platform: None,
		};

		//
		let response = docker
			.create_container(Some(create_options), config)
			.await
			.map_err(|e| format!("Failed to create container: {}", e))?;

		//
		if !response.warnings.is_empty() {
			warn!("Warnings: {:?}", response.warnings);
		}

		//
		let success_msg = format!("create container successful: {:?}", response.warnings);
		info!("{}", success_msg);

		//
		self.status = CREATED.to_string();
		if let Err(err) = self.add_event(self.status.clone(), &success_msg).await {
			return Err(format!("Event can't be added: {}", err));
		}

		// 22222
		//
		// Start container
		//
		// 22222

		// Event Starting
		self.status = STARTING.to_string();
		let mesg = format!("begin to start container");
		if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
			return Err(format!("Event can't be added: {}", err));
		};

		info!("{}", mesg);

		//
		let docker = Docker::connect_with_local_defaults()
			.map_err(|e| format!("Failed to connect to Docker: {}", e))?;

		//
		let ctx = tokio::time::timeout(
			std::time::Duration::from_secs(10),
			docker.start_container(
				&self.container_conf.name,
				None::<bollard::container::StartContainerOptions<String>>,
			),
		)
		.await;

		// Container start
		match ctx {
			Ok(_inner) => {}

			//
			Err(_) => {
				//
				self.status = FAILED.to_string();
				let mesg = format!("Container '{}' is NOT running", self.container_conf.name);
				//
				if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
					//
					return Err(format!("Event can't be added: {}", err));
				}

				//
				return Err("Timeout starting container".to_string());
			}
		}

		// Event Running
		self.status = RUNNING.to_string();
		let mesg = format!("Container '{}' is running", self.container_conf.name);
		//
		if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
			//
			return Err(format!("Event can't be added: {}", err));
		}

		//
		// Async
		//

		let cancel_rx = self.cancel_chan.receiver.take().expect("Cancel receiver missing");
		let container_id = response.id.clone();
		let cli_clone = docker.clone();
		let task_clone = self.clone();

		tokio::spawn(async move {
			task_clone.monitor_cancel(cli_clone, container_id, cancel_rx).await;
		});

		//
		let mut wait_stream = docker.wait_container(
			&response.id,
			Some(WaitContainerOptions {
				condition: "not-running".to_string(),
			}),
		);

		//
		let status_ch = wait_stream.next().await;

		//
		let status_str = match &status_ch {
			// 
			Some(Ok(response)) => response.status_code.to_string(),
			//
			Some(Err(e)) => "unknown".to_string(),
			None => "no response".to_string(),
		};

		//
		let error_str = match &status_ch {
			Some(Err(e)) => e.to_string(),
			_ => "none".to_string(),
		};

		// Event Waiting
		self.status = WAITING.to_string();
		let mesg = format!(
			"Container '{}' is waiting, status: {}, error: {}",
			self.container_conf.name, status_str, error_str
		);
		//
		if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
			//
			return Err(format!("Event can't be added: {}", err));
		}

		//
		// Select
		//
		match status_ch {
			Some(Err(e)) => {
				// R
				return Err(format!("error waiting for container: {}", e).into());
			}
			Some(Ok(status)) => {
				//
				info!("Container exited with status code: {}", status.status_code);

				//
				let logs_options = LogsOptions::<&str> {
					stdout: true,
					stderr: true,
					..Default::default()
				};

				//
				let mut logs_stream = docker.logs(&response.id, Some(logs_options));

				//
				let mut stdout_buf: Vec<u8> = Vec::new();
				let mut stderr_buf: Vec<u8> = Vec::new();

				//
				while let Some(result) = logs_stream.next().await {
					match result {
						Ok(log_output) => {
							//
							match log_output {
								LogOutput::StdOut {
									message,
								} => {
									stdout_buf.extend_from_slice(&message);
								}
								LogOutput::StdErr {
									message,
								} => {
									stderr_buf.extend_from_slice(&message);
								}
								_ => (), // Ignore others.
							}
						}

						Err(e) => {
							return Err(format!("error reading logs: {}", e).into());
						}
					}
				}

				//
				let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
				let stderr = String::from_utf8_lossy(&stderr_buf).to_string();

				info!("Container stdout : {}", stdout);
				info!("Container Stderr : {}", stderr);

				//
				let container_info = docker
					.inspect_container(&response.id, None::<InspectContainerOptions>)
					.await
					.map_err(|e| format!("Ereror inspecting container: {}", e))?;

				//
				let exit_code = container_info.state.and_then(|s| s.exit_code).unwrap_or(0);

				//
				info!("Container Exit Code: {}", exit_code);

				//
				let exit_cause = if exit_code != 0 {
					FAILED
				} else {
					SUCCESS
				}
				.to_string();

				//
				app_response = AppResponse {
					exit_cause,
					stdout,
					stderr,
					exit_code: status.status_code,
				};

				//
				if status.status_code != 0 {
					//
					// Event Failed
					self.status = FAILED.to_string();
					let mesg = format!(
						"Container '{}' failed with status code: {}",
						self.container_conf.name, status.status_code
					);
					//
					if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
						//
						return Err(format!("Event can't be added: {}", err));
					}
					debug!(mesg);

					// R
					return Err(
						format!("Docker container failed, status code: {}", status.status_code).into(),
					);

					//
				}
				// if status.status_code != 0
				else {
					//
					self.status = POSTCOMPUTE.to_string();
					let mesg = format!(
						"Container '{}' finished successfully, status {:?}",
						self.container_conf.name, status
					);
					//
					if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
						//
						return Err(format!("Event can't be added: {}", err));
					}
					debug!(mesg);

					// R
					return Ok(app_response);
				}
			}
			None => {
				// R
				return Err("no response from container wait".into());
			}
		}

		//
		// Ok(app_response)
	}

	// ---------------------------------------------------
	// M - Task - monitor_cancel
	// ---------------------------------------------------
	pub async fn monitor_cancel(
		&self,
		docker: Docker,
		container_id: String,
		cancel_rx: oneshot::Receiver<()>,
	) {
		//
		logger_debug!("");

		//
		if cancel_rx.await.is_ok() {
			//
			info!("Cancel signal received. Stopping container...");

			//
			if let Err(e) = docker.stop_container(&container_id, None).await {
				//
				info!("Error stopping container: {}", e);
			} else {
				//
				info!("Container stopped successfully.");
			}
		}

	}

	// ---------------------------------------------------
	// M - Task - build_mounts
	// ---------------------------------------------------
	fn build_mounts(&self) -> Vec<Mount> {
		let mut mounts = self.container_conf.mounts.clone();
		mounts.push(Mount {
			target: Some("/secret".to_string()),
			source: Some(self.secret_save_dir.clone()),
			typ: Some(MountTypeEnum::BIND),
			read_only: Some(true),
			..Default::default()
		});
		mounts
	}

	// ---------------------------------------------------
	// M - Task - build_port_bindings
	// ---------------------------------------------------
	fn build_port_bindings(&self) -> PortMap {
		let mut port_map = HashMap::new();
		for port in &self.container_conf.ports {
			let key = format!("{}/tcp", port.target_port);
			port_map.insert(
				key,
				Some(vec![PortBinding {
					host_ip: Some("0.0.0.0".to_string()),
					host_port: Some(port.published_port.to_string()),
				}]),
			);
		}
		port_map
	}

	// ---------------------------------------------------
	// M - Task - build_exposed_ports
	// ---------------------------------------------------
	fn build_exposed_ports(&self) -> Option<HashMap<String, HashMap<(), ()>>> {
		let mut exposed_ports = HashMap::new();
		for port in &self.container_conf.ports {
			let key = format!("{}/tcp", port.target_port);
			exposed_ports.insert(key, HashMap::new());
		}
		Some(exposed_ports)
	}

	// ---------------------------------------------------
	// M - Task - create_dirs
	// ---------------------------------------------------
	pub async fn create_dirs(&self) -> Result<(), String> {
		//
		logger_debug!("");

		//
		for mount in &self.container_conf.mounts {
			//
			fs::create_dir_all(mount.source.as_deref().ok_or("Mount source is None")?)
				.map_err(|e| e.to_string())?;

			info!("Directory created with mount.source: {:#?}", mount.source);

			if mount.target == Some("/iexec_out".to_string()) {
				if let Some(source) = mount.source.as_deref() {
					// set env
					env::set_var("IEXEC_OUT", source);

					// check env
					if std::env::var("IEXEC_OUT").is_err() {
						error!("Failed to set environment variable: IEXEC_OUT");
					}
				}
			} else if mount.target.as_deref() == Some("/iexec_in") {
				if let Some(source) = mount.source.as_deref() {
					// set env
					env::set_var("IEXEC_PRE_COMPUTE_OUT", source);

					// check env
					if std::env::var("IEXEC_PRE_COMPUTE_OUT").is_err() {
						error!("Failed to set environment variable: IEXEC_PRE_COMPUTE_OUT");
					}
				}
			}
		}

		fs::create_dir_all("/post-compute-tmp")
			.map_err(|e| format!("Failed to create directory: {}", e))?;

		info!("Directory created: {}", "/post-compute-tmp");

		Ok(())
	}

	// ---------------------------------------------------
	// M - Task - attest
	// ---------------------------------------------------
	pub async fn attest(&mut self) -> Result<(), String> {
		//
		logger_debug!("");

		//
		self.status = ATTESTING.to_string();
		let mesg = "Begin to do remote attestation".to_string();
		if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
			return Err(format!("Event can't be added: {}", err));
		}

		//
		info!("{}", mesg);

		info!("attest - - - - - - 1");
		//
		let skip_attest = false; 

		if !skip_attest {
			info!("attest - - - - - - 2");
			let docker = Docker::connect_with_local_defaults()
				.map_err(|e| format!("Failed to connect to Docker: {}", e))?;

			//
			let image_name = &self.container_conf.image_info.as_ref().unwrap().image_name;
			//
			let image_inspect = docker
				.inspect_image(image_name)
				.await
				.map_err(|e| format!("Failed to inspect image '{}': {}", image_name, e))?;
			info!("attest - - - - - - 3");

			warn!("image_inspect = {:#?}", image_inspect);

			fs::create_dir_all(&self.secret_save_dir).map_err(|e| e.to_string())?;

			info!("attest - - - - - - 4");

			// ERROR
			if self.container_conf.kms_endpoints.is_empty() {
				let msg = "no kms endpoint configured".to_string();
				info!("attest - - - - - - 5");

				//
				if let Err(err) = self.add_event(self.status.clone(), &msg).await {
					info!("attest - - - - - - 6");
					return Err(format!("Event can't be added: {}", err));
				}
				error!("{}", msg);
				info!("attest - - - - - - 7");
				return Err(msg);
			}

			//
			let image_id = image_inspect.id.expect("Image ID is missing.");

			info!("attest - - - - - - 8");
			//
			let split_id: Vec<&str> = image_id.split(':').collect();

			// ERROR
			if split_id.len() != 2 {
				let msg = "image id format error".to_string();
				info!("attest - - - - - - 9");
				//
				if let Err(err) = self.add_event(self.status.clone(), &msg).await {
					return Err(format!("Event can't be added: {}", err));
				}

				info!("attest - - - - - - 10");
				error!("{}", msg);

				return Err(msg);
			}

			info!("attest - - - - - - 11");
			//
			for k in &self.container_conf.kms_endpoints {
				let envs =
					vec![format!("appId={}", &self.container_conf.session_id), format!("kbsEndpoint={}", k)];


				warn!("k = {}", k); 
				warn!("envs = {:#?}", envs);

				let mut args_list = vec!["-v", "nullverifier", "-f", "-s"];
				// 
				let secret_file_path =
					format!("{}/secret-{}.json", self.secret_save_dir, &self.container_conf.session_id);
				args_list.push(&secret_file_path);

				warn!("args_list = {:#?}", args_list); 
				warn!("secret_provider_agent = {:#?}", &self.secret_provider_agent);
				warn!("&[&args_list] = {:#?}", &[&args_list]);

				info!("attest - - - - - - 11-A");
				let err_code = run_actuator_cmd(&self.secret_provider_agent, &envs, &args_list);
				info!("attest - - - - - - 11-B");

				warn!("err_code = {:#?}", err_code);

				//
				match err_code {
					Ok(code) => {
						if code != 0 {
							let _ = fs::remove_dir_all(&self.secret_save_dir);
							let msg = format!("get secret failed, error: {}", code);

							info!("attest - - - - - - 12");

							//
							match self.add_event(self.status.clone(), &msg).await {
								Ok(_) => {}
								Err(err) => {
									error!("Error when adding the event: {}", err);
								}
							}

							error!("{}", msg);
							return Err(msg);
						}
						// Go B
						else {
							// 1
							let json_content = fs::read_to_string(&secret_file_path)
								.map_err(|e| format!("Failed to read file: {}", e))?;

							//
							warn!("secret_file_path = {:#?}", &secret_file_path);
							//
							warn!("json_content = {:#?}", &json_content);

							// 2 - Convert the JSON file into the Services struct
							let services: Services = serde_json::from_str(&json_content)
								.map_err(|e| format!("Error parsing JSON data: {}", e))?;

							//
							info!("services: {:?}", services);

							// 3 - Check if pre-compute Services exists in the JSON file.
							// If yes, set has_pre_compute_service to true.
							let mut has_pre_compute_service = HAS_PRECOMPUTE_SERVICE.lock().await; // get the mutex

							*has_pre_compute_service = services.pre_compute.is_some(); // get true or false

							//
							if *has_pre_compute_service {
								info!("Pre-compute service exists.");
							}

							// 4 - Retrieve the app and post-compute Services into a vector.
							// The app and post-compute data must exist.
							let mut service_map =
								vec![("app", &services.app), ("post-compute", &services.post_compute)];

							//
							warn!("service_map = {:#?}", service_map.clone());

							// 5 - Adding the pre-compute Services in the previous vector only if it exists.
							if *has_pre_compute_service {
								warn!("Adding the pre-compute service");
								service_map.push(("pre-compute", services.pre_compute.as_ref().unwrap()));
								warn!("service_map with pre_compute_service = {:#?}", service_map.clone());
							}

							// 6 - Iterate through the vector -> (service_name, env_vars[String][String]).
							for (service_name, env_vars) in &service_map {
								info!(
									"Setting environment variables for service: --> service_name = {}",
									service_name
								); // service_name = "app"

								warn!("env_vars = {:#?}", env_vars);

								//
								for (key, value) in *env_vars {
									info!("Setting environment variable: key = value --> {} = {}", key, value);

									//
									if *service_name == "app" {
										// Insert all env_vars from "app" service_name to the  container_conf.env Vec<String>
										info!("service_name = {:#?}", service_name); // service_name = "app"

										//
										if let Some(env) = self.container_conf.env.as_mut() {
											warn!("Before env = {:#?}", env);
											env.push(format!("{}={}", key, value));
											info!("After env.pushed, env = {:#?}", env);
										} else {
											warn!("`env` is None in container_conf");
										}

										//
										warn!("INSIDE 1 - service_map");
									} else {
										env::set_var(&key, &value); // Insert all other service_name data to the general env.
										warn!("INSIDE 2 - service_map");
									}
								}
							}
						}
						// Go E
					}
					Err(err) => {
						// Err
						error!("Failed to run actuator command: {}", err);
					}
				}
			}
		}

		self.status = ATTESTED.to_string();
		info!("attest - - - - - - 14");
		//
		match self.add_event(self.status.clone(), "do remote attesting successful").await {
			Ok(_) => {}
			Err(err) => {
				error!("Error when adding the event: {}", err);
			}
		}

		Ok(())
	}

	// ---------------------------------------------------
	// M - run_pre_compute
	// ---------------------------------------------------
	pub async fn run_pre_compute(&mut self) -> Result<(), String> {
		//
		logger_debug!("");

		info!("TEE pre-compute started");

		let has_pre_compute_service = HAS_PRECOMPUTE_SERVICE.lock().await;


		info!("~ ~ ~ ~ ~ 0");

    // Check if the pre compute service is available (from the  attest method with the JSON data -> Struc Services is filled if yes)
		if *has_pre_compute_service {
			warn!("has_pre_compute_service is true so let's do the run_pre_compute method.");
			info!("~ ~ ~ ~ ~ 1");

			// Set the default value to "" if there is no IEXEC_TASK_ID.
			let chain_task_id = env::var(util::IEXEC_TASK_ID).unwrap_or_else(|_| String::new());

      //
			if chain_task_id.is_empty() { // chain_task_id -> ""
        warn!("~ ~ ~ ~ ~ 1.A");
        //
				error!("TEE pre-compute cannot go further without taskID context");
				return Err("TEE pre-compute cannot go further without taskID context".to_string());
      }
      
			// Status
			self.status = PRECOMPUTE.to_string();
			let mesg = "pre-compute service running".to_string();
			info!("mesg = {:#?}", mesg);
			match self.add_event(PRECOMPUTE.to_string(), &mesg).await {
        Ok(_) => {}
				Err(err) => {
          error!("Error when adding the event: {}", err);
				}
			}
      
			//
			// pre_compute_app::run()
			//
			let exit_code = pre_compute::pre_compute_app::run(&chain_task_id).await;
      
			// Check
			match exit_code {
        Ok(_) => {
          //
					info!("TEE pre-compute completed");
				}
				Err(e) => {
          // 
          let message_error = format!("TEE pre-compute failed with known error: {:?}", e);
					error!(message_error);
          
					// 
          warn!("~ ~ ~ ~ ~ 1.B");
          return Err(message_error);
				}
			} // match exit_code 
		} // 1

		info!("~ ~ ~ ~ ~ 2");

    //
		Ok(())
	}

	// ---------------------------------------------------
	// M - run_post_compute
	// ---------------------------------------------------
	pub async fn run_post_compute(&mut self, chain_task_id: Option<String>) -> Result<(), String> {
		//
		logger_debug!("");

		// 
		info!("TEE post-compute started");

		info!("PC --------------- 1");

		let result: Result<(), post_compute::replicate_status_cause::ReplicateStatusCause> =
			post_compute::post_compute_app::run(chain_task_id.clone().unwrap().as_str());

      info!("PC --------------- 2");

    //
		match result {
			Ok(_) => {
				info!("PC --------------- 2.1");
				// 
				info!("Post compute started for task ID: {}", chain_task_id.clone().unwrap());
		

        // Status
        self.status = POSTCOMPUTE.to_string();
        let mesg = "post-compute service running".to_string();
        info!("mesg = {:#?}", mesg);
        match self.add_event(POSTCOMPUTE.to_string(), &mesg).await {
          Ok(_) => {}
          Err(err) => {
            error!("Error when adding the event: {}", err);
          }
        }

        //
				Ok(())
			}
			Err(e) => {
        //
        let message_error = format!("TEE post-compute failed with a known error: {:?}", e);
        error!(message_error);

        //
        Err(message_error)
      }


		}

	}

	// ---------------------------------------------------
	// M - Task - add_event
	// ---------------------------------------------------
	pub async fn add_event(&mut self, action: String, message: &str) -> Result<(), String> {
		//
		logger_debug!("");

		//
		let eve = Events {
			action: action,
			message: message.to_string(),
			time: Utc::now(),
		};

		self.events.push(Box::new(eve));

		//
		if let Err(err) = self.save_task().await {
			let error_message = format!("save task info failed, error: {}", err);
			log::error!("{}", error_message);
			return Err(error_message);
		}

		//
		Ok(())
	}

	// ---------------------------------------------------
	// M - Task - pull_image
	// ---------------------------------------------------
	pub async fn pull_image(&mut self, image_info: Option<ImageInfo>) -> Result<(), String> {
		//
		logger_debug!("");

		//
		self.status = PULLING.to_string();
		let mesg = format!("begin to pull image: {}", image_info.as_ref().unwrap().image_name);

		//
		if let Err(err) = self.add_event(PULLING.to_string(), &mesg).await {
			return Err(format!("Event can't be added: {}", err));
		};

		//
		info!("{}", mesg);

		//
		if image_info.as_ref().is_none() {
			return Err("image info is nil".to_string());
		}

		//
		let client = match Docker::connect_with_local_defaults() {
			Ok(cli) => cli,
			Err(err) => {
				if let Err(err) = self.add_event(PULLING.to_string(), &err.to_string()).await {
					return Err(format!("Event can't be added: {}", err));
				};
				return Err(format!("new docker client failed, error: {}", err));
			}
		};

		//
		let encoded_json = serde_json::to_string(&image_info.as_ref().unwrap().register_auth_info)
			.map_err(|e| format!("Failed to encode auth info: {}", e))?;

		let _auth_str = URL_SAFE.encode(encoded_json.as_bytes());

		//
		info!("_auth_str = {}", &_auth_str);

		//
		let auth_config = AuthConfig {
			username: Some(
				image_info.as_ref().unwrap().register_auth_info.as_ref().unwrap().username.clone(),
			),
			password: Some(
				image_info.as_ref().unwrap().register_auth_info.as_ref().unwrap().password.clone(),
			),
			..Default::default()
		};

		//
		let auth_json = serde_json::to_string(&auth_config)
			.map_err(|e| format!("Failed to serialize auth config: {}", e))?;

		let auth_bytes = Bytes::from(URL_SAFE.encode(auth_json.as_bytes()));

		//
		let options = CreateImageOptions {
			from_image: image_info.as_ref().unwrap().image_name.clone(),
			..Default::default()
		};

		//
		let mut stream = client.create_image(Some(options), Some(auth_bytes), None);

		//
		while let Some(result) = stream.next().await {
			match result {
				Ok(create_image_info) => {
					//
					let mut output = String::new();

					//
					if let Some(status) = &create_image_info.status {
						output.push_str(&format!("status: {}", status));
					}
					//
					if let Some(progress) = &create_image_info.progress {
						output.push_str(&format!(", progress: {}", progress));
					}

					//
					if !output.is_empty() {
						info!("{}", output);
					}
				}
				Err(err) => {
					if let Err(err) = self.add_event(PULLING.to_string(), &mesg).await {
						return Err(format!("Event't can be added: {}", err));
					};
					return Err(format!("Error during pulling: {}", err));
				}
			}
		}

		//
		let success_mesg =
			format!("pull image: {} successfully", image_info.as_ref().unwrap().image_name);
		info!("{}", success_mesg);

		//
		if let Err(err) = self.add_event(PULLING.to_string(), &mesg).await {
			return Err(format!("Event can't be added: {}", err));
		} else {
			if let Err(err) = self.add_event(PULLED.to_string(), &success_mesg).await {
				return Err(format!("Event can't be added: {}", err));
			}
		};

		// Checks what's inside the events field
		for event in &self.events {
			info!("event ------> {:?}", event);
		}

		//
		Ok(())
	}

	// ---------------------------------------------------
	// M - Task - clear
	// ---------------------------------------------------
	pub async fn clear(&mut self) -> Result<(), String> {
		//
		logger_debug!("");

		debug!("1 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
		warn!("self = {:#?}", self);
		warn!("self.status 1 = {:#?}", self.status);
		debug!("In clear() -> Task pointer: {:p}, status: {}", &self, self.status);
		debug!(
			"From clear() -> Reading -> {:p}, is_cancel: {}, status: {}, ",
			&self, self.is_cancel, self.status
		);

		warn!("self.status 2 = {:#?}", self.status);

		// Only possible if we already set a status from the Task methods.
		if self.status == SUCCESS.to_string()
			|| self.status == FAILED.to_string()
			|| self.status == CANCELLED.to_string()
		{
			//
			debug!("2 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
			info!("self.status 3 = {}", self.status);

			//
			// remove_container
			//
			match self.remove_container(&self.container_conf.name.clone()).await {
				Ok(_) => {
					info!("OK removing container.")
				}
				Err(err) => {
					error!("BAD removing container: {}", err)
				}
			}

			debug!("3 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
			//
			// remove_image
			//
			let image_info_value =
				self.container_conf.image_info.as_ref().map(|value| value.image_name.clone());

			debug!("4 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
			//
			if let Some(image_name) = image_info_value {
				//
				match self.remove_image(&image_name.as_str()).await {
					Ok(_) => {
						debug!("5 a ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
						info!("OK removing image.")
					}
					Err(err) => {
						debug!("5 b ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
						error!("BAD removing image: {}", err)
					}
				}
			} else {
				error!("Image name not found.");
			}

			debug!("6 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);

      let file = match OpenOptions::new()
      .write(true)
      .truncate(true)
      .open(&self.task_info_save_path)
      .await {
          Ok(file) => file,
          Err(err) => {
            error!("{}", err);
            return Err(format!("Error when opening the file: {}", err));
          }
      };
    
    // Set permissions to 0644
    #[cfg(unix)]
    {
        if let Err(err) = file.set_permissions(std::fs::Permissions::from_mode(0o644)).await {
            return Err(format!("Erreur when trying to set permissions: {}", err));
        }
    }




			debug!("7 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
			//
			// remove_unused_images
			//
			if let Err(err) = self.remove_unused_images().await {
				error!("{}", err);
			};

			debug!("8 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
			//
			// remove_unused_volumes
			//
			if let Err(err) = self.remove_unused_volumes().await {
				error!("{}", err);
			};
			debug!("9 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
		}
		// end if self.status == ...
		else {
			//
			debug!("10 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
			return Err("Please cancel task first".to_string());
		}

		debug!("11 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
		//delete_task
		info!("Clearing task...");

		//
		debug!("12 ----- &self.task_info_save_path = {:#?}", &self.task_info_save_path);
		return Ok(());
	}

	// ---------------------------------------------------
	// M - Task - remove_container
	// ---------------------------------------------------
	pub async fn remove_container(&mut self, container_name: &str) -> Result<(), String> {
		//
		logger_debug!("");

		// map_err helps to transform bollard::errors::Error directly in a String.
		let docker = Docker::connect_with_local_defaults().map_err(|err| err.to_string())?;

		//
		let options = RemoveContainerOptions {
			force: true,          // even if the container doesn't or can't be removed
			..Default::default()  // others fields are filled with their value already there
		};

		// Calling the bollard library
		match docker.remove_container(container_name, Some(options)).await {
			Ok(_) => {
				info!("remove container successful");
				Ok(())
			}
			Err(err) => {
				let error_message = format!("Remove container failed, error: {}", err);
				error!("{}", error_message);
				Err(error_message)
			}
		}
	}

	// ---------------------------------------------------
	// M - Task - remove_image
	// ---------------------------------------------------
	pub async fn remove_image(&mut self, image_name: &str) -> Result<(), String> {
		//
		logger_debug!("");

		// map_err helps to transform bollard::errors::Error directly in a String.
		let docker = Docker::connect_with_local_defaults().map_err(|err| err.to_string())?;

		//
		let options = RemoveImageOptions {
			force: true,          // even if the container doesn't or can't be removed
			..Default::default()  // others fields are filled with their value already there
		};

		// Calling the bollard library
		match docker.remove_image(image_name, Some(options), None).await {
			Ok(removed_images) => {
				for image in removed_images {
					info!("Image successfully removed: {:?}", image);
				}
				info!("Remove image successfully");

				Ok(())
			}
			Err(err) => {
				let error_message = format!("Remove image failed, error: {}", err);
				error!("{}", error_message);
				Err(error_message)
			}
		}
	}

	// ---------------------------------------------------
	// M - Task - remove_image
	// ---------------------------------------------------
	pub async fn remove_unused_images(&mut self) -> Result<(), String> {
		//
		logger_debug!("");

		//
		let client = Docker::connect_with_local_defaults()
			.map_err(|err| format!("Docker connection failed: {}", err))?;

		//
		let filters = HashMap::new();
		filters.clone().insert("until", vec!["10m"]);

		//
		let options = Some(PruneImagesOptions {
			filters,
		});

		//
		let prune_result: Result<ImagePruneResponse, bollard::errors::Error> =
			client.prune_images(options).await;

		match prune_result {
			Ok(_) => {
				info!("Remove unused images successful");
				Ok(())
			}
			Err(err) => {
				let message = format!("remove unused images failed, error: {}", err);
				log::error!("{}", message);
				Err(message)
			}
		}
	}

	// ---------------------------------------------------
	// M - Task - remove_image
	// ---------------------------------------------------
	pub async fn remove_unused_volumes(&mut self) -> Result<(), String> {
		//
		logger_debug!("");

		//
		let client = Docker::connect_with_local_defaults()
			.map_err(|err| format!("Docker connection failed: {}", err))?;

		//
		let mut filters = HashMap::new();
		filters.insert("", vec![""]);

		//
		let options = Some(PruneVolumesOptions {
			filters,
		});

		//
		let prune_result = client.prune_volumes(options).await;

		//
		match prune_result {
			Ok(_) => {
				info!("Remove unused volumes successful");

				Ok(())
			}
			Err(err) => {
				let message_error = format!("remove unused volumes failed, error: {}", err);
				log::error!("{}", message_error);

				Err(message_error)
			}
		}
	}

	// ---------------------------------------------------
	// M - cancel_task
	// ---------------------------------------------------
	pub fn cancel_task(&mut self) {
		//
		if self.cancel_chan.sender.is_some() {
			info!("Sending cancel signal...");

			//
			if let Some(sender) = self.cancel_chan.sender.take() {
				let _ = sender.send(()); // Send the cancel signal
			}

			//
			self.status = CANCELLED.to_string();
			self.is_cancel = true;
		} else {
			info!("No task is running.");
		}
	}
}

// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================

// ---------------------------------------------------
// F - delete_task
// ---------------------------------------------------
pub async fn delete_task() -> Result<(), String> {
	//
	logger_debug!("");

	//
	logger_debug!("delete_task - before lock");
	let mut worker = WORKER.lock().await;
	logger_debug!("delete_task - after lock");

	info!("worker = {:?}", worker);


    //
    match worker.as_mut() {
      None => {
        //
        debug!("No task is running");
        return Err("no task now".to_string());
      }
      Some(task) => {
        //
        warn!("WORKER TASK exists.");

        debug!(
          "From delete_task() -> {:p}, is_cancel: {}, status: {}, ",
          &task, task.is_cancel, task.status
        );
        //
        if !task.is_cancel {
          return Err("Task must be cancelled before deleting".to_string());
        }

        //
        if let Err(e) = task.clear().await {
          error!("clear task failed, error: {}", e);
          return Err(e);
        }

        // Deleting the task
        *worker = None;
      }
    }

  info!("Task deleted successfully.");
	Ok(())
}

// ---------------------------------------------------
// F - cancel_inter_task
// ---------------------------------------------------
pub async fn cancel_inter_task() -> Result<(), String> {
	//
	logger_debug!("");

	//
	logger_debug!("cancel_inter_task - before lock");
	let mut worker = WORKER.lock().await;
	logger_debug!("cancel_inter_task - after lock");

	//
	match worker.as_mut() {
		None => {
			warn!("No task is running.");
			return Err("no task now".to_string());
		}
		Some(task) => {
			//
			debug!("From cancel_inter_task() -> BEFORE modifying task.is_cancel -> {:p}, is_cancel: {}, status: {}, ", &task, task.is_cancel, task.status);

			//
			task.cancel_task();

      drop(worker);

      match delete_task().await {
        Ok(_) => {
          info!("Task cancelled successfully.");
          return Ok(());
        }
        Err(e) => {
          error!("Error, deleting: {}", e);
          return Err(e);
        }
      }

		}
	}
}

// ---------------------------------------------------
// F - manager_worker
// ---------------------------------------------------
pub async fn manager_worker() -> Result<&'static str, &'static str> {
	//
	logger_debug!("");

	if let Err(e) = init_task().await {
		error!("Error initializing task: {:?}", e)
	}

	Ok("OK boomer")
}

// ---------------------------------------------------
// init_task
// We retrieve a variable TASK_INFO_SAVE_PATH if
// it exists.
// Otherwise, we assign it a default value: "task.json".
// ---------------------------------------------------
pub async fn init_task() -> Result<(), Box<dyn std::error::Error>> {
	//
	logger_debug!("");

	// Get the configuration file path.
	// In this case, we retrieve TASK_INFO_SAVE_PATH if
	// it exists, otherwise by default use "task.json".
	let task_info_save_path =
		std::env::var("TASK_INFO_SAVE_PATH").unwrap_or_else(|_| "task.json".to_string());

	// Check if file exists.
	if !fs::metadata(&task_info_save_path).is_ok() {
		info!("The file  {:?} doesn't exist.", task_info_save_path);
		return Ok(()); // Returns OK even if the file doesn't exist.
	}

	// Read the file.
	let task_data = fs::read(&task_info_save_path)?;

	// Deserialize the JSON into the Task structure
	let task: Task = serde_json::from_slice(&task_data)?;

	// Lock the WORKER var.
	let mut worker_lock = WORKER.lock().await;

	// Update the WORKER var.
	*worker_lock = Some(task);

	//
	Ok(())
}

// ---------------------------------------------------
// F - create_task
// ---------------------------------------------------
pub async fn create_task(container: Container) -> Result<AppResponse, std::io::Error> {
	logger_debug!("");

	let _lock = TASK_MUTEX.lock().await; // Locking the mutex

	let mut worker = WORKER.lock().await;

	if worker.is_some() {
		return Err(std::io::Error::new(std::io::ErrorKind::Other, "task is already created"));
	}

	let new_worker = Task {
		id: Uuid::new_v4().to_string(),
		container_conf: container,
		status: "".to_string(),
		is_cancel: false,
		cancel_chan: CancelSender::new(),
		events: Vec::new(),
		container_inspect: None,
		save_mutex: Arc::new(Mutex::new(())),
		secret_save_dir: get_config_value("SecretSaveDir", "/secret"),
		task_info_save_path: get_config_value("TaskInfoSavePath", "task.json"),
		secret_provider_agent: get_config_value(
			"SecretProviderAgent",
			"/workplace/cvm-agent/cvmassistants/secretprovider/secret_provider_agent",
		),
	};

	// worker in the gv
	*worker = Some(new_worker);

	// WORKER cloning and app_response before unlocking the mutex
	let worker_clone = Arc::clone(&WORKER);
	let app_response = Arc::new(Mutex::new(AppResponse {
		exit_cause: FAILED.to_string(),
		exit_code: -1,
		stderr: "".to_string(),
		stdout: "".to_string(),
	}));
	let app_response_clone = Arc::clone(&app_response);

	// Freeing the mutex before spawning the thread
	drop(worker);

	// Background task with tokio::spawn
	let handle = tokio::spawn(async move {
		let mut worker = worker_clone.lock().await;

		if let Some(ref mut w) = *worker {
			if let Err(e) = w.save_task().await {
				error!("ERROR saving task: {:?}", e);
				return Err(std::io::Error::new(
					std::io::ErrorKind::Other,
					format!("ERROR saving task: {:?}", e),
				));
			}
			info!("save_task() OK.");

			if let Err(e) = w.check_param().await {
				error!("ERROR checking parameters: {:?}", e);
				return Err(std::io::Error::new(
					std::io::ErrorKind::Other,
					format!("ERROR checking parameters: {:?}", e),
				));
			}
			info!("check_param() OK");

			info!("Let's RUUUUNnnnnnnnnn!!!!");
			match w.run().await {
				Ok(res) => {
					info!("OK w.run() -> res: {:?}", res);
					let mut response = app_response_clone.lock().await;
					// response.stdout = "Attestation OK.".to_string();
					// response.exit_cause = "".to_string();
          *response = res;
					info!("app_response updated = {:?}", response);
					Ok(response.clone()) // Cloning the updated response
				}
				Err(err) => {
					error!("@Error create task: {}", err);
					Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Error create task: {}", err)))
				}
			}
		} else {
			Err(std::io::Error::new(std::io::ErrorKind::Other, "Worker not found"))
		}
	});

	// Waiting the end of the task without blocking the mutex
	let result = handle.await.unwrap();

	match result {
		Ok(app_response) => {
			info!("FINAL -> app_response = {:?}", app_response);
			Ok(app_response)
		}
		Err(err) => Err(err),
	}
}

// ---------------------------------------------------
// F - get_config_value
// ---------------------------------------------------
fn get_config_value(key: &str, default: &str) -> String {
	//
	logger_debug!("");

	//
	std::env::var(key).unwrap_or_else(|_| default.to_string())
}

// ---------------------------------------------------
// F - run_actuator_cmd
// ---------------------------------------------------
pub fn run_actuator_cmd(name: &str, envs: &[String], args: &[&str]) -> Result<i32, String> {
	//
	logger_debug!("");
	info!("1 -- args = {:#?}", args); // --> "/secret/secret-145.239.161.248:3333.json",

	// Command with program name and arguments
	let mut command = Command::new(name);
	command.args(args);

	//
	info!("name = {:#?}", name); 
	info!("envs = {:#?}", envs); 
	info!("2 -- args = {:#?}", args); 
	info!("command = {:#?}", command); 

	// Adding ENV
	for env in envs {
		//
		info!("env = {:#?}", env);

		if let Some(eq_pos) = env.find('=') {
			info!("eq_pos = {:#?}", eq_pos);
			let (key, value) = env.split_at(eq_pos);
			info!("key = {:#?}", key);
			let value = &value[1..]; // Removing '='
			info!("value = {:#?}", value);
			info!("key,value = {:#?}", (key, value));
			command.env(key, value);
		}
	}

	// Execute command in order to get output
	let output = command.output();
	info!("Here --> output = {:#?}", output);

	match output {
		Ok(output) => {
			info!("output in match {:#?}", output);

			if !output.stdout.is_empty() {
				info!("09 - Output: {}", String::from_utf8_lossy(&output.stdout));
			}
			if !output.stderr.is_empty() {
				error!("09 - Error: {}", String::from_utf8_lossy(&output.stderr));
			}
			if !output.status.success() {
				info!("09 - Command failed with exit code: {}", output.status);
			}

			if !output.status.success() {
				let exit_status = output.status.code().unwrap_or(-1);
				info!("exit_status {:#?}", exit_status);

				//
				return Err(format!("Command failed with exit code: {}", exit_status));
			} else {
				info!("output.status.code() {:#?}", output.status.code());
				Ok(output.status.code().unwrap_or(0))
			}
		}
		Err(err) => {
			info!("09 - err {:#?}", err);
			Err(format!("Failed to run command: {}", err))
		}
	}
}
