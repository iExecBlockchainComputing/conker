// ====================================
// import
// ====================================
use crate::logger_debug;
use base64::{engine::general_purpose::URL_SAFE, Engine};
use bollard::container::{
	/*CreateContainerOptions, */ Config, CreateContainerOptions, RemoveContainerOptions,
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
use futures_util::StreamExt;
use lazy_static::lazy_static;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::{self /*, error*/};
use std::collections::HashMap;
use std::fs::{self};
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::{env, fs::File /*, io::Read*/};
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
#[derive(Debug, Deserialize, Serialize)]
pub struct AppResponse {
	exit_cause: String,
	stdout: String,
	stderr: String,
	exit_code: i32,
}

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
	//     pub cmd: String,
	//     pub max_execution_time: u32,
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
	// pub session_id: String,
	// pub worker_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Task {
	pub id: String,
	pub container_conf: Container,
	pub status: String,
	pub is_cancel: bool,
	// #[serde(skip)]
	// pub cancel_chan: tokio::sync::broadcast::Sender<()>,
	// pub events: Vec<Events>,
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

	#[serde(rename = "app")]
	app: HashMap<String, String>,

	#[serde(rename = "post-compute", skip_serializing_if = "Option::is_none")]
	post_compute: Option<HashMap<String, String>>,
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

		// Mount checking
		for v in &self.container_conf.mounts {
			if v.typ != Some(MountTypeEnum::VOLUME) {
				return Err("mount type only supports volume".to_string());
			}
		}

		//
		Ok(())
	}

	// ---------------------------------------------------
	// M - Task - run
	// ---------------------------------------------------
	pub async fn run(&mut self) -> Result<(), String> {
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

		// cancel_checker
		if let Err(e) = self.cancel_checker().await {
			error!("Task cancelled: {}", e);
			return Err(e);
		}

		//
		// attest
		//
		if let Err(err) = self.attest().await {
			self.status = FAILED.to_string();
			error!("Error: {}", err);
			return Err(err);
		}

		// cancel_checker
		if let Err(e) = self.cancel_checker().await {
			error!("Task cancelled: {}", e);
			return Err(e);
		}

		//
		// create_container
		//
		if let Err(err) = self.create_container().await {
			self.status = FAILED.to_string();
			error!("Error: {}", err);
			return Err(err);
		}

		// cancel_checker
		if let Err(e) = self.cancel_checker().await {
			error!("Task cancelled: {}", e);
			return Err(e);
		}

		//
		// start_container
		//
		if let Err(err) = self.start_container().await {
			// self.status = TaskStatus::Failed.to_string(); //FAILED.to_string();
			self.status = FAILED.to_string(); //FAILED.to_string();
			eprintln!("Error: {}", err);
			return Err(err);
		}

		//
		Ok(())
	}

	// ---------------------------------------------------
	// M - Task - start_container
	// ---------------------------------------------------
	pub async fn start_container(&mut self) -> Result<(), String> {
		//
		logger_debug!("");

		//
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

		//
		match ctx {
			Ok(inner) => match inner {
				Ok(_) => {
					//
					self.status = RUNNING.to_string();
					let mesg = format!("Container '{}' is running", self.container_conf.name);
					//
					if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
						//
						return Err(format!("Event can't be added: {}", err));
					}
					Ok(())
				}
				Err(e) => Err(format!("Failed to start container: {}", e)),
			},
			Err(_) => Err("Timeout starting container".to_string()),
		}
	}

	// ---------------------------------------------------
	// M - Task - create_container
	// ---------------------------------------------------
	pub async fn create_container(&mut self) -> Result<(), String> {
		//
		logger_debug!("");

		//
		self.status = CREATING.to_string();
		let mesg = "Begin to create container".to_string();
		if let Err(err) = self.add_event(self.status.clone(), &mesg).await {
			return Err(format!("Event can't be added: {}", err));
		}

		info!("mesg = {}", mesg);

		//
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

		// Container config with HostConfig integrated
		let config = Config {
			image: Some(self.container_conf.image_info.clone().unwrap().image_name.clone()),
			env: self.container_conf.env.clone(),
			exposed_ports: self.build_exposed_ports(),
			host_config: Some(host_config), // HostConfig added here
			..Default::default()
		};

		let create_options = CreateContainerOptions {
			name: &self.container_conf.name,
			platform: None,
		};

		let response = docker
			.create_container(Some(create_options), config)
			.await
			.map_err(|e| format!("Failed to create container: {}", e))?;

		if !response.warnings.is_empty() {
			warn!("Warnings: {:?}", response.warnings);
		}

		let success_msg = format!("create container successful: {:?}", response.id);
		info!("{}", success_msg);

		self.status = CREATED.to_string();
		if let Err(err) = self.add_event(self.status.clone(), &success_msg).await {
			return Err(format!("Event can't be added: {}", err));
		}

		Ok(())
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
	// M - Task - is_cancel
	// ---------------------------------------------------
	pub async fn cancel_checker(&mut self) -> Result<(), String> {
		//
		if self.is_cancel {
			//
			let message = "Task to be cancelled after pulling the image.".to_string();
			self.status = CANCELLED.to_string();
			if let Err(err) = self.add_event(self.status.clone(), &message).await {
				error!("Failed to add event for task {}: {}", self.id, err);
			}

			//
			return Err(format!("Task {} is cancelled", self.id));
		}

		//
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
		let skip_attest = false; // Need a config file
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
				let envs = vec![format!("appId={}", split_id[1]), format!("kbsEndpoint={}", k)];

				warn!("k = {}", k); // --> k = 145.239.161.248:3333
				warn!("envs = {:#?}", envs); /* --> envs = [
																		 "appId=27b7ad4fc76d486536f808dcc1c0368afee310893f2698339ad352cde555b9a2",
																		 "kbsEndpoint=145.239.161.248:3333",
																 ]
																	*/

				let mut args_list = vec!["-v", "nullverifier", "-f", "-s"];
				let secret_file_path = format!("{}/secret-{}.json", self.secret_save_dir, k);
				args_list.push(&secret_file_path);

				warn!("args_list = {:#?}", args_list); // "/secret/secret-145.239.161.248:3333.json"
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
		if self.status == RUNNING.to_string()
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
			//
			// remove_file from FS.
			//
			if let Err(err) = fs::remove_file(&self.task_info_save_path) {
				error!("{}", err);
				return Err(err.to_string());
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
	if worker.is_none() {
		return Err("no task now".to_string());
	}

	warn!("WORKER TASK exists!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

	//
	if let Some(task) = worker.as_mut() {
		info!("- - - - 1");
		debug!(
			"From delete_task() -> {:p}, is_cancel: {}, status: {}, ",
			&task, task.is_cancel, task.status
		);
		//
		if !task.is_cancel {
			return Err("Task must be cancelled before deleting".to_string());
		}

		//
		if let Err(err) = task.clear().await {
			info!("- - - - 2");
			error!("clear task failed, error: {}", err);
			return Err(err);
		}
		info!("- - - - 3");
	}

	info!("- - - - 4");
	*worker = None;

	info!("- - - - 5");
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

	// BAD
	if worker.is_none() {
		return Err("no task now".to_string());
	}

	// OK
	if let Some(task) = worker.as_mut() {
		info!("- - - - 6");

		debug!("From cancel_inter_task() -> BEFORE modifying task.is_cancel -> {:p}, is_cancel: {}, status: {}, ", &task, task.is_cancel, task.status);

		//
		task.is_cancel = true;
		task.status = CANCELLED.to_string();
		info!("Task cancelled successfully.");

		info!("- - - - 8");
	}

	info!("- - - - 9");

	//
	Ok(())
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
pub async fn create_task(container: Container) -> Result<(), std::io::Error> {
	//
	logger_debug!("");

	// Use it as debug in order to remove the compiler warning like "PULLING not used".
	debug!("PULLING = {}", PULLING.to_string());
	debug!("PULLED = {}", PULLED.to_string());
	debug!("ATTESTING = {}", ATTESTING.to_string());
	debug!("ATTESTED = {}", ATTESTED.to_string());
	debug!("PRECOMPUTE = {}", PRECOMPUTE.to_string());
	debug!("CREATING = {}", CREATING.to_string());
	debug!("CREATED = {}", CREATED.to_string());
	debug!("STARTING = {}", STARTING.to_string());
	debug!("RUNNING = {}", RUNNING.to_string());
	debug!("WAITING = {}", WAITING.to_string());
	debug!("DELETING = {}", DELETING.to_string());
	debug!("CANCELLED = {}", CANCELLED.to_string());
	debug!("FAILED = {}", FAILED.to_string());
	debug!("SUCCESS = {}", SUCCESS.to_string());
	debug!("POSTCOMPUTE = {}", POSTCOMPUTE.to_string());

	//
	let _lock = TASK_MUTEX.lock().await; // Locking the mutex

	let mut worker = WORKER.lock().await; // WORKER

	info!("worker.is_some() = {:#?}", worker.is_some());

	if let Some(ref task) = worker.as_ref() {
		info!("1111111111111 - task.TaskInfoSavePath = {:#?}", task.task_info_save_path);
	}

	if worker.is_some() {
		// if task is already created, we return straight.
		return Err(std::io::Error::new(std::io::ErrorKind::Other, "task is already created"));
	}

	let new_worker = Task {
		id: Uuid::new_v4().to_string(),
		container_conf: container,
		status: "".to_string(),
		is_cancel: false,
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

	// Save the worker in the global state
	*worker = Some(new_worker);

	if let Some(task) = worker.as_ref() {
		info!("22222222222 - task.TaskInfoSavePath = {:#?}", task.task_info_save_path);
	}

	//
	let worker_clone = Arc::clone(&WORKER);

	// Create a new thread with the worker_clone.
	tokio::task::spawn(async move {
		let mut worker = worker_clone.lock().await;

		//
		if let Some(ref mut w) = *worker {
			// Checks if the *worker is defined
			//
			if let Err(e) = w.save_task().await {
				// Checks if we can save the task
				error!("ERROR saving task: {:?}", e);
			} else if let Err(e) = w.check_param().await {
				// Checks params
				// check_param()
				eprint!("ERROR checking parameters: {:?}", e);
			} else {
				info!("Let's RUUUUNnnnnnnnnn!!!!");
				match w.run().await {
					// run()
					Ok(res) => {
						info!("OK w.run() -> res: {:?}", res)
					}
					Err(err) => {
						info!("BAD w.run() -> Error create task.");
						error!("Error create task: {}", err)
					}
				}
			}
		}
	});

	Ok(())
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
	info!("name = {:#?}", name); // --> "/workplace/cvm-agent/cvmassistants/secretprovider/secret_provider_agent"
	info!("envs = {:#?}", envs); // --> "appId=27b7ad4fc76d486536f808dcc1c0368afee310893f2698339ad352cde555b9a2",   "kbsEndpoint=145.239.161.248:3333"
	info!("2 -- args = {:#?}", args); // --> "/secret/secret-145.239.161.248:3333.json",
	info!("command = {:#?}", command); /* -->    program: "/workplace/cvm-agent/cvmassistants/secretprovider/secret_provider_agent",
																			 args: [
																					 "/workplace/cvm-agent/cvmassistants/secretprovider/secret_provider_agent",
																					 "/secret/secret-145.239.161.248:3333.json",
																			 ],
																			 create_pidfd: false,
																		*/

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
