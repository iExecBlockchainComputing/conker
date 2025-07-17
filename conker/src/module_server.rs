use crate::error_codes::consts::{self, ERROR_CANCEL_CONTAINER_FAILED, ERROR_DELETE_CONTAINER_FAILED, ERROR_GET_CONTAINER_FAILED};
use crate::module_worker::{self, create_task, get_task_status, AppResponse, Container};
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request};
use axum::http::HeaderMap;
use axum::response::Html;
use axum::routing::delete;
use axum::{
	http::{
		header::{AUTHORIZATION, CONTENT_TYPE},
		Method, StatusCode,
	},
	routing::get,
};
use axum::{
	response::{IntoResponse, Json},
	routing::post,
	Router,
};
use const_format::formatcp;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, warn};
 
// ====================================
// const
// ====================================
const DEFAULT_ADDRESS: &'static str = "0.0.0.0:8383";

const ROUTE_SW_API_V1: &'static str = "/sw/api/v1";
const ROUTE_SW_API_V1_CONTAINER: &'static str = formatcp!("{}/container", ROUTE_SW_API_V1);
const ROUTE_SW_API_V1_CONTAINER_CANCEL: &'static str =
	formatcp!("{}/cancel", ROUTE_SW_API_V1_CONTAINER);
const ROUTE_SW_API_V1_PUB: &'static str = formatcp!("{}/pub", ROUTE_SW_API_V1);
const ROUTE_SW_API_V1_PUB_HEALTH: &'static str = formatcp!("{}/health", ROUTE_SW_API_V1_PUB);

// ====================================
// structs
// ====================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseRes {
	code: u16,
	message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRes<T> {
	#[serde(flatten)]
	base_res: BaseRes,
	data: Option<T>,
}

struct DefaultController {
	new_token: String,
}

struct ContainerController {
	state: Arc<Mutex<AppState>>,
	default_controller: DefaultController,
}

#[derive(Debug, Clone)]
struct AppState {
	name: String,
}

impl DefaultController {
	fn new(new_token: String) -> Self {
		DefaultController {
			new_token: new_token,
		}
	}

	fn handle_success(&self, code: u16, message: &str) -> BaseRes {
		debug!("handle_success");
		BaseRes {
			code,
			message: message.to_string(),
		}
	}

	fn handle_error_status_bad_request(&self, code: u16, message: &str) -> BaseRes {
		debug!("handle_error_status_bad_request");
		BaseRes {
			code,
			message: message.to_string(),
		}
	}
}

impl ContainerController {
	pub fn new(state: Arc<Mutex<AppState>>, new_token: String) -> Self {
		ContainerController {
			state: state,
			default_controller: DefaultController::new(new_token),
		}
	}

    async fn create_container(&self, req: Request<Body>) -> impl IntoResponse {
        debug!("create_container");
        let ConnectInfo(addr) = req.extensions().get::<ConnectInfo<SocketAddr>>()
            .expect("ConnectInfo should be present");
        debug!("Client IP : {}", addr.ip());
        self.process_payload_container(req).await
    }

    async fn process_payload_container(&self, req: Request<Body>) -> impl IntoResponse {
        debug!("process_payload_container");

        let (parts, body) = req.into_parts();
    
        let ConnectInfo(addr) = parts.extensions.get::<ConnectInfo<SocketAddr>>()
            .expect("ConnectInfo should be present");

        debug!("Client IP: {}", addr.ip());

        let body_bytes = match to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes,
            Err(e) => {
                let message = format!("Failed to read request body: {}", e);
                let base_res = self.default_controller.handle_error_status_bad_request(
                    consts::ERROR_CODE__JSON__UNMARSHAL_FAILED,
                    &message
                );
                return (StatusCode::BAD_REQUEST, Json(base_res))
            }
        };

        let container = match serde_json::from_slice::<Container>(&body_bytes) { // deserialize the JSON file into a Container
            Ok(container) => {
                info!("Container deserialized: {:?}", container);
                container
            }
            Err(e) => {
                let message = format!("get body error: {}", e);
                let base_res = self.default_controller.handle_error_status_bad_request(
                    consts::ERROR_CREATE_CONTAINER_FAILED,
                    &message,
                );
                return (StatusCode::BAD_REQUEST, Json(base_res))
            }
        };

        let raw_app_response = match create_task(container).await {
            Ok(response) => response,
            Err(e) => {
                let app_response = AppResponse {
                    exit_cause: "".to_string(),
                    stdout: "".to_string(),
                    stderr: e.to_string(),
                    exit_code: -1,
                };

                let app_response_json = serde_json::to_string(&app_response)
                    .unwrap_or_else(|_| "Failed to serialize response".to_string());
                let message = format!("create container failed, error: {}, logs: \n{}", e, app_response_json);

                error!("original message: {}", message);

                let base_res = self.default_controller.handle_error_status_bad_request(
                    consts::ERROR_CREATE_CONTAINER_FAILED,
                    &message,
                );
               return (StatusCode::BAD_REQUEST, Json(base_res))
            }
        };

        // success
        let app_response_json = serde_json::to_string(&raw_app_response)
            .unwrap_or_else(|_| "Failed to serialize response".to_string());

        let base_res = self.default_controller.handle_success(200, &app_response_json);
        (StatusCode::OK, Json(base_res))
    }

	async fn get_container(&self, req: Request<Body>) -> impl IntoResponse {
		debug!("get_container");

		let headers = req.headers();

		// Client IP
		let client_ip = headers
			.get("x-real-ip") // try this
			.or_else(|| headers.get("x-forwarded-for")) // or that
			.and_then(|value| value.to_str().ok()) // and apply it (Some or None with ok())
			.unwrap_or("0.0.0.0"); // otherwise return a default value

		info!("Client IP: {}", client_ip);

		// Get status.
		match get_task_status().await {
			Ok(task) => {
				let message = "get ContainerConf info successful.";
				let code = 200;

				debug!("task = {:#?}", &task);

                let base_res = self.default_controller.handle_success(code, message);
                (StatusCode::OK, Json(base_res))
			}

			Err(err) => {
				let err_message = format!("get container info failed, error: {}", err);
                let base_res = self.default_controller.handle_error_status_bad_request(ERROR_GET_CONTAINER_FAILED, &err_message);
                (StatusCode::BAD_REQUEST, Json(base_res))
			}
		}
	}

	async fn get_health(&self) -> Json<BaseRes> {
		debug!("get_health");
		let base_res = self.default_controller.handle_success(200, "Server is healthy.");
		Json(base_res)
	}

	async fn delete_container(&self) -> impl IntoResponse {
		debug!("delete_container");
		match module_worker::delete_task().await {
			Ok(_) => {
				let base_res = self.default_controller.handle_success(200, "DELETING container OK.");
				(StatusCode::OK, Json(base_res))
			}
			Err(err) => {
				let err_message = format!("delete container info failed, error: {}", err);
				let base_res = self.default_controller.handle_error_status_bad_request(ERROR_DELETE_CONTAINER_FAILED, &err_message);
				(StatusCode::BAD_REQUEST, Json(base_res))
			}
		}
	}

	async fn cancel_container_task(&self, req: Request<Body>) -> impl IntoResponse {
		debug!("cancel_container_task");
		let headers: &HeaderMap = req.headers();
		warn!("headers = {:#?}", headers);
		match module_worker::cancel_inter_task().await {
			Ok(_) => {
				let base_res = self.default_controller.handle_success(200, "CANCELING task OK.");
				(StatusCode::OK, Json(base_res))
			}
			Err(err) => {
				let err_message = format!("Cancel Container Status failed, error: {}", err);
				let base_res = self.default_controller.handle_error_status_bad_request(ERROR_CANCEL_CONTAINER_FAILED, &err_message);
				(StatusCode::BAD_REQUEST, Json(base_res))
			}
		}
	}
  
}

pub async fn manager_server(result: Result<&'static str, &'static str>) -> Result<&str, &str> {
	debug!("manager_server");
	let str = "OK!";
	let router = routing_init().await;
	match result {
		Ok(answer) => {
			if answer == "start" {
				// Bind the address to the listener.
				let listener = tokio::net::TcpListener::bind(DEFAULT_ADDRESS).await.unwrap();
				println!("Listening on {}", listener.local_addr().unwrap());
				axum::serve(
					listener,
					router.into_make_service_with_connect_info::<SocketAddr>(),
				)
				.await
				.unwrap();
			} else if answer == "exit" {
			} else {
			}
		}
		Err(answer) => {
			error!("ERROR: Weird error: {}", answer);
		}
	}
	Ok(&str)
}

async fn routing_init() -> Router {
	debug!("routing_init");

	let methods = vec![Method::GET, Method::POST, Method::DELETE];
	let headers = vec![AUTHORIZATION, CONTENT_TYPE];

	// CORS
	let cors = CorsLayer::new().allow_origin(Any).allow_methods(methods).allow_headers(headers);

	let name: String = String::from("Hello.");
	let state = Arc::new(Mutex::new(AppState {
		name: name,
	}));

	let container_controller =
		Arc::new(ContainerController::new(state.clone(), "new_token".to_string()));

	let container_controller = container_controller.clone();

	// Router
	Router::new()
		.route("/", get(handler))
		.route(ROUTE_SW_API_V1_CONTAINER, {
			let controller = container_controller.clone();
			post(move |req| async move { controller.create_container(req).await })
		})
		.route(ROUTE_SW_API_V1_CONTAINER, {
			let controller = container_controller.clone();
			delete(move || async move { controller.delete_container().await })
		})
		.route(ROUTE_SW_API_V1_CONTAINER, {
			let controller = container_controller.clone();
			get(move |req| async move { controller.get_container(req).await })
		})
		.route(ROUTE_SW_API_V1_CONTAINER_CANCEL, {
			let controller = container_controller.clone();
			post(move |req| async move { controller.cancel_container_task(req).await })
		})
		.route(&ROUTE_SW_API_V1_PUB_HEALTH, {
			let controller = container_controller.clone();
			get(move || async move { controller.get_health().await })
		})
		.with_state(state)
		.layer(cors)
}

async fn handler() -> Html<String> {
	debug!("handler");

	let today = chrono::Local::now();
	let formatted_date = today.format("%Y-%m-%d %H:%M:%S").to_string();

	let html_content = format!(
		r#"
            <html>
            <head>
                <style>
                    body {{
                        background-color: #333333; /* grey light */
                        text-align: center;
                        color: #FFFFFF;
                        margin: 0;
                        padding: 0;
                        font-family: Arial, sans-serif;
        }}
                        h1 {{
                        color: #FFFFFF;
        }}
                </style>
            </head>
            <body>
                <h1>Main</h1>
                <h2>{}</h2>
            </body>
            </html>
            "#,
		formatted_date
	);

	Html(html_content)
}
