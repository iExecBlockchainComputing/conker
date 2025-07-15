// ====================================
// import
// ====================================
use crate::error_codes::consts;
use crate::logger_debug;
use crate::module_worker::{self, create_task, get_task_status, AppResponse, Container};
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request};
use axum::http::{self, HeaderMap, Response};
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
  Json as JsonResponse,
	routing::post,
	Router,
};
use const_format::formatcp;
use serde::{Deserialize, Serialize};
use serde_json::json;
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

#[derive(Debug, serde::Serialize)]
struct RequestMessageData {
	uri: String,
	method: String,

	user: String,
	ip: String,

	response_status: u16,
	request_body: String,
	request_auth: String,
}

//
struct DefaultController {
	new_token: String,
}

//
struct ContainerController {
	state: Arc<Mutex<AppState>>,
	default_controller: DefaultController,
}

#[derive(Debug, Clone)]
struct AppState {
	name: String,
}

// ----------------------------------------------
// impl - DefaultController
// ----------------------------------------------
impl DefaultController {
	// ----------------------------------------------
	// M - new
	// ----------------------------------------------
	fn new(new_token: String) -> Self {
		//
		logger_debug!("");

		//
		DefaultController {
			new_token: new_token,
		}
	}

	// ----------------------------------------------
	// M - DefaultController - handle_success_simple
	// ----------------------------------------------
	fn handle_success_simple(&self, code: u16, message: &str) -> BaseRes {
		//
		logger_debug!("");

		//
		let base_res = BaseRes {
			code,
			message: message.to_string(),
		};

		//
		base_res
	}

  // ----------------------------------------------
	// M - DefaultController - handle_success_mika
	// ----------------------------------------------
  fn handle_success_normal(
    &self,
    code: u16,
    message: &str,
    addition: &str,
    renewal: bool,
    headers: &axum::http::HeaderMap,
    uri: &axum::http::Uri,
    method: &axum::http::Method,
    request_body: &str,
    client_ip: &str,
    extensions: &axum::http::Extensions,
) -> (String, BaseRes, Option<String>) {
  //
  logger_debug!("");

  let x_real_ip = headers.get("X-Real-ip").and_then(|v: &http::HeaderValue| v.to_str().ok());
  warn!("X-Real-ip: {:?}", x_real_ip);

  let connect_info = extensions.get::<axum::extract::ConnectInfo<SocketAddr>>();
  warn!("ConnectInfo: {:?}", connect_info);

  //
  let client_ip: String = headers
  .get("X-Real-ip")
  .and_then(|v| v.to_str().ok())
  .map(|s| s.to_string())
  .unwrap_or_else(|| {
      headers
          .get("X-Forwarded-For")
          .and_then(|v| v.to_str().ok())
          .map(|s| s.to_string())
          .unwrap_or_else(|| {
              extensions
                  .get::<axum::extract::ConnectInfo<SocketAddr>>()
                  .map(|info| info.0.ip().to_string())
                  // .unwrap_or("unknown".to_string())
                  .unwrap_or(client_ip.to_string())
          })
  });

  //
  warn!("OK Client IP: {:#?}", client_ip);
  
  let request_info = RequestMessageData {
    uri: uri.to_string(),
    method: method.to_string(),
    user: "".to_string(),
    ip: client_ip.to_string(),
    request_auth: "".to_string(),
    response_status: code,
    request_body: request_body.to_string(),
  };
  
  //
  warn!("request_info: {:#?}", request_info);

  let base_res = BaseRes {
        code,
        message: message.to_string(),
    };

    let new_token_opt = if renewal {
        Some(self.new_token.clone())
    } else {
        None
    };

    match serde_json::to_string(&request_info) {
        Ok(json_str) => {
          let message = (
            format!("message: {}; addition: {}; request: {}", message, addition, json_str),
            base_res,
            new_token_opt,
        );

        //
        warn!("message OK = {:#?}", message);

        message
      }
        Err(e) => {
            error!("message err: {}", e);
            (
                format!("message: {}; addition: {}; request: {}", message, addition, e),
                base_res,
                new_token_opt,
            )
        }
    }
}

	// ----------------------------------------------
	// M - DefaultController - handle_success2
	// ----------------------------------------------
	pub fn handle_success2(
		&self,
		req: &Request<Body>,
		code: u16,
		message: &str,
		addition: &str,
		renewal: bool,
		client_ip: Option<String>,
		task: &module_worker::Task,
	) -> Result<Response<Body>, String> {
		//
		logger_debug!("");

		//
		let client_ip = client_ip.unwrap_or_else(|| "Unknown IP".to_string());

		//
		let uri = req.uri().to_string();
		let method = req.method().to_string();
		let user = req.headers().get("Authorization").map(|h| h.to_str().unwrap_or("")).unwrap_or("");
		let client_ip = client_ip;

		//
		let request_info = json!({
				"URI": uri,
				"Method": method,
				"User": user,
				"IP": client_ip,
				"RequestAuth": "",
				"ResponseStatus": code,
		});

		//
		info!("request_info = {:#?}", request_info);

		//
		let request_info_str = serde_json::to_string(&request_info)
			.map_err(|e| format!("Error serializing request info: {}", e))?;

		info!("request_info_str = {:#?}", request_info_str);

		//
		if request_info_str.is_empty() {
			warn!("--- request_info_str is empty.");

			return Err(format!(
				"message: {}; addition: {}; error: {};",
				message, addition, "Serialization Error"
			));
		}

		//
		let mut headers = HeaderMap::new();
		if renewal {
			headers.insert("NewToken", self.new_token.parse().unwrap());
		}

		let body_for_debug = format!(
			"code: {}, message: {}; addition: {}; request: {};",
			code, message, addition, request_info_str
		);

		//
		info!("body_for_debug {:#?}", body_for_debug);

		//
		//
		//
		let base_res = BaseRes {
			code: code,
			message: message.to_string(),
		};

		//
		let res = DataRes {
			base_res: base_res,
			data: Some(task),
		};

		//
		match serde_json::to_string(&res) {
			Ok(body) => {
				let response_body = axum::http::Response::builder()
					.status(StatusCode::OK)
					.header("Content-Type", "application/json")
					.body(body.into())
					.map_err(|e| e.to_string())?;

				Ok(response_body)
			}
			Err(e) => Err(format!("Error serialization: {}", e)),
		}
	}

	// ----------------------------------------------
	// M - DefaultController - handle_error_bad_request
	// ----------------------------------------------
	fn handle_error_bad_request_simple(&self, code: u16, message: &str) -> BaseRes {
		//
		logger_debug!("");

		//
		let base_res = BaseRes {
			code,
			message: message.to_string(),
		};
		//
		base_res
	}

	// ----------------------------------------------
	// M - DefaultController - handle_error_status_bad_request_mika
	// ----------------------------------------------
  async fn handle_error_status_bad_request(&self, 
    code: u16, 
    message: &str, 
    addition: &str, 
    headers: &http::HeaderMap, 
    uri: &http::Uri, 
    method: &http::Method,
    client_ip: &str,
    extensions: &axum::http::Extensions,
  ) -> String {
  
  //
  logger_debug!("");

  //
  let connect_info = extensions.get::<axum::extract::ConnectInfo<SocketAddr>>();
  warn!("ConnectInfo: {:?}", connect_info);

  //
  let client_ip: String = headers
  .get("X-Real-ip")
  .and_then(|v| v.to_str().ok())
  .map(|s| s.to_string())
  .unwrap_or_else(|| {
      headers
          .get("X-Forwarded-For")
          .and_then(|v| v.to_str().ok())
          .map(|s| s.to_string())
          .unwrap_or_else(|| {
              extensions
                  .get::<axum::extract::ConnectInfo<SocketAddr>>()
                  .map(|info| info.0.ip().to_string())
                  // .unwrap_or("unknown".to_string())
                  .unwrap_or(client_ip.to_string())
          })
  });

  //
  warn!("BAD req - Client IP: {:#?}", client_ip);

    let request_info = RequestMessageData {
      uri: uri.to_string(),
      method: method.to_string(),
      user: "".to_string(),
      ip: client_ip.to_string(),
      response_status: code,
      request_body: "".to_string(),
      request_auth: "".to_string(),
    };

    //
    match serde_json::to_string(&request_info) {
      // OK
      Ok(json_str) => {
        format!("message: {}; addition: {}; request: {}", message, addition, json_str)
      }
      // ERR
      Err(e) => {
        error!("Failed to serialize request info: {}", e);
        format!("message: {}; addition: {}; request: {}", message, addition, e)
      }
    }

    }

	// ----------------------------------------------
	// M - DefaultController - handle_error_bad_request2
	// ----------------------------------------------
	pub fn handle_error_bad_request2(
		&self,
		req: &Request<Body>,
		code: u16,
		message: &str,
		addition: &str,
		client_ip: Option<String>,
	) -> Result<Response<Body>, String> {
		// IP Client
		let client_ip = client_ip.unwrap_or_else(|| "Unknown IP".to_string()); // Default ID

		// Data extraction from the request
		let uri = req.uri().to_string();
		let method = req.method().to_string();
		let user = req.headers().get("Authorization").map(|h| h.to_str().unwrap_or("")).unwrap_or(""); // User example
		let client_ip = client_ip; // Using the IP given

		// Creating the RequestMessageData struct
		let request_info = json!({
				"URI": uri,
				"Method": method,
				"User": user,
				"IP": client_ip,
				"RequestAuth": "",  // Replace with auth data if needed
				"ResponseStatus": code,
		});

		//
		let base_res = json!({
				"code": code,
				"message": message,
		});

		// Error handler for JSON serialization
		let request_info_str = serde_json::to_string(&request_info)
			.map_err(|e| format!("Error serializing request info: {}", e))?;

		// Log or error for serialization
		if request_info_str.is_empty() {
			return Err(format!(
				"message: {}; addition: {}; error: {}",
				message, addition, "Serialization Error"
			));
		}

		// Return "Unauthorized" status and error data
		let headers = HeaderMap::new();
		let body = format!(
			"message: {}; addition: {}; request: {}; response: {}",
			message, addition, request_info_str, base_res
		);

		// Return full response with code status
		Ok((StatusCode::UNAUTHORIZED, headers, body).into_response())
	}
}

// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// impl - ContainerController
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
impl ContainerController {
	// ----------------------------------------------
	// M - new
	// ----------------------------------------------
	pub fn new(state: Arc<Mutex<AppState>>, new_token: String) -> Self {
		//
		logger_debug!("");

		//
		ContainerController {
			state: state,
			default_controller: DefaultController::new(new_token),
		}
	}

	// ----------------------------------------------
	// M - ContainerController - create_mika
	// ----------------------------------------------
    async fn create_container(
      &self,
      req: Request<Body>,
  ) -> impl axum::response::IntoResponse {
		//
		logger_debug!("");
   
    //
    let ConnectInfo(addr) = req.extensions().get::<ConnectInfo<SocketAddr>>()
        .expect("ConnectInfo should be present");
    debug!("Client IP : {}", addr.ip());

		//
		let response = self.process_payload_container(req).await;

    //
    response
	}

	// ----------------------------------------------
	// M - ContainerController - process_payload_mika
	// ----------------------------------------------
	async fn process_payload_container(&self, req: Request<Body>) -> impl IntoResponse {
		//
		logger_debug!("");

    //
    let (parts, body) = req.into_parts();

    let headers = parts.headers.clone();
    let uri = parts.uri.clone();
    let method = parts.method.clone();
    let extensions = axum::http::Extensions::new();
    
    let ConnectInfo(addr) = parts.extensions.get::<ConnectInfo<SocketAddr>>()
    .expect("ConnectInfo should be present");


    //
    debug!("Client IP: {}", addr.ip());

    // body_bytes
    let body_bytes = match to_bytes(body, usize::MAX).await {
      // OK
      Ok(bytes) => {
        bytes
      }
      // ERR
      Err(e) => {
        let message = format!("Failed to read request body: {}", e);
        let err_mes = self.default_controller.handle_error_status_bad_request(
            consts::ERROR_CODE__JSON__UNMARSHAL_FAILED,
            &message,
            "",
            &headers,
            &uri,
            &method,
            &addr.ip().to_string(),
            &extensions,
        ).await;
        error!("{}", err_mes);
        return (
          HeaderMap::new(),
                    JsonResponse(DataRes {
                        base_res: BaseRes {
                            code: consts::ERROR_CODE__JSON__UNMARSHAL_FAILED,
                            message: err_mes,
                        },
                        data: None,
                    }),
                );
    }
    };

    // serde_json::from_slice
    let container = match serde_json::from_slice::<Container>(&body_bytes) { // deserialize the JSON file into a Container
      // OK
      Ok(container) => {
        info!("Container deserialized: {:?}", container);
        container
      }
      // ERR
      Err(e) => {
        //
        let message = format!("get body error: {}", e);
        let err_mes = self.default_controller.handle_error_status_bad_request(
            consts::ERROR_CREATE_CONTAINER_FAILED,
            &message,
            "",
            &headers,
            &uri,
            &method,
            &addr.ip().to_string(),
            &extensions,
        ).await;
        error!("{}", err_mes);
        return (
          HeaderMap::new(),
          JsonResponse(DataRes {
              base_res: BaseRes {
                  code: consts::ERROR_CREATE_CONTAINER_FAILED,
                  message: err_mes,
              },
              data: None,
          }),
        );
      }
    };

    //
    let raw_app_response = match create_task(container).await {
      // OK
      Ok(response) => {
        response
      }
      // ERR
      Err(e) => {
        //
        let app_response = AppResponse {
          exit_cause: "".to_string(),
          stdout: "".to_string(),
          stderr: e.to_string(),
          exit_code: -1,
        };
      
      //
      let app_response_json = serde_json::to_string(&app_response)
        .unwrap_or_else(|_| "Failed to serialize response".to_string());
      let message = format!("create container failed, error: {}, logs: \n{}", e, app_response_json);

      //
      error!("original message: {}", message);

      let err_mes = self.default_controller.handle_error_status_bad_request(
        consts::ERROR_CREATE_CONTAINER_FAILED,
        &message,
        "",
        &headers,
        &uri,
        &method,
        &addr.ip().to_string(),
        &extensions,
      ).await;

      error!("{}", err_mes);
      return (
      HeaderMap::new(),
                    JsonResponse(DataRes {
                        base_res: BaseRes {
                            code: consts::ERROR_CREATE_CONTAINER_FAILED,
                            message: err_mes,
                        },
                        data: None,
                    }),
                  );

      } // End ERR


    };


    // success
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    let app_response_json = serde_json::to_string(&raw_app_response)
      .unwrap_or_else(|_| "Failed to serialize response".to_string());

    let renewal = true;
    let (mesg, base_res, new_token_opt) = self.default_controller.handle_success_normal(
      200,
      &app_response_json,
      "",
      renewal,
      &headers,
      &uri,
      &method,
      &body_str,
      &addr.ip().to_string(),
      &extensions,
    );
    let res: DataRes<AppResponse> = DataRes { 
      base_res,
      data: None
    };
    info!("{}", mesg);


      //
      let mut response_headers = HeaderMap::new();
      if let Some(token) = new_token_opt {
          response_headers.insert("NewToken", token.parse().unwrap());
      }
      (response_headers, JsonResponse(res))


			}

	// ----------------------------------------------
	// M - ContainerController - get_container
	// ----------------------------------------------
	async fn get_container(&self, req: Request<Body>) -> impl IntoResponse {
		//
		logger_debug!("");

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

				//
				debug!("task = {:#?}", &task);

				// Call handle_success2 to build the response
				match self.default_controller.handle_success2(
					&req,
					code,
					message,
					"",
					true,
					Some(client_ip.to_string()),
					&task,
				) {
					//
					Ok(response_body) => {
						//
						response_body // Return the Response directly
					}

					//
					Err(err) => {
						error!("Failed to create response: {}", err);
						(StatusCode::INTERNAL_SERVER_ERROR, Json(err)).into_response()
					}
				}
			}

			Err(err) => {
				let message_error = format!("get container info failed, error: {}", err);
				let code = 400;

				match self.default_controller.handle_error_bad_request2(
					&req,
					code,
					&message_error,
					"additionMessageError",
					Some(client_ip.to_string()),
				) {
					Ok(response) => response, // Return the Response directly
					Err(err) => {
						error!("Failed to create response: {}", err);
						(StatusCode::INTERNAL_SERVER_ERROR, Json(err)).into_response()
					}
				}
			}
		}
	}

	// ----------------------------------------------
	// M - ContainerController - get_health
	// ----------------------------------------------
	async fn get_health(&self) -> Json<BaseRes> {
		//
		logger_debug!("");

		//
		let base_res = self.default_controller.handle_success_simple(200, "Server is healthy.");

		//
		Json(base_res)
	}

	// ---------------------------------------------------
	// M - ContainerController - delete_container
	// ---------------------------------------------------
	async fn delete_container(&self) -> impl IntoResponse {
		//
		logger_debug!("");

		//
		match module_worker::delete_task().await {
			//
			Ok(_) => {
				//
				let base_res = self.default_controller.handle_success_simple(200, "DELETING container OK.");

				Json(base_res)
			}

			//
			Err(err) => {
				//
				let err_message_default = "DELETING container BAD.".to_string();

				//
				let err_message = format!("{}{}", err_message_default, err).to_string();

				//
				let base_res = self.default_controller.handle_error_bad_request_simple(400, &err_message);

				Json(base_res)
			}
		}
	}

	// ---------------------------------------------------
	// M - ContainerController - cancel_container_task
	// ---------------------------------------------------
	async fn cancel_container_task(&self, req: Request<Body>) -> impl IntoResponse {
		//
		logger_debug!("");

		let headers: &HeaderMap = req.headers();

		//
		warn!("headers = {:#?}", headers);

		//
		match module_worker::cancel_inter_task().await {
			//
			Ok(_) => {
				//
				let base_res = self.default_controller.handle_success_simple(200, "CANCELING task OK.");

				Json(base_res)
			}
			//
			Err(err) => {
				//
				let err_message_default = "CANCELING task BAD.".to_string();

				//
				let err_message = format!("{}{}", err_message_default, err).to_string();

				//
				let base_res = self.default_controller.handle_error_bad_request_simple(400, &err_message);

				Json(base_res)
			}
		}
	}
  
}

// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------
// ----------------------------------------------

// ---------------------------------------------------
// F - manager_server
// ---------------------------------------------------
pub async fn manager_server(result: Result<&'static str, &'static str>) -> Result<&str, &str> {
	//
	logger_debug!("");

	//
	let str = "OK!";

	//
	let router = routing_init().await;

	//
	match result {
		// OK
		Ok(answer) => {
			//
			if answer == "start" {
				// Bind the address to the listener.
				let listener = tokio::net::TcpListener::bind(DEFAULT_ADDRESS).await.unwrap();

				// Message.
				println!("Listening on {}", listener.local_addr().unwrap());





				// //
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

		//
		Err(answer) => {
			error!("ERROR: Weird error: {}", answer);
		}
	}

	//
	Ok(&str)
}


// ---------------------------------------------------
// routing_init
// ---------------------------------------------------
async fn routing_init() -> Router {
	//
	logger_debug!("");

	//
	let methods = vec![Method::GET, Method::POST, Method::DELETE];
	let headers = vec![AUTHORIZATION, CONTENT_TYPE];

	// CORS
	let cors = CorsLayer::new().allow_origin(Any).allow_methods(methods).allow_headers(headers);

	//
	let name: String = String::from("Hello.");

	//
	let state = Arc::new(Mutex::new(AppState {
		name: name,
	}));

	let container_controller =
		Arc::new(ContainerController::new(state.clone(), "new_token".to_string()));

	//
	let container_controller = container_controller.clone();

	// Router
	let router = Router::new()
		//
		.route("/", get(handler))
		//
		// create
		.route(ROUTE_SW_API_V1_CONTAINER, {
			let controller = container_controller.clone();
			post(move |body| async move { controller.create_container(body).await })
		})
		//
		// delete
		.route(ROUTE_SW_API_V1_CONTAINER, {
			let controller = container_controller.clone();
			delete(move || async move { controller.delete_container().await })
		})
		//
		// get container
		.route(ROUTE_SW_API_V1_CONTAINER, {
			let controller = container_controller.clone();
			get(move |req: Request<Body>| async move {
				controller.get_container(req).await
			})
		})
		//
		// cancel
		.route(ROUTE_SW_API_V1_CONTAINER_CANCEL, {
			let controller = container_controller.clone();
			post(move |req: Request<Body>| async move { controller.cancel_container_task(req).await })
		})
		//
		// health
		.route(&ROUTE_SW_API_V1_PUB_HEALTH, {
			let controller = container_controller.clone();
			get(move || async move { controller.get_health().await })
		})
		//
		.with_state(state)
		.layer(cors);

	//
	router
}

// ---------------------------------------------------
// handler
// ---------------------------------------------------
async fn handler() -> Html<String> {
	//
	logger_debug!("");

	//
	let today = chrono::Local::now();
	let formatted_date = today.format("%Y-%m-%d %H:%M:%S").to_string();

	//
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

	//
	Html(html_content)
}
