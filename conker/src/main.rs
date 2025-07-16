// imports
use std::process::exit;
use std::sync::OnceLock;
use tracing::{debug, error};
use tracing_appender::rolling;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Layer};

// modules
mod module_cli;
mod module_server;
mod module_worker;
mod module_utils;
mod error_codes;

mod pre_compute;
mod post_compute;

// static
static LOGGER_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

#[tokio::main]
async fn main() {
	run().await;
}

// ---------------------------------------------------
// init_logger
// ---------------------------------------------------
fn init_logger() {
	// create a file for logs
	let file_appender = rolling::daily("./logs", "all.log");
	let (non_blocking, guard) = tracing_appender::non_blocking(file_appender); // Non-blocking for writing in the file

	LOGGER_GUARD.set(guard).expect("Logger already initialized");

	// layer for console output
	let console_layer = fmt::layer()
		.with_writer(std::io::stdout)
		.with_target(false)
		.with_line_number(true)
		.with_file(true)
		.with_filter(EnvFilter::from_default_env()); // using RUST_LOG for filtering logs

	// layer to write in the file
	let file_layer = fmt::layer()
		.with_writer(non_blocking) // Nont blocking for writing in the file
		.with_target(false)
		.with_filter(EnvFilter::from_default_env()); // RUST_LOG env for filtering the logs

	// combine the both layers: for the console and for the file
	tracing_subscriber::registry()
		.with(console_layer) // console
		.with(file_layer) // file
		.init();

	debug!("Logger has started");
}

// ---------------------------------------------------
// run
// ---------------------------------------------------
async fn run() {
	init_logger();

	// manager_cli
	let result_from_cli = module_cli::module_cli::manager_cli().await;
	verify_result(result_from_cli).await;
	debug!("After result_from_cli");

	// manager_worker
	let result_from_worker = module_worker::manager_worker().await;
	verify_result(result_from_worker).await;
	debug!("After result_from_worker");

	// // manager_server
	let result_from_server: Result<&str, &str> = module_server::manager_server(result_from_cli).await;
	verify_result(result_from_server).await;
	debug!("After result_from_server");
}

// ---------------------------------------------------
// verify_result
// ---------------------------------------------------
async fn verify_result(result: Result<&'static str, &'static str>) {
	match result {
		Ok(message) => {
			debug!("Success: {}", message);
		}
		Err(error) => {
			error!("Error: {}", error);
			exit(-12345)
		}
	}
}
