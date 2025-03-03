// imports
// use backtrace::Backtrace;
use std::process::exit;
use std::sync::OnceLock;
use tracing::{debug, error /*, info, trace, warn*/};
use tracing_appender::rolling;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Layer};

// modules
mod module_cli;
mod module_server;
mod module_worker;

// static
static LOGGER_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

// macro
#[macro_export]
macro_rules! logger_debug {
    ($msg:expr) => {
        // get stack calls
        let backtrace = backtrace::Backtrace::new();

        // get and display the function name from the stack
        let mut function_name = String::new();
        for frame in backtrace.frames() {
            for symbol in frame.symbols() {
                if let Some(name) = symbol.name() {
                    function_name = name.to_string();
                    // filtering with "{{closure}}" string
                    if function_name.contains("{{closure}}") {
                        function_name = function_name.split("{{closure}}").next().unwrap_or_default().to_string(); // first element or empty string
                    }
                    break;
                }
            }
            if !function_name.is_empty() {
                break;
            }
        }

        // delete the project name
        let project_name = env!("CARGO_PKG_NAME").replace("-", "_"); // need it because "-" are replaced by "_", so we want the final name
        let clean_name = function_name
            .strip_prefix(&(project_name.to_owned() + "::")) // convert &str to String to concatenation and remove prefix
            .unwrap_or(&function_name); // if nothing is removed, keep the original name

        // logging
        debug!(
            "{}{}>>{}",
            clean_name,
            line!(),
            $msg
        );
    };
}

// ---------------------------------------------------
// main
// ---------------------------------------------------
#[tokio::main]
async fn main() {
	//
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
		.with_writer(std::io::stdout) //
		.with_target(false)
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

	logger_debug!("Logger has started");
}

// ---------------------------------------------------
// run
// ---------------------------------------------------
async fn run() {
	//
	init_logger();

	// manager_cli
	let result_from_cli = module_cli::module_cli::manager_cli().await;
	verify_result(result_from_cli).await;

	//
	logger_debug!("After result_from_cli");

	// manager_worker
	let result_from_worker = module_worker::manager_worker().await;
	verify_result(result_from_worker).await;

	// // manager_server
	let result_from_server: Result<&str, &str> = module_server::manager_server(result_from_cli).await;
	verify_result(result_from_server).await;

	//
	logger_debug!("After result_from_server");
}

// ---------------------------------------------------
// verify_result
// ---------------------------------------------------
async fn verify_result(result: Result<&'static str, &'static str>) {
	//
	logger_debug!("After result_from_cli");

	//
	match result {
		//
		Ok(message) => {
			debug!("Success: {}", message);
		}
		Err(error) => {
			error!("Error: {}", error);
			exit(-12345)
		}
	} // result
}
