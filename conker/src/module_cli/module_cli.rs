// ---------------------------------------------------
// import
// ---------------------------------------------------
use clap::{Arg, ArgAction, Command};

// ---------------------------------------------------
// const
// ---------------------------------------------------
const _STR_SUB_CMD_CONKER: &str = "conker";
const STR_SUB_CMD_START: &str = "start";
const STR_SUB_CMD_EXIT: &str = "exit";

// ---------------------------------------------------
// create_cli
// ---------------------------------------------------
fn create_cli() -> Result<&'static str, &'static str> {
	// The first command node ("conker" here) is the first node, implicitly called.
	let matches = Command::new("conker")
		.about("Conker is a tool for generating certificates and starting up nginx server in TEE.")
		.version("5.2.1")
		.subcommand_required(true)
		.arg_required_else_help(true)
		// Query subcommand
		// We need to "init" subcommands in order to call them later.
		.subcommand(
			Command::new(STR_SUB_CMD_START)
				.short_flag('S')
				.long_flag(STR_SUB_CMD_START)
				.about("Starting server where Conker is.")
				.arg(
					Arg::new("search")
						.short('s')
						.long("search")
						.help("search locally installed packages for matching strings")
						.conflicts_with("info")
						.action(ArgAction::Set)
						.num_args(1..),
				)
				.arg(
					Arg::new("info")
						.long("info")
						.short('i')
						.conflicts_with("search")
						.help("view package information")
						.action(ArgAction::Set)
						.num_args(1..),
				),
		)
		.subcommand(
			Command::new(STR_SUB_CMD_EXIT)
				.short_flag('E')
				.long_flag(STR_SUB_CMD_EXIT)
				.about("Stopping server where Conker is."),
		)
		.get_matches();

	// Checks if the user has written a command (we take it from the "matches" variable).
	match matches.subcommand() {
		Some(("start", query_matches)) => {
			//
			if let Some(packages) = query_matches.get_many::<String>("info") {
				// Displays all args with "comma_sep".
				// Example: cargo run -- --start --info a b c d
				// Result --> Retrieving info for a, b, c, d...
				let comma_sep = packages.map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
				println!("Retrieving info for {comma_sep}...");
			} else if let Some(queries) = query_matches.get_many::<String>("search") {
				let comma_sep = queries.map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
				println!("Searching Locally for {comma_sep}...");
			} else {
				// Command without any args: "cargo run -- --start".
				println!("\"conker\" command activated --> Conker has started.");
			}

			Ok("start")
		}
		Some(("exit", _)) => {
			println!("Stopping Axum the server.");
			Ok("exit")
		}
		_ => unreachable!(), // If all subcommands are defined above, anything else is unreachable
	}
}

// ---------------------------------------------------
// init_cli
// ---------------------------------------------------
async fn init_cli() {}

// ---------------------------------------------------
// manager_cli
// ---------------------------------------------------
pub async fn manager_cli() -> Result<&'static str, &'static str> {
	//
	init_cli().await;

	// If the help command is displayed then the program exit just after the command below.
	let result = create_cli();

	//
	result
}
