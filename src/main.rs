use std::process::ExitCode;

fn main() -> ExitCode {
    match ember_agent_monitor::cli::run(std::env::args().collect()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("ember-agent: {e}");
            ExitCode::from(2)
        }
    }
}
