use std::io::{self, IsTerminal};

fn main() -> std::process::ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let stderr_is_tty = stderr.is_terminal();
    let mut stdin_lock = stdin.lock();
    let mut stdout_lock = stdout.lock();
    let mut stderr_lock = stderr.lock();
    let code = rpm_cli::run_cli_args_with_tty(
        std::env::args_os(),
        &mut stdin_lock,
        &mut stdout_lock,
        &mut stderr_lock,
        None,
        stderr_is_tty,
    );
    std::process::ExitCode::from(code as u8)
}
