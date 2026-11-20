use std::io;

fn main() -> std::process::ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut stdin_lock = stdin.lock();
    let mut stdout_lock = stdout.lock();
    let mut stderr_lock = stderr.lock();
    let code = rpm_cli::run_cli_args(
        std::env::args_os(),
        &mut stdin_lock,
        &mut stdout_lock,
        &mut stderr_lock,
        None,
    );
    std::process::ExitCode::from(code as u8)
}
