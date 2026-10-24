//! BoxKernel entry point — port of cli/cli.c `main()`.

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // `proot --shm-helper` — detached sysvipc backing-fd daemon.
    if args.len() == 2 && args[1] == "--shm-helper" {
        boxkernel::extension::sysvipc::shm::shm_helper_main();
    }

    // talloc_autofree equivalent: temp files and binding placeholders
    // are removed when the process exits.
    boxkernel::sys::at_exit(temp_cleanup_atexit);

    // Pre-create the first tracee (pid == 0 placeholder).
    let tracee = match boxkernel::tracee::get_tracee(0, true) {
        Some(t) => t,
        None => {
            eprintln!("fatal error: can't allocate the first tracee");
            std::process::exit(libc::EXIT_FAILURE);
        }
    };

    let status = boxkernel::cli::run(&tracee, &args);
    if status < 0 {
        if boxkernel::cli::EXIT_FAILURE.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("fatal error: see `proot --help`.");
            std::process::exit(libc::EXIT_FAILURE);
        }
        std::process::exit(libc::EXIT_SUCCESS);
    }
    std::process::exit(status);
}

extern "C" fn temp_cleanup_atexit() {
    boxkernel::path::temp::cleanup();
}
