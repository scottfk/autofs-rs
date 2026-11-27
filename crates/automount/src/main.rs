//! `automount`.

fn main() {
    // A panic in any thread (a path not ported yet) stops the daemon rather
    // than leaving the kernel waiting for an answer that never comes.
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        std::process::abort();
    }));
    automount::daemon::automount::main();
}
