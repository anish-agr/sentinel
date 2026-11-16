fn main() {
    if let Err(e) = sentineld::run_foreground() {
        eprintln!("sentinel daemon failed: {e:#}");
        sentineld::clear_info();
        std::process::exit(1);
    }
}
