mod app;
mod data;
mod helper;
mod intune;
mod mdm;
mod util;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s == "--helper").unwrap_or(false) {
        std::process::exit(helper::run(&args[2..]));
    }
    if let Err(e) = app::run() {
        eprintln!("Fehler: {e}");
        std::process::exit(1);
    }
}
