use anyhow::Result;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    println!("xtask scaffold ready");
    println!("future tasks: build-ebpf, package, verify-env");
    Ok(())
}
