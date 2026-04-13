use std::{env, process::Command};

use anyhow::{Context, Result, bail};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("build-ebpf") => build_ebpf(!args.any(|arg| arg == "--debug")),
        Some(command) => bail!("unknown xtask command '{command}'"),
        None => {
            print_help();
            Ok(())
        }
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let profile = if release { "release" } else { "debug" };

    let mut command = Command::new("rustup");
    command
        .arg("run")
        .arg("nightly")
        .arg("cargo")
        .arg("build")
        .arg("-Z")
        .arg("build-std=core")
        .arg("-p")
        .arg("walle-ebpf")
        .arg("--bin")
        .arg("walle-ebpf")
        .arg("--features")
        .arg("ebpf")
        .arg("--target")
        .arg("bpfel-unknown-none");
    command.env("RUSTFLAGS", "-Zunstable-options -Cpanic=immediate-abort");

    if release {
        command.arg("--release");
    }

    let status = command.status().context("failed to invoke cargo build")?;
    if !status.success() {
        bail!(
            "eBPF build failed; ensure the nightly toolchain and rust-src are available for `cargo +nightly build -Z build-std=core`"
        );
    }

    println!("built eBPF object: target/bpfel-unknown-none/{profile}/walle-ebpf");
    Ok(())
}

fn print_help() {
    println!("xtask commands:");
    println!("  build-ebpf [--debug]");
}
