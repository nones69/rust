use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let linker_script = PathBuf::from("linker.ld");
    let boot_asm = PathBuf::from("src/arch/x86_64/boot.s");

    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!("cargo:rerun-if-changed={}", boot_asm.display());
    println!("cargo:rerun-if-changed=build.rs");

    println!(
        "cargo:rustc-link-arg=-T{}",
        linker_script
            .canonicalize()
            .expect("linker.ld not found — run from rust-os/ directory")
            .display()
    );

    println!("cargo:rustc-link-arg=--entry=_start32");
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=--image-base=0x100000");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let boot_obj = out_dir.join("boot.o");

    let status = Command::new("as")
        .args(["-o"])
        .arg(&boot_obj)
        .arg(&boot_asm)
        .status()
        .expect("failed to invoke `as` — install binutils (apt install binutils)");

    if !status.success() {
        panic!("assembling boot.s failed");
    }

    println!("cargo:rustc-link-arg={}", boot_obj.display());
}