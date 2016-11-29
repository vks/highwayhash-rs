use std::process::Command;
use std::env;

fn main() {
    std::env::set_current_dir("third_party/highwayhash").unwrap();
    // Rust requires position-independent code for any static library.
    env::set_var("CPPFLAGS", "-fPIC");
    env::set_var("CFLAGS", "-fPIC");
    let status = Command::new("make").args(&["libhighwayhash.a"])
        .status()
        .expect("Failed to run make. \
                 Please make sure it is installed");
    if !status.success() {
        panic!("make exited with an error. \
                Please make sure that your CPU supports AVX2.");
    }

    println!("cargo:rustc-link-search=native=third_party/highwayhash");
    println!("cargo:rustc-link-lib=static=highwayhash");
}
