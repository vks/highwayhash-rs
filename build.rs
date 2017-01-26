use std::process::Command;

fn main() {
    std::env::set_current_dir("highwayhash").unwrap();
    let status = Command::new("make")
        // Rust requires position-independent code for any static library.
        .args(&["HH_CXXFLAGS=-fPIC", "libhighwayhash.a"])
        .status()
        .expect("Failed to run make. \
                 Please make sure it is installed");
    if !status.success() {
        panic!("make exited with an error.");
    }

    println!("cargo:rustc-link-search=native=highwayhash");
    println!("cargo:rustc-link-lib=static=highwayhash");
}
