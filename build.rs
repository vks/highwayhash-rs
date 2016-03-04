use std::env;
use std::process::Command;

fn main() {
    // let out_dir = env::var("OUT_DIR").unwrap();

    std::env::set_current_dir("highwayhash").unwrap();
    Command::new("bazel").args(&["build", ":all", "-c", "opt", "--copt=-mavx2"])
        .status().unwrap();

    println!("cargo:rustc-link-search=native=highwayhash/bazel-out/local_linux-opt/bin");
    println!("cargo:rustc-link-lib=static=highway_tree_hash");
    // println!("cargo:rustc-link-lib=static=mf");
}
