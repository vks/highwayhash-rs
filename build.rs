use std::process::Command;

fn main() {
    std::env::set_current_dir("highwayhash").unwrap();
    Command::new("bazel").args(&["build", ":all", "-c", "opt", "--copt=-mavx2", "--copt=-fPIC"])
        .status()
        .expect("Failed to run bazel. \
                 Please make sure it is installed and that your CPU supports AVX2.");

    println!("cargo:rustc-link-search=native=highwayhash/bazel-out/local_linux-opt/bin");
    //^ FIXME: This only works on Linux.
    println!("cargo:rustc-link-lib=static=highway_tree_hash");
    println!("cargo:rustc-link-lib=static=sip_tree_hash");
    println!("cargo:rustc-link-lib=static=sip_hash");
}
