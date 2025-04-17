// build.rs
fn main() {
    println!(
        "cargo:rustc-env=PROJECT_ROOT={}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
}
