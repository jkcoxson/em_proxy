// Jackson Coxson
use std::env;
use cbindgen;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::generate(crate_dir)
      .expect("Unable to generate C bindings")
      .write_to_file("em_proxy.h");
}
