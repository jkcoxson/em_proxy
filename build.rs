// Jackson Coxson

use std::process::Command;

fn main() {
    // Generate the cbindings
    let _ = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "cbindgen -c cbindgen.toml -o em_proxy.h"])
            .output()
            .expect("Failed to generate c bindings")
    } else {
        Command::new("sh")
            .arg("-c")
            .arg("cbindgen -c cbindgen.toml -o em_proxy.h")
            .output()
            .expect("Failed to generate c bindings")
    };
}
