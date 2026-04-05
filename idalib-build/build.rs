use std::env;

fn main() {
    let sdk = env::var("DEP_IDALIB_SDK").expect("DEP_IDALIB_SDK set by idalib-sys");
    println!("cargo:rustc-env=IDALIB_SDK={sdk}");
}
