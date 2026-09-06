fn main() {
    println!("cargo:rerun-if-changed=static/approval.wat");
    let wasm = wat::parse_file("static/approval.wat").expect("compile approval reviewer");
    let bytes = format!("{:?}", wasm);
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("approval-wasm.json"), bytes).expect("write embedded reviewer");
}
