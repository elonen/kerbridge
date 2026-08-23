// Embed the resource script: the app manifest (themed Common-Controls v6 + PerMonitor-V2
// DPI), the application icon, and the VERSIONINFO block that gives Windows a friendly
// name for the process. embed-resource shells out to windres for the
// x86_64-pc-windows-gnu target. Track the .rc's inputs so a regenerated icon or edited
// manifest re-embeds (embed-resource only tracks the .rc itself), and Cargo.toml too,
// because the version below comes from it.
fn main() {
    println!("cargo:rerun-if-changed=kerbridge-agent.rc");
    println!("cargo:rerun-if-changed=kerbridge-agent.manifest");
    println!("cargo:rerun-if-changed=ui/icons/app-icon.ico");
    println!("cargo:rerun-if-changed=Cargo.toml");
    // VERSIONINFO wants the version as three integers *and* as a string; the .rc builds
    // the string from these, so the crate version stays the only place it is written.
    let macros = ["MAJOR", "MINOR", "PATCH"].map(|part| {
        let v = std::env::var(format!("CARGO_PKG_VERSION_{part}")).unwrap();
        format!("VER_{part}={v}")
    });
    embed_resource::compile("kerbridge-agent.rc", macros);
}
