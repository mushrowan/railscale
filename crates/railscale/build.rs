//! build script to capture version information at compile time

use std::process::Command;

fn main() {
    // rerun if git HEAD changes
    println!("cargo:rerun-if-changed=.git/HEAD");

    // get git commit SHA
    let sha = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=RAILSCALE_GIT_SHA={sha}");

    // check if working tree is dirty
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    println!("cargo:rustc-env=RAILSCALE_GIT_DIRTY={dirty}");

    // build timestamp (UTC)
    let timestamp = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=RAILSCALE_BUILD_TIMESTAMP={timestamp}");

    // rust compiler version
    let rustc_version = Command::new("rustc")
        .args(["--version"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .strip_prefix("rustc ")
                .unwrap_or("unknown")
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=RAILSCALE_RUSTC_VERSION={rustc_version}");
}
