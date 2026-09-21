use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PC_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let explicit = std::env::var("PC_BUILD_GIT_SHA")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_SHA")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });

    let (sha, dirty) = if let Some(sha) = explicit {
        (sha, false)
    } else {
        let sha = git_output(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
        let dirty = git_dirty();
        (sha, dirty)
    };

    let short = sha.trim().chars().take(12).collect::<String>();
    let value = if dirty && short != "unknown" {
        format!("{short}-dirty")
    } else {
        short
    };
    println!("cargo:rustc-env=PC_BUILD_GIT_SHA={value}");
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| !output.stdout.is_empty())
}
