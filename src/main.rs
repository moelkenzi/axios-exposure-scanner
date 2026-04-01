use rayon::prelude::*;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use walkdir::{DirEntry, WalkDir};

const SUSPICIOUS_AXIOS_VERSIONS: [&str; 2] = ["1.14.1", "0.30.4"];
const SUSPICIOUS_DEPENDENCY: &str = "plain-crypto-js";

fn is_suspicious_axios(version: &str) -> bool {
    SUSPICIOUS_AXIOS_VERSIONS.contains(&version)
}

fn should_ignore(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();

    matches!(
        name.as_ref(),
        ".git"
            | ".next"
            | ".nuxt"
            | ".cache"
            | "target"
            | "Library"
            | "dist"
            | "build"
            | ".turbo"
            | ".expo"
            | ".idea"
            | ".vscode"
    )
}

fn is_installed_axios_pkg(path: &Path) -> bool {
    path.ends_with("node_modules/axios/package.json")
}

fn is_installed_plain_crypto_pkg(path: &Path) -> bool {
    path.ends_with("node_modules/plain-crypto-js/package.json")
}

fn is_package_lock(path: &Path) -> bool {
    path.file_name().map(|s| s == "package-lock.json").unwrap_or(false)
}

fn is_yarn_lock(path: &Path) -> bool {
    path.file_name().map(|s| s == "yarn.lock").unwrap_or(false)
}

fn is_pnpm_lock(path: &Path) -> bool {
    path.file_name()
        .map(|s| s == "pnpm-lock.yaml")
        .unwrap_or(false)
}

fn is_bun_lock(path: &Path) -> bool {
    path.file_name().map(|s| s == "bun.lock").unwrap_or(false)
}

fn read_file(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn print_hit(kind: &str, detail: &str, path: &Path) {
    println!("⚠️  [{}] {} → {}", kind, detail, path.display());
}

fn scan_installed_package_json(path: &Path, found: &AtomicBool) {
    let Some(content) = read_file(path) else {
        return;
    };

    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return;
    };

    let name = json.get("name").and_then(Value::as_str).unwrap_or("");
    let version = json.get("version").and_then(Value::as_str).unwrap_or("");

    if name == "axios" && is_suspicious_axios(version) {
        print_hit("installed", &format!("axios {}", version), path);
        found.store(true, Ordering::Relaxed);
    }

    if name == SUSPICIOUS_DEPENDENCY {
        print_hit("installed", SUSPICIOUS_DEPENDENCY, path);
        found.store(true, Ordering::Relaxed);
    }
}

fn scan_package_lock(path: &Path, found: &AtomicBool) {
    let Some(content) = read_file(path) else {
        return;
    };

    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return;
    };

    // npm v7+ lockfile format: "packages"
    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        for (pkg_path, pkg_data) in packages {
            let version = pkg_data.get("version").and_then(Value::as_str).unwrap_or("");
            let resolved_name = if pkg_path.ends_with("node_modules/axios") {
                Some("axios")
            } else if pkg_path.ends_with("node_modules/plain-crypto-js") {
                Some("plain-crypto-js")
            } else {
                pkg_data.get("name").and_then(Value::as_str)
            };

            match resolved_name {
                Some("axios") if is_suspicious_axios(version) => {
                    print_hit(
                        "package-lock",
                        &format!("axios {} (packages:{pkg_path})", version),
                        path,
                    );
                    found.store(true, Ordering::Relaxed);
                }
                Some("plain-crypto-js") => {
                    print_hit(
                        "package-lock",
                        &format!("plain-crypto-js (packages:{pkg_path})"),
                        path,
                    );
                    found.store(true, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    // npm v6 style: "dependencies"
    if let Some(deps) = json.get("dependencies").and_then(Value::as_object) {
        scan_npm_deps_recursive(deps, path, found);
    }
}

fn scan_npm_deps_recursive(
    deps: &serde_json::Map<String, Value>,
    lockfile_path: &Path,
    found: &AtomicBool,
) {
    for (name, value) in deps {
        let version = value.get("version").and_then(Value::as_str).unwrap_or("");

        if name == "axios" && is_suspicious_axios(version) {
            print_hit(
                "package-lock",
                &format!("axios {} (dependencies)", version),
                lockfile_path,
            );
            found.store(true, Ordering::Relaxed);
        }

        if name == "plain-crypto-js" {
            print_hit("package-lock", "plain-crypto-js (dependencies)", lockfile_path);
            found.store(true, Ordering::Relaxed);
        }

        if let Some(nested) = value.get("dependencies").and_then(Value::as_object) {
            scan_npm_deps_recursive(nested, lockfile_path, found);
        }
    }
}

fn scan_yarn_lock(path: &Path, found: &AtomicBool) {
    let Some(content) = read_file(path) else {
        return;
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim_end();

        if line.starts_with("axios@") || line.contains("\"axios@") {
            let mut version = None;
            let mut j = i + 1;

            while j < lines.len() {
                let l = lines[j];

                if !l.starts_with(' ') && !l.starts_with('\t') && !l.trim().is_empty() {
                    break;
                }

                let t = l.trim();
                if let Some(rest) = t.strip_prefix("version ") {
                    version = Some(rest.trim_matches('"').to_string());
                    break;
                }
                j += 1;
            }

            if let Some(v) = version {
                if is_suspicious_axios(&v) {
                    print_hit("yarn.lock", &format!("axios {}", v), path);
                    found.store(true, Ordering::Relaxed);
                }
            }
        }

        if line.contains("plain-crypto-js@") || line.contains("\"plain-crypto-js@") {
            print_hit("yarn.lock", "plain-crypto-js", path);
            found.store(true, Ordering::Relaxed);
        }

        i += 1;
    }
}

fn scan_pnpm_lock(path: &Path, found: &AtomicBool) {
    let Some(content) = read_file(path) else {
        return;
    };

    for line in content.lines() {
        let t = line.trim();

        if t.contains("/axios@") {
            for v in SUSPICIOUS_AXIOS_VERSIONS {
                if t.contains(&format!("/axios@{}", v)) {
                    print_hit("pnpm-lock.yaml", &format!("axios {}", v), path);
                    found.store(true, Ordering::Relaxed);
                }
            }
        }

        if t.contains("/plain-crypto-js@") {
            print_hit("pnpm-lock.yaml", "plain-crypto-js", path);
            found.store(true, Ordering::Relaxed);
        }
    }
}

fn scan_bun_lock(path: &Path, found: &AtomicBool) {
    let Some(content) = read_file(path) else {
        return;
    };

    for v in SUSPICIOUS_AXIOS_VERSIONS {
        if content.contains("axios") && content.contains(v) {
            print_hit("bun.lock", &format!("possible axios {}", v), path);
            found.store(true, Ordering::Relaxed);
        }
    }

    if content.contains("plain-crypto-js") {
        print_hit("bun.lock", "plain-crypto-js", path);
        found.store(true, Ordering::Relaxed);
    }
}

fn dedupe_roots() -> Vec<PathBuf> {
    let candidates = vec![
        "/Users",
        "/home",
        "/root",
        "/var/www",
        "/opt",
        "/srv",
        "/workspace",
        "/workspaces",
    ];

    let mut seen = HashSet::new();
    let mut roots = Vec::new();

    for root in candidates {
        let path = PathBuf::from(root);
        if path.exists() && seen.insert(path.clone()) {
            roots.push(path);
        }
    }

    roots
}

fn main() {
    println!("======================================");
    println!("🚨 Axios Exposure Scanner");
    println!("======================================\n");

    let roots = dedupe_roots();
    if roots.is_empty() {
        eprintln!("No scan roots found.");
        return;
    }

    let found = AtomicBool::new(false);
    let scanned_files = AtomicUsize::new(0);
    let walk_errors = AtomicUsize::new(0);

    roots.par_iter().for_each(|root| {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !should_ignore(e))
        {
            match entry {
                Ok(entry) => {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }

                    scanned_files.fetch_add(1, Ordering::Relaxed);

                    if is_installed_axios_pkg(path) || is_installed_plain_crypto_pkg(path) {
                        scan_installed_package_json(path, &found);
                    } else if is_package_lock(path) {
                        scan_package_lock(path, &found);
                    } else if is_yarn_lock(path) {
                        scan_yarn_lock(path, &found);
                    } else if is_pnpm_lock(path) {
                        scan_pnpm_lock(path, &found);
                    } else if is_bun_lock(path) {
                        scan_bun_lock(path, &found);
                    }
                }
                Err(_) => {
                    walk_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    println!("\n======================================");
    println!("Scanned files : {}", scanned_files.load(Ordering::Relaxed));
    println!("Walk errors   : {}", walk_errors.load(Ordering::Relaxed));
    println!("--------------------------------------");

    if found.load(Ordering::Relaxed) {
        println!("🚨 Suspicious Axios exposure indicators detected.");
        println!();
        println!("Recommended next steps:");
        println!("  1. Remove node_modules and lockfiles");
        println!("  2. Reinstall with a safe Axios version");
        println!("  3. Check for plain-crypto-js");
        println!("  4. Rotate secrets/tokens");
        println!("  5. Review shell history and CI logs");
    } else {
        println!("✅ No known suspicious Axios indicators found.");
        println!("Note: this still does NOT prove a machine was never compromised.");
    }

    println!("======================================");
}