use rayon::prelude::*;
use serde_json::Value;
use std::fs;
use walkdir::{DirEntry, WalkDir};

const SUSPICIOUS_VERSIONS: [&str; 2] = ["1.14.1", "0.30.4"];

fn is_suspicious(version: &str) -> bool {
    SUSPICIOUS_VERSIONS.contains(&version)
}

// Skip heavy/useless dirs
fn is_ignored(entry: &DirEntry) -> bool {
    let path = entry.path().to_string_lossy();

    path.contains(".git")
        || path.contains("node_modules/.cache")
        || path.contains("target")
        || path.contains("Library")
}

// Match axios installed package
fn is_axios_pkg(entry: &DirEntry) -> bool {
    entry
        .path()
        .ends_with("node_modules/axios/package.json")
}

// Match package-lock.json
fn is_lockfile(entry: &DirEntry) -> bool {
    entry.file_name() == "package-lock.json"
}

fn main() {
    println!("======================================");
    println!("🚨 Axios Suspicious Version Scanner");
    println!("======================================\n");

    let roots = vec![
        "/Users",
        "/home",
        "/root",
        "/var/www",
        "/opt",
    ];

    let found = std::sync::atomic::AtomicBool::new(false);

    roots.par_iter().for_each(|root| {
        WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| !is_ignored(e))
            .filter_map(Result::ok)
            .for_each(|entry| {
                let path = entry.path();

                // --- Check 1: node_modules axios ---
                if is_axios_pkg(&entry) {
                    if let Ok(content) = fs::read_to_string(path) {
                        if let Ok(json) = serde_json::from_str::<Value>(&content) {
                            if let Some(version) = json["version"].as_str() {
                                if is_suspicious(version) {
                                    println!(
                                        "⚠️  FOUND suspicious axios {} → {}",
                                        version,
                                        path.display()
                                    );
                                    found.store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }

                // --- Check 2: package-lock.json ---
                if is_lockfile(&entry) {
                    if let Ok(content) = fs::read_to_string(path) {
                        for v in SUSPICIOUS_VERSIONS.iter() {
                            if content.contains(&format!("\"axios\""))
                                && content.contains(v)
                            {
                                println!(
                                    "⚠️  FOUND axios {} in lockfile → {}",
                                    v,
                                    path.display()
                                );
                                found.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
            });
    });

    println!("\n======================================");

    if found.load(std::sync::atomic::Ordering::Relaxed) {
        println!("🚨 Suspicious axios versions detected!");
        println!("");
        println!("Recommended:");
        println!("  1. Remove node_modules & lockfile");
        println!("  2. npm install axios@1.14.0 --save-exact");
        println!("  3. npm ci");
        println!("  4. Audit dependencies");
    } else {
        println!("✅ No suspicious axios versions found.");
    }

    println!("======================================");
}