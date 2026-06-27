use std::{
    collections::{BTreeSet, HashSet},
    env, fs,
    path::{Component, Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

const WEB_DISTRIBUTION_DIRECTORY: &str = "web/build";
const DEVELOPMENT_FIXTURE_DIRECTORY: &str = "tests/fixtures/web-assets";
const MAX_ASSET_COUNT: usize = 4_096;
const MAX_ASSET_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_ASSET_BYTES: u64 = 128 * 1024 * 1024;
const MAX_INLINE_SCRIPT_HASHES: usize = 256;

fn main() {
    println!("cargo:rerun-if-changed={WEB_DISTRIBUTION_DIRECTORY}");
    println!("cargo:rerun-if-changed={DEVELOPMENT_FIXTURE_DIRECTORY}");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=EXECUTOR_WEB_ASSETS_DIR");

    let profile = env::var("PROFILE").unwrap_or_default();
    let override_directory = env::var_os("EXECUTOR_WEB_ASSETS_DIR").map(PathBuf::from);
    let production_assets = profile != "debug" || override_directory.is_some();
    let source = if let Some(source) = override_directory.as_deref() {
        println!("cargo:rerun-if-changed={}", source.display());
        source
    } else if production_assets {
        let source = Path::new(WEB_DISTRIBUTION_DIRECTORY);
        if !source.join("index.html").is_file() {
            panic!(
                "production packaging requires {WEB_DISTRIBUTION_DIRECTORY}/index.html; run the web asset packaging step before compiling the production binary"
            );
        }
        source
    } else {
        Path::new(DEVELOPMENT_FIXTURE_DIRECTORY)
    };

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let copied_assets = output.join("embedded-web-assets");
    let _ = fs::remove_dir_all(&copied_assets);
    fs::create_dir_all(&copied_assets).expect("embedded web asset output directory is created");

    let mut relative_paths = Vec::new();
    collect_files(source, source, &mut relative_paths);
    relative_paths.sort();
    if relative_paths.len() > MAX_ASSET_COUNT {
        panic!(
            "web asset distribution contains {} files; the maximum is {MAX_ASSET_COUNT}",
            relative_paths.len()
        );
    }
    if !relative_paths.iter().any(|path| path == "index.html") {
        panic!("embedded web assets must include index.html");
    }
    let mut normalized_paths = HashSet::with_capacity(relative_paths.len());
    for path in &relative_paths {
        if !normalized_paths.insert(path.to_ascii_lowercase()) {
            panic!("web assets contain duplicate case-insensitive paths: {path}");
        }
    }
    if production_assets
        && !relative_paths.iter().any(|path| {
            path.starts_with("_app/immutable/")
                && matches!(
                    Path::new(path).extension().and_then(|value| value.to_str()),
                    Some("js" | "mjs" | "css")
                )
        })
    {
        panic!(
            "release web assets must contain at least one JavaScript or CSS file below _app/immutable"
        );
    }

    let mut generated = format!(
        "static EMBEDDED_WEB_ASSETS: [EmbeddedAsset; {}] = [\n",
        relative_paths.len()
    );
    let mut total_bytes = 0_u64;
    let mut content_security_policy = None;
    for relative_path in relative_paths {
        let asset_path = source.join(&relative_path);
        let content = fs::read(&asset_path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", asset_path.display()));
        let asset_bytes = content.len() as u64;
        if asset_bytes > MAX_ASSET_BYTES {
            panic!(
                "web asset {relative_path} is {asset_bytes} bytes; the per-file maximum is {MAX_ASSET_BYTES}"
            );
        }
        total_bytes = total_bytes
            .checked_add(asset_bytes)
            .filter(|bytes| *bytes <= MAX_TOTAL_ASSET_BYTES)
            .unwrap_or_else(|| {
                panic!(
                    "web asset distribution exceeds the {MAX_TOTAL_ASSET_BYTES}-byte aggregate maximum"
                )
            });
        let destination = copied_assets.join(&relative_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).expect("embedded web asset parent directory is created");
        }
        fs::write(&destination, &content).expect("web asset is copied into Cargo output");
        if relative_path == "index.html" {
            content_security_policy = Some(index_content_security_policy(&content));
        }
        let etag = format!("\"{:x}\"", Sha256::digest(&content));
        generated.push_str("    EmbeddedAsset { path: ");
        generated.push_str(&format!("{relative_path:?}"));
        generated.push_str(", content: include_bytes!(concat!(env!(\"OUT_DIR\"), ");
        generated.push_str(&format!(
            "{:?}",
            format!("/embedded-web-assets/{relative_path}")
        ));
        generated.push_str(")), etag: ");
        generated.push_str(&format!("{etag:?}"));
        generated.push_str(" },\n");
    }
    generated.push_str("];\n");
    let content_security_policy =
        content_security_policy.expect("embedded web assets include index.html");
    let generated =
        format!("static EMBEDDED_WEB_CSP: &str = {content_security_policy:?};\n{generated}");
    fs::write(output.join("embedded_web_assets.rs"), generated)
        .expect("embedded web asset manifest is written");
}

fn index_content_security_policy(index: &[u8]) -> String {
    let hashes = inline_script_hashes(index);
    let mut script_source = String::from("script-src 'self'");
    for hash in hashes {
        script_source.push_str(" 'sha256-");
        script_source.push_str(&hash);
        script_source.push('\'');
    }
    format!(
        "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; manifest-src 'self'; object-src 'none'; {script_source}; style-src 'self' 'unsafe-inline'; worker-src 'self'"
    )
}

fn inline_script_hashes(index: &[u8]) -> BTreeSet<String> {
    const OPEN: &[u8] = b"<script";
    const CLOSE: &[u8] = b"</script";

    let mut hashes = BTreeSet::new();
    let mut cursor = 0;
    loop {
        let next_open = find_ascii_tag(index, OPEN, cursor);
        let next_close = find_ascii_tag(index, CLOSE, cursor);
        match (next_open, next_close) {
            (None, None) => break,
            (None, Some(_)) => panic!("index.html contains a closing script tag without an opener"),
            (Some(open), Some(close)) if close < open => {
                panic!("index.html contains a closing script tag without an opener")
            }
            (Some(open), _) => {
                let open_end = index[open + OPEN.len()..]
                    .iter()
                    .position(|byte| *byte == b'>')
                    .map(|offset| open + OPEN.len() + offset)
                    .unwrap_or_else(|| panic!("index.html contains an unclosed script opener"));
                let body_start = open_end + 1;
                let close = find_ascii_tag(index, CLOSE, body_start)
                    .unwrap_or_else(|| panic!("index.html contains an unclosed script body"));
                let close_end = index[close + CLOSE.len()..]
                    .iter()
                    .position(|byte| *byte == b'>')
                    .map(|offset| close + CLOSE.len() + offset)
                    .unwrap_or_else(|| panic!("index.html contains an unclosed script closer"));
                if !index[close + CLOSE.len()..close_end]
                    .iter()
                    .all(|byte| byte.is_ascii_whitespace())
                {
                    panic!("index.html contains a malformed closing script tag");
                }

                hashes.insert(STANDARD.encode(Sha256::digest(&index[body_start..close])));
                if hashes.len() > MAX_INLINE_SCRIPT_HASHES {
                    panic!(
                        "index.html contains more than {MAX_INLINE_SCRIPT_HASHES} distinct script bodies"
                    );
                }
                cursor = close_end + 1;
            }
        }
    }
    hashes
}

fn find_ascii_tag(input: &[u8], tag: &[u8], start: usize) -> Option<usize> {
    if tag.len() > input.len() {
        return None;
    }
    (start..=input.len() - tag.len()).find(|position| {
        input[*position..*position + tag.len()].eq_ignore_ascii_case(tag)
            && input
                .get(*position + tag.len())
                .is_none_or(|byte| byte.is_ascii_whitespace() || matches!(*byte, b'>' | b'/'))
    })
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<String>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("could not enumerate {}: {error}", directory.display()));
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let file_type = entry.file_type().unwrap_or_else(|error| {
            panic!("could not inspect {}: {error}", entry.path().display())
        });
        if file_type.is_symlink() {
            panic!(
                "web assets cannot contain symbolic links: {}",
                entry.path().display()
            );
        }
        if file_type.is_dir() {
            collect_files(root, &entry.path(), files);
        } else if file_type.is_file() {
            let entry_path = entry.path();
            let relative_path = entry_path
                .strip_prefix(root)
                .expect("asset remains below its root");
            validate_asset_path(relative_path);
            files.push(
                relative_path
                    .to_str()
                    .unwrap_or_else(|| {
                        panic!("web asset path is not UTF-8: {}", entry_path.display())
                    })
                    .replace('\\', "/"),
            );
        }
    }
}

fn validate_asset_path(path: &Path) {
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            panic!(
                "web asset path contains an unsafe component: {}",
                path.display()
            );
        }
        let component = component
            .as_os_str()
            .to_str()
            .unwrap_or_else(|| panic!("web asset path is not UTF-8: {}", path.display()));
        if component.starts_with('.')
            || component.contains('\\')
            || component.contains('%')
            || component.chars().any(char::is_control)
        {
            panic!(
                "web asset path contains a hidden or unsafe component: {}",
                path.display()
            );
        }
    }

    let extension = path.extension().and_then(|extension| extension.to_str());
    let allowed = matches!(
        extension,
        Some(
            "html"
                | "css"
                | "js"
                | "mjs"
                | "json"
                | "svg"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "avif"
                | "ico"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
                | "txt"
                | "xml"
                | "webmanifest"
                | "wasm"
        )
    );
    if !allowed {
        panic!(
            "web asset has an unsupported extension (source maps and secret/config files are not embedded): {}",
            path.display()
        );
    }
}
