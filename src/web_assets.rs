use std::path::Path;

pub const WEB_DISTRIBUTION_DIRECTORY: &str = "web/build";

pub fn distribution_exists(repository_root: &Path) -> bool {
    repository_root
        .join(WEB_DISTRIBUTION_DIRECTORY)
        .join("index.html")
        .is_file()
}
