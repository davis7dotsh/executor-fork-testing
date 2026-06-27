use std::{
    ffi::{OsStr, OsString},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use directories::BaseDirs;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SYSTEMD_SERVICE: &str = "executor.service";
const LAUNCHD_LABEL: &str = "dev.executor.gateway";
const STATUS_INACTIVE: i32 = 3;

const SYSTEMD_INSTALLER: &[u8] = include_bytes!("../scripts/install-systemd.sh");
const SYSTEMD_KEY_HELPER: &[u8] = include_bytes!("../scripts/lib/install-systemd-master-key.sh");
const SYSTEMD_UNIT: &[u8] = include_bytes!("../packaging/systemd/executor.service");
const SYSTEMD_ENV: &[u8] = include_bytes!("../packaging/systemd/executor.env.example");
const LAUNCHD_INSTALLER: &[u8] = include_bytes!("../scripts/install-launchd.sh");
const LAUNCHD_PLIST: &[u8] = include_bytes!("../packaging/launchd/dev.executor.gateway.plist");
const BOUNDED_LOGGER: &[u8] = include_bytes!("../packaging/launchd/bounded-log.sh");

#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    Install(ServiceInstallArgs),
    Status,
    Start,
    Stop,
    Restart,
    Remove,
}

#[derive(Args, Debug)]
pub struct ServiceInstallArgs {
    #[arg(long, help = "Install the service without starting it")]
    pub no_start: bool,
}

#[derive(Debug)]
pub struct ServiceOutcome {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ServiceOutcome {
    fn success(message: impl Into<Vec<u8>>) -> Self {
        Self {
            exit_code: 0,
            stdout: message.into(),
            stderr: Vec::new(),
        }
    }

    fn inactive() -> Self {
        Self {
            exit_code: STATUS_INACTIVE,
            stdout: b"inactive\n".to_vec(),
            stderr: Vec::new(),
        }
    }

    fn from_process(output: ProcessOutput, fallback: &[u8]) -> Self {
        let stdout = if output.stdout.is_empty() {
            fallback.to_vec()
        } else {
            output.stdout
        };
        Self {
            exit_code: 0,
            stdout,
            stderr: output.stderr,
        }
    }

    pub fn emit(self) -> Result<()> {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&self.stdout)?;
        stdout.flush()?;
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(&self.stderr)?;
        stderr.flush()?;
        if self.exit_code != 0 {
            std::process::exit(self.exit_code);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Linux,
    MacOs,
    Unsupported,
}

#[derive(Clone, Debug)]
struct ServicePaths {
    linux_binary: PathBuf,
    linux_unit: PathBuf,
    linux_manifest: PathBuf,
    linux_recovery: PathBuf,
    linux_lock: PathBuf,
    mac_executor_root: PathBuf,
    mac_install_root: PathBuf,
    mac_binary_dir: PathBuf,
    mac_binary: PathBuf,
    mac_library: PathBuf,
    mac_launch_agents: PathBuf,
    mac_plist: PathBuf,
    mac_wrapper: PathBuf,
    mac_logger: PathBuf,
    mac_manifest: PathBuf,
    mac_recovery: PathBuf,
    mac_config: PathBuf,
    mac_lock: PathBuf,
}

impl ServicePaths {
    fn for_home(home: &Path) -> Self {
        let mac_executor_root = home.join(".executor");
        let mac_install_root = mac_executor_root.join("service");
        let mac_binary_dir = mac_install_root.join("bin");
        let mac_library = home.join("Library");
        let mac_launch_agents = mac_library.join("LaunchAgents");
        let mac_manifest = mac_install_root.join("service-install.manifest");
        let mac_recovery = mac_install_root.join("service-install.recovery");
        let mac_config = mac_install_root.join("service-config");
        let mac_lock = mac_install_root.join("service-operation.lock");
        let mac_wrapper = mac_install_root.join("run-launchd.sh");
        let mac_logger = mac_install_root.join("bounded-log.sh");
        Self {
            linux_binary: PathBuf::from("/usr/local/bin/executor"),
            linux_unit: PathBuf::from("/etc/systemd/system/executor.service"),
            linux_manifest: PathBuf::from("/etc/executor/service-install.manifest"),
            linux_recovery: PathBuf::from("/etc/executor/service-install.recovery"),
            linux_lock: PathBuf::from("/etc/executor/service-operation.lock"),
            mac_executor_root,
            mac_binary: mac_binary_dir.join("executor"),
            mac_binary_dir,
            mac_install_root,
            mac_plist: mac_launch_agents.join("dev.executor.gateway.plist"),
            mac_wrapper,
            mac_logger,
            mac_manifest,
            mac_recovery,
            mac_config,
            mac_lock,
            mac_library,
            mac_launch_agents,
        }
    }
}

#[derive(Clone, Debug)]
struct ServiceContext {
    platform: Platform,
    effective_uid: u32,
    filesystem_uid: u32,
    current_exe: PathBuf,
    installation_source: PathBuf,
    home: PathBuf,
    temporary_root: PathBuf,
    paths: ServicePaths,
    #[cfg(test)]
    directory_sync_test: DirectorySyncTestState,
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct DirectorySyncTestState {
    failure: std::rc::Rc<std::cell::RefCell<Option<PathBuf>>>,
    events: std::rc::Rc<std::cell::RefCell<Vec<PathBuf>>>,
}

impl ServiceContext {
    fn system() -> Result<Self> {
        let platform = if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Unsupported
        };
        let home = BaseDirs::new()
            .context("could not determine the current user's home directory")?
            .home_dir()
            .to_path_buf();
        let effective_uid = effective_uid();
        let temporary_root = if platform == Platform::Linux {
            PathBuf::from("/var/tmp")
        } else {
            std::env::temp_dir()
        };
        let current_exe =
            std::env::current_exe().context("could not locate the running Executor binary")?;
        let installation_source = if platform == Platform::Linux {
            PathBuf::from("/proc/self/exe")
        } else {
            current_exe.clone()
        };
        Ok(Self {
            platform,
            effective_uid,
            filesystem_uid: effective_uid,
            current_exe,
            installation_source,
            paths: ServicePaths::for_home(&home),
            home,
            temporary_root,
            #[cfg(test)]
            directory_sync_test: DirectorySyncTestState::default(),
        })
    }
}

#[derive(Debug)]
struct ProcessOutput {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ProcessOutput {
    fn success(&self) -> bool {
        self.code == Some(0)
    }
}

trait CommandRunner {
    fn run(&mut self, program: &OsStr, arguments: &[OsString]) -> Result<ProcessOutput>;
}

struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, program: &OsStr, arguments: &[OsString]) -> Result<ProcessOutput> {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .with_context(|| format!("could not run {}", program.to_string_lossy()))?;
        Ok(ProcessOutput {
            code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[derive(Clone, Copy)]
enum BundleKind {
    Systemd,
    Launchd,
}

struct InstallerBundle {
    root: PathBuf,
}

impl InstallerBundle {
    fn create(context: &ServiceContext, kind: BundleKind) -> Result<Self> {
        let temporary_root =
            validate_temporary_root(&context.temporary_root, context.filesystem_uid)?;
        let root =
            create_private_directory(&temporary_root, ".executor-service", context.filesystem_uid)?;
        let bundle = Self { root };
        let files: &[(&str, &[u8], u32)] = match kind {
            BundleKind::Systemd => &[
                ("scripts/install-systemd.sh", SYSTEMD_INSTALLER, 0o700),
                (
                    "scripts/lib/install-systemd-master-key.sh",
                    SYSTEMD_KEY_HELPER,
                    0o600,
                ),
                ("packaging/systemd/executor.service", SYSTEMD_UNIT, 0o600),
                ("packaging/systemd/executor.env.example", SYSTEMD_ENV, 0o600),
            ],
            BundleKind::Launchd => &[
                ("scripts/install-launchd.sh", LAUNCHD_INSTALLER, 0o700),
                (
                    "packaging/launchd/dev.executor.gateway.plist",
                    LAUNCHD_PLIST,
                    0o600,
                ),
                ("packaging/launchd/bounded-log.sh", BOUNDED_LOGGER, 0o700),
            ],
        };
        for (relative_path, contents, mode) in files {
            bundle.write(relative_path, contents, *mode)?;
        }
        Ok(bundle)
    }

    fn write(&self, relative_path: &str, contents: &[u8], mode: u32) -> Result<()> {
        let destination = self.root.join(relative_path);
        let parent = destination
            .parent()
            .context("embedded installer path has no parent")?;
        create_private_tree(&self.root, parent)?;
        write_new_file(&destination, contents, mode)
    }

    fn script(&self, relative_path: &str) -> PathBuf {
        self.root.join(relative_path)
    }

    fn stage_executable(&self, source: &Path) -> Result<PathBuf> {
        let destination = self.root.join("executor");
        copy_to_new_file(source, &destination, 0o700)?;
        Ok(destination)
    }
}

impl Drop for InstallerBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MacLoadState {
    NotLoaded,
    LoadedInactive,
    Active,
}

const SERVICE_MANIFEST_HEADER: &str = "executor-service-install-v1";
const SERVICE_RECOVERY_CONTENTS: &str = "executor-service-install-recovery-v1\n";
const MAX_MANIFEST_BYTES: u64 = 4 * 1024;
const MAX_MANAGED_FILE_BYTES: u64 = 512 * 1024 * 1024;

struct ManagedFileSpec<'a> {
    name: &'static str,
    description: &'static str,
    path: &'a Path,
    mode: u32,
    remove_with_service: bool,
    allow_without_manifest: bool,
}

fn managed_file_specs(context: &ServiceContext) -> Vec<ManagedFileSpec<'_>> {
    match context.platform {
        Platform::Linux => vec![
            ManagedFileSpec {
                name: "binary",
                description: "installed Executor binary",
                path: &context.paths.linux_binary,
                mode: 0o755,
                remove_with_service: true,
                allow_without_manifest: false,
            },
            ManagedFileSpec {
                name: "unit",
                description: "systemd unit",
                path: &context.paths.linux_unit,
                mode: 0o644,
                remove_with_service: true,
                allow_without_manifest: false,
            },
        ],
        Platform::MacOs => vec![
            ManagedFileSpec {
                name: "binary",
                description: "installed Executor binary",
                path: &context.paths.mac_binary,
                mode: 0o755,
                remove_with_service: true,
                allow_without_manifest: false,
            },
            ManagedFileSpec {
                name: "plist",
                description: "LaunchAgent plist",
                path: &context.paths.mac_plist,
                mode: 0o600,
                remove_with_service: true,
                allow_without_manifest: false,
            },
            ManagedFileSpec {
                name: "wrapper",
                description: "LaunchAgent wrapper",
                path: &context.paths.mac_wrapper,
                mode: 0o700,
                remove_with_service: true,
                allow_without_manifest: false,
            },
            ManagedFileSpec {
                name: "logger",
                description: "bounded log helper",
                path: &context.paths.mac_logger,
                mode: 0o700,
                remove_with_service: true,
                allow_without_manifest: false,
            },
            ManagedFileSpec {
                name: "config",
                description: "persisted LaunchAgent configuration",
                path: &context.paths.mac_config,
                mode: 0o600,
                remove_with_service: false,
                allow_without_manifest: true,
            },
        ],
        Platform::Unsupported => Vec::new(),
    }
}

fn service_manifest_path(context: &ServiceContext) -> &Path {
    match context.platform {
        Platform::Linux => &context.paths.linux_manifest,
        Platform::MacOs | Platform::Unsupported => &context.paths.mac_manifest,
    }
}

fn service_recovery_path(context: &ServiceContext) -> &Path {
    match context.platform {
        Platform::Linux => &context.paths.linux_recovery,
        Platform::MacOs | Platform::Unsupported => &context.paths.mac_recovery,
    }
}

fn preflight_service_install(context: &ServiceContext) -> Result<()> {
    if service_recovery_exists(context)? {
        return Ok(());
    }
    let specs = managed_file_specs(context);
    if service_manifest_exists(context)? {
        return verify_service_manifest_entries(context, &specs, false);
    }

    let source_hash = hash_source_file(&context.installation_source)?;
    for spec in &specs {
        if !managed_file_exists(context, spec)? {
            continue;
        }
        if spec.allow_without_manifest {
            continue;
        }
        if spec.name == "binary" && hash_managed_file(context, spec)? == source_hash {
            continue;
        }
        bail!(
            "refusing to replace unmanaged {} at {}; remove it manually or restore the Executor ownership manifest",
            spec.description,
            spec.path.display()
        );
    }
    Ok(())
}

fn preflight_service_removal(context: &ServiceContext) -> Result<Vec<bool>> {
    reject_incomplete_service_install(context)?;
    let specs = managed_file_specs(context);
    let manifest_exists = service_manifest_exists(context)?;
    let existing = specs
        .iter()
        .map(|spec| {
            if manifest_exists || spec.remove_with_service {
                managed_file_exists(context, spec)
            } else {
                Ok(false)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    if manifest_exists {
        verify_service_manifest_entries(context, &specs, true)?;
    } else if specs
        .iter()
        .zip(&existing)
        .any(|(spec, exists)| spec.remove_with_service && *exists)
    {
        bail!(
            "refusing to remove service files without the Executor ownership manifest at {}",
            service_manifest_path(context).display()
        );
    }
    Ok(existing)
}

fn verify_service_manifest(context: &ServiceContext) -> Result<()> {
    reject_incomplete_service_install(context)?;
    if !service_manifest_exists(context)? {
        bail!(
            "the Executor ownership manifest is missing at {}; rerun service install before mutating the service",
            service_manifest_path(context).display()
        );
    }
    verify_service_manifest_entries(context, &managed_file_specs(context), false)
}

fn reject_incomplete_service_install(context: &ServiceContext) -> Result<()> {
    if service_recovery_exists(context)? {
        bail!(
            "a previous service installation did not finish; rerun service install before any other lifecycle command ({})",
            service_recovery_path(context).display()
        );
    }
    Ok(())
}

fn verify_service_manifest_entries(
    context: &ServiceContext,
    specs: &[ManagedFileSpec<'_>],
    allow_missing: bool,
) -> Result<()> {
    let recorded = read_service_manifest(context, specs)?;
    for (spec, expected_hash) in specs.iter().zip(recorded) {
        if !managed_file_exists(context, spec)? {
            if allow_missing && spec.remove_with_service {
                continue;
            }
            bail!(
                "managed {} recorded by the Executor ownership manifest is missing at {}",
                spec.description,
                spec.path.display()
            );
        }
        let actual_hash = hash_managed_file(context, spec)?;
        if actual_hash != expected_hash {
            bail!(
                "refusing to mutate replaced {} at {}; its contents do not match the Executor ownership manifest",
                spec.description,
                spec.path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
fn write_service_manifest(context: &ServiceContext) -> Result<()> {
    let specs = managed_file_specs(context);
    let mut contents = String::from(SERVICE_MANIFEST_HEADER);
    contents.push('\n');
    for spec in &specs {
        contents.push_str(spec.name);
        contents.push(' ');
        contents.push_str(&hash_managed_file(context, spec)?);
        contents.push('\n');
    }

    let manifest = service_manifest_path(context);
    if let Some(parent) = manifest.parent() {
        validate_owned_directory(parent, context.filesystem_uid, "service manifest directory")?;
    }
    validate_manifest_file(context)?;
    let parent = manifest
        .parent()
        .context("service manifest has no parent")?;
    let temporary = parent.join(format!(".service-install-{}.tmp", Uuid::new_v4()));
    let write_result = (|| -> Result<()> {
        write_new_file(&temporary, contents.as_bytes(), 0o600)?;
        fs::rename(&temporary, manifest)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result.with_context(|| {
        format!(
            "could not publish the Executor ownership manifest at {}",
            manifest.display()
        )
    })
}

fn read_service_manifest(
    context: &ServiceContext,
    specs: &[ManagedFileSpec<'_>],
) -> Result<Vec<String>> {
    let path = service_manifest_path(context);
    let mut file = open_no_follow(path)
        .with_context(|| format!("could not open service manifest {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect service manifest {}", path.display()))?;
    validate_control_file_metadata(context, path, &metadata, "service manifest")?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        bail!("service manifest is too large: {}", path.display());
    }
    let mut contents = String::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_string(&mut contents)
        .with_context(|| format!("could not read service manifest {}", path.display()))?;
    if contents.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("service manifest is too large: {}", path.display());
    }
    let mut lines = contents.lines();
    if lines.next() != Some(SERVICE_MANIFEST_HEADER) {
        bail!(
            "service manifest has an unsupported format: {}",
            path.display()
        );
    }
    let mut hashes = Vec::with_capacity(specs.len());
    for spec in specs {
        let line = lines
            .next()
            .with_context(|| format!("service manifest is incomplete: {}", path.display()))?;
        let (name, hash) = line
            .split_once(' ')
            .with_context(|| format!("service manifest is malformed: {}", path.display()))?;
        if name != spec.name
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("service manifest is malformed: {}", path.display());
        }
        hashes.push(hash.to_owned());
    }
    if lines.next().is_some() {
        bail!(
            "service manifest has unexpected entries: {}",
            path.display()
        );
    }
    Ok(hashes)
}

fn service_manifest_exists(context: &ServiceContext) -> Result<bool> {
    validate_manifest_file(context)
}

#[cfg(unix)]
fn recover_service_recovery_publication_alias(context: &ServiceContext) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let path = service_recovery_path(context);
    let destination = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "could not inspect service recovery marker {}",
                    path.display()
                )
            });
        }
    };
    if !destination.is_file() || destination.nlink() != 2 {
        return Ok(());
    }
    let parent = path
        .parent()
        .context("service recovery marker has no parent")?;
    let mut matching_alias = None;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(uuid) = name
            .strip_prefix(".service-recovery-")
            .and_then(|name| name.strip_suffix(".tmp"))
        else {
            continue;
        };
        if Uuid::parse_str(uuid).is_err() {
            continue;
        }
        let alias_path = entry.path();
        let alias = fs::symlink_metadata(&alias_path)?;
        let is_matching = alias.is_file()
            && alias.dev() == destination.dev()
            && alias.ino() == destination.ino()
            && alias.nlink() == 2
            && alias.uid() == context.filesystem_uid
            && alias.uid() == destination.uid()
            && alias.gid() == destination.gid()
            && alias.mode() == destination.mode()
            && alias.mode() & 0o7777 == 0o600
            && alias.len() == SERVICE_RECOVERY_CONTENTS.len() as u64
            && alias.len() == destination.len();
        if !is_matching {
            continue;
        }
        if matching_alias.replace(alias_path).is_some() {
            return Ok(());
        }
    }

    if let Some(alias) = matching_alias {
        let contents = fs::read(path)?;
        if contents == SERVICE_RECOVERY_CONTENTS.as_bytes() {
            fs::remove_file(alias)?;
            sync_service_directory(context, parent, "service recovery directory")?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn recover_service_recovery_publication_alias(_context: &ServiceContext) -> Result<()> {
    Ok(())
}

fn service_recovery_exists(context: &ServiceContext) -> Result<bool> {
    recover_service_recovery_publication_alias(context)?;
    let path = service_recovery_path(context);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "could not inspect service recovery marker {}",
                    path.display()
                )
            });
        }
    };
    validate_control_file_metadata(context, path, &metadata, "service recovery marker")?;
    if metadata.len() != SERVICE_RECOVERY_CONTENTS.len() as u64 {
        bail!("service recovery marker is malformed: {}", path.display());
    }
    let mut file = open_no_follow(path)
        .with_context(|| format!("could not open service recovery marker {}", path.display()))?;
    let mut contents = String::new();
    std::io::Read::by_ref(&mut file)
        .take((SERVICE_RECOVERY_CONTENTS.len() + 1) as u64)
        .read_to_string(&mut contents)
        .with_context(|| format!("could not read service recovery marker {}", path.display()))?;
    if contents != SERVICE_RECOVERY_CONTENTS {
        bail!("service recovery marker is malformed: {}", path.display());
    }
    let parent = path
        .parent()
        .context("service recovery marker has no parent")?;
    sync_service_directory(context, parent, "service recovery directory")?;
    Ok(true)
}

fn ensure_service_recovery_marker(context: &ServiceContext) -> Result<()> {
    if service_recovery_exists(context)? {
        return Ok(());
    }
    let path = service_recovery_path(context);
    let parent = path
        .parent()
        .context("service recovery marker has no parent")?;
    validate_owned_directory(parent, context.filesystem_uid, "service recovery directory")?;
    let temporary = parent.join(format!(".service-recovery-{}.tmp", Uuid::new_v4()));
    let publish_result = (|| -> Result<()> {
        write_new_file(&temporary, SERVICE_RECOVERY_CONTENTS.as_bytes(), 0o600)?;
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        sync_service_directory(context, parent, "service recovery directory")?;
        Ok(())
    })();
    if publish_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    publish_result.with_context(|| {
        format!(
            "could not publish service installation recovery marker {}",
            path.display()
        )
    })
}

fn validate_manifest_file(context: &ServiceContext) -> Result<bool> {
    let path = service_manifest_path(context);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_control_file_metadata(context, path, &metadata, "service manifest")?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("could not inspect service manifest {}", path.display())),
    }
}

fn validate_control_file_metadata(
    context: &ServiceContext,
    path: &Path,
    metadata: &fs::Metadata,
    description: &str,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{description} must be a regular file: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != context.filesystem_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            bail!(
                "{description} must be owned by the service installer with mode 0600 and one hard link: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn managed_file_exists(context: &ServiceContext, spec: &ManagedFileSpec<'_>) -> Result<bool> {
    match fs::symlink_metadata(spec.path) {
        Ok(metadata) => {
            validate_managed_file_metadata(context, spec, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "could not inspect {}: {}",
                spec.description,
                spec.path.display()
            )
        }),
    }
}

fn validate_managed_file_metadata(
    context: &ServiceContext,
    spec: &ManagedFileSpec<'_>,
    metadata: &fs::Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "{} must be a regular file: {}",
            spec.description,
            spec.path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != context.filesystem_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != spec.mode
        {
            bail!(
                "{} has unexpected ownership, links, or mode: {}",
                spec.description,
                spec.path.display()
            );
        }
    }
    if metadata.len() > MAX_MANAGED_FILE_BYTES {
        bail!(
            "{} is unexpectedly large: {}",
            spec.description,
            spec.path.display()
        );
    }
    Ok(())
}

fn hash_managed_file(context: &ServiceContext, spec: &ManagedFileSpec<'_>) -> Result<String> {
    let mut file = open_no_follow(spec.path).with_context(|| {
        format!(
            "could not open {}: {}",
            spec.description,
            spec.path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "could not inspect {}: {}",
            spec.description,
            spec.path.display()
        )
    })?;
    validate_managed_file_metadata(context, spec, &metadata)?;
    hash_reader(&mut file, spec.description)
}

fn hash_source_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("could not open running Executor binary {}", path.display()))?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "could not inspect running Executor binary {}",
            path.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_MANAGED_FILE_BYTES {
        bail!(
            "running Executor binary is not a bounded regular file: {}",
            path.display()
        );
    }
    hash_reader(&mut file, "running Executor binary")
}

fn hash_reader(reader: &mut File, description: &str) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("could not read {description}"))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_MANAGED_FILE_BYTES {
            bail!("{description} is unexpectedly large");
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn open_no_follow(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn sync_service_directory(context: &ServiceContext, path: &Path, description: &str) -> Result<()> {
    #[cfg(not(test))]
    let _ = context;
    #[cfg(test)]
    {
        context
            .directory_sync_test
            .events
            .borrow_mut()
            .push(path.to_path_buf());
        if context.directory_sync_test.failure.borrow().as_deref() == Some(path) {
            bail!("injected directory sync failure for {}", path.display());
        }
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("could not sync {description} {}", path.display()))
}

fn sync_removed_managed_file_parents(context: &ServiceContext) -> Result<()> {
    let mut synced = Vec::new();
    for spec in managed_file_specs(context)
        .into_iter()
        .filter(|spec| spec.remove_with_service)
    {
        let parent = spec
            .path
            .parent()
            .with_context(|| format!("managed path has no parent: {}", spec.path.display()))?;
        if synced
            .iter()
            .any(|synced_path: &PathBuf| synced_path == parent)
        {
            continue;
        }
        sync_service_directory(context, parent, "managed service directory")?;
        synced.push(parent.to_path_buf());
    }
    Ok(())
}

fn remove_service_manifest(context: &ServiceContext) -> Result<()> {
    let manifest = service_manifest_path(context);
    let parent = manifest
        .parent()
        .context("service manifest has no parent")?;
    if validate_manifest_file(context)? {
        fs::remove_file(manifest)
            .with_context(|| format!("could not remove service manifest {}", manifest.display()))?;
    }
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            sync_service_directory(context, parent, "service manifest directory")?;
        }
        Ok(_) => bail!(
            "service manifest parent must be a non-symlinked directory: {}",
            parent.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "could not inspect service manifest parent {}",
                    parent.display()
                )
            });
        }
    }
    Ok(())
}

pub fn execute(arguments: ServiceArgs) -> Result<ServiceOutcome> {
    let context = ServiceContext::system()?;
    execute_with(&context, &mut SystemCommandRunner, arguments.command)
}

struct ServiceOperationLock {
    _file: File,
}

fn acquire_service_operation_lock(context: &ServiceContext) -> Result<ServiceOperationLock> {
    let (path, parent): (&Path, &Path) = match context.platform {
        Platform::Linux => {
            let path = &context.paths.linux_lock;
            let parent = path.parent().context("Linux service lock has no parent")?;
            let trusted_parent = parent
                .parent()
                .context("Linux service lock directory has no trusted parent")?;
            validate_owned_directory(
                trusted_parent,
                context.filesystem_uid,
                "Linux service lock parent",
            )?;
            ensure_owned_directory(
                parent,
                context.filesystem_uid,
                0o700,
                "Linux service lock directory",
                false,
            )?;
            (path.as_path(), parent)
        }
        Platform::MacOs => {
            validate_owned_directory(
                &context.home,
                context.filesystem_uid,
                "service lock home directory",
            )?;
            ensure_owned_directory(
                &context.paths.mac_executor_root,
                context.filesystem_uid,
                0o700,
                "Executor root directory",
                false,
            )?;
            ensure_owned_directory(
                &context.paths.mac_install_root,
                context.filesystem_uid,
                0o700,
                "Executor service directory",
                false,
            )?;
            (
                context.paths.mac_lock.as_path(),
                context.paths.mac_install_root.as_path(),
            )
        }
        Platform::Unsupported => bail!("unsupported service lock platform"),
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let mut create = OpenOptions::new();
        create
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = match create.open(path) {
            Ok(file) => {
                file.sync_all().with_context(|| {
                    format!(
                        "could not sync new service operation lock {}",
                        path.display()
                    )
                })?;
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .with_context(|| {
                        format!(
                            "could not sync service operation lock directory {}",
                            parent.display()
                        )
                    })?;
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut existing = OpenOptions::new();
                existing
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                existing.open(path).with_context(|| {
                    format!("could not open service operation lock {}", path.display())
                })?
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("could not create service operation lock {}", path.display())
                });
            }
        };
        let metadata = file.metadata().with_context(|| {
            format!(
                "could not inspect service operation lock {}",
                path.display()
            )
        })?;
        if !metadata.is_file()
            || metadata.uid() != context.filesystem_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            bail!(
                "service operation lock must be an installer-owned 0600 regular file with one link: {}",
                path.display()
            );
        }
        file.sync_all()
            .with_context(|| format!("could not sync service operation lock {}", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| {
                format!(
                    "could not sync service operation lock directory {}",
                    parent.display()
                )
            })?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.kind(), std::io::ErrorKind::WouldBlock) {
                bail!("another Executor service operation is already active");
            }
            return Err(error).context("could not acquire the Executor service operation lock");
        }
        Ok(ServiceOperationLock { _file: file })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, parent);
        bail!("service operation locking requires a Unix platform")
    }
}

fn execute_with(
    context: &ServiceContext,
    runner: &mut impl CommandRunner,
    command: ServiceCommand,
) -> Result<ServiceOutcome> {
    match context.platform {
        Platform::Linux => execute_linux(context, runner, command),
        Platform::MacOs => execute_macos(context, runner, command),
        Platform::Unsupported => {
            bail!("service management is supported only on Linux and macOS")
        }
    }
}

fn execute_linux(
    context: &ServiceContext,
    runner: &mut impl CommandRunner,
    command: ServiceCommand,
) -> Result<ServiceOutcome> {
    let _operation_lock = if matches!(&command, ServiceCommand::Status) {
        None
    } else {
        require_linux_root(context)?;
        Some(acquire_service_operation_lock(context)?)
    };
    match command {
        ServiceCommand::Install(arguments) => {
            require_linux_root(context)?;
            preflight_service_install(context)?;
            let bundle = InstallerBundle::create(context, BundleKind::Systemd)?;
            let staged_binary = bundle.stage_executable(&context.installation_source)?;
            let mut command_arguments = vec![
                bundle.script("scripts/install-systemd.sh").into_os_string(),
                OsString::from("--binary"),
                staged_binary.into_os_string(),
            ];
            if arguments.no_start {
                command_arguments.push(OsString::from("--no-start"));
            }
            let output = run_checked(
                runner,
                OsStr::new("/bin/bash"),
                &command_arguments,
                "systemd installation",
            )?;
            verify_service_manifest(context)?;
            Ok(ServiceOutcome::from_process(
                output,
                b"Executor system service installed.\n",
            ))
        }
        ServiceCommand::Status => linux_status(runner),
        ServiceCommand::Start => {
            require_linux_root(context)?;
            require_regular_file(&context.paths.linux_unit, "systemd unit")?;
            require_regular_file(&context.paths.linux_binary, "installed Executor binary")?;
            verify_service_manifest(context)?;
            let output = run_checked(
                runner,
                OsStr::new("systemctl"),
                &os_args(&["start", SYSTEMD_SERVICE]),
                "starting executor.service",
            )?;
            Ok(ServiceOutcome::from_process(
                output,
                b"Executor service started.\n",
            ))
        }
        ServiceCommand::Stop => {
            require_linux_root(context)?;
            if linux_is_active(runner)? {
                verify_service_manifest(context)?;
                let output = run_checked(
                    runner,
                    OsStr::new("systemctl"),
                    &os_args(&["stop", SYSTEMD_SERVICE]),
                    "stopping executor.service",
                )?;
                Ok(ServiceOutcome::from_process(
                    output,
                    b"Executor service stopped.\n",
                ))
            } else {
                Ok(ServiceOutcome::success(
                    b"Executor service is already stopped.\n".to_vec(),
                ))
            }
        }
        ServiceCommand::Restart => {
            require_linux_root(context)?;
            require_regular_file(&context.paths.linux_unit, "systemd unit")?;
            require_regular_file(&context.paths.linux_binary, "installed Executor binary")?;
            verify_service_manifest(context)?;
            let output = run_checked(
                runner,
                OsStr::new("systemctl"),
                &os_args(&["restart", SYSTEMD_SERVICE]),
                "restarting executor.service",
            )?;
            Ok(ServiceOutcome::from_process(
                output,
                b"Executor service restarted.\n",
            ))
        }
        ServiceCommand::Remove => {
            require_linux_root(context)?;
            let manifest_exists = service_manifest_exists(context)?;
            let managed = preflight_service_removal(context)?;
            let unit_exists = managed[1];
            let binary_exists = managed[0];
            let active = linux_is_active(runner)?;
            if active && !manifest_exists {
                bail!("executor.service is active but has no Executor ownership manifest");
            }
            if unit_exists || active {
                run_checked(
                    runner,
                    OsStr::new("systemctl"),
                    &os_args(&["disable", "--now", SYSTEMD_SERVICE]),
                    "disabling executor.service",
                )?;
            }
            if binary_exists {
                fs::remove_file(&context.paths.linux_binary)
                    .context("could not remove the installed Executor binary")?;
            }
            if unit_exists {
                fs::remove_file(&context.paths.linux_unit)
                    .context("could not remove the systemd unit")?;
            }
            if manifest_exists {
                sync_removed_managed_file_parents(context)?;
            }
            if unit_exists || manifest_exists {
                run_checked(
                    runner,
                    OsStr::new("systemctl"),
                    &os_args(&["daemon-reload"]),
                    "reloading systemd",
                )?;
            }
            remove_service_manifest(context)?;
            Ok(ServiceOutcome::success(
                b"Executor service removed. Data and configuration were preserved.\n".to_vec(),
            ))
        }
    }
}

fn execute_macos(
    context: &ServiceContext,
    runner: &mut impl CommandRunner,
    command: ServiceCommand,
) -> Result<ServiceOutcome> {
    require_macos_user(context)?;
    let _operation_lock = if matches!(&command, ServiceCommand::Status) {
        None
    } else {
        Some(acquire_service_operation_lock(context)?)
    };
    match command {
        ServiceCommand::Install(arguments) => {
            preflight_service_install(context)?;
            let bundle = InstallerBundle::create(context, BundleKind::Launchd)?;
            let staged_binary = bundle.stage_executable(&context.current_exe)?;
            run_checked(
                runner,
                OsStr::new("/bin/bash"),
                &[
                    bundle.script("scripts/install-launchd.sh").into_os_string(),
                    OsString::from("--binary"),
                    staged_binary.into_os_string(),
                    OsString::from("--validate-only"),
                ],
                "validating the LaunchAgent installation",
            )?;
            if mac_load_state(context, runner)? != MacLoadState::NotLoaded {
                run_checked(
                    runner,
                    OsStr::new("launchctl"),
                    &[OsString::from("bootout"), mac_service_target(context)],
                    "stopping the existing LaunchAgent",
                )?;
            }
            prepare_macos_directories(context)?;
            ensure_service_recovery_marker(context)?;
            atomic_copy_executable(&context.current_exe, &context.paths.mac_binary)?;
            let mut command_arguments = vec![
                bundle.script("scripts/install-launchd.sh").into_os_string(),
                OsString::from("--binary"),
                context.paths.mac_binary.clone().into_os_string(),
            ];
            if arguments.no_start {
                command_arguments.push(OsString::from("--no-start"));
            }
            let output = run_checked(
                runner,
                OsStr::new("/bin/bash"),
                &command_arguments,
                "LaunchAgent installation",
            )?;
            verify_service_manifest(context)?;
            Ok(ServiceOutcome::from_process(
                output,
                b"Executor LaunchAgent installed.\n",
            ))
        }
        ServiceCommand::Status => match mac_load_state(context, runner)? {
            MacLoadState::Active => Ok(ServiceOutcome::success(b"active\n".to_vec())),
            MacLoadState::LoadedInactive | MacLoadState::NotLoaded => {
                Ok(ServiceOutcome::inactive())
            }
        },
        ServiceCommand::Start => {
            require_macos_runtime_files(context)?;
            verify_service_manifest(context)?;
            match mac_load_state(context, runner)? {
                MacLoadState::Active => Ok(ServiceOutcome::success(
                    b"Executor service is already active.\n".to_vec(),
                )),
                MacLoadState::LoadedInactive => {
                    let output = run_checked(
                        runner,
                        OsStr::new("launchctl"),
                        &[OsString::from("kickstart"), mac_service_target(context)],
                        "starting the Executor LaunchAgent",
                    )?;
                    Ok(ServiceOutcome::from_process(
                        output,
                        b"Executor service started.\n",
                    ))
                }
                MacLoadState::NotLoaded => {
                    launchctl_enable(context, runner)?;
                    let output = launchctl_bootstrap(context, runner)?;
                    Ok(ServiceOutcome::from_process(
                        output,
                        b"Executor service started.\n",
                    ))
                }
            }
        }
        ServiceCommand::Stop => {
            if mac_load_state(context, runner)? == MacLoadState::NotLoaded {
                return Ok(ServiceOutcome::success(
                    b"Executor service is already stopped.\n".to_vec(),
                ));
            }
            verify_service_manifest(context)?;
            let output = run_checked(
                runner,
                OsStr::new("launchctl"),
                &[OsString::from("bootout"), mac_service_target(context)],
                "stopping the Executor LaunchAgent",
            )?;
            Ok(ServiceOutcome::from_process(
                output,
                b"Executor service stopped.\n",
            ))
        }
        ServiceCommand::Restart => {
            require_macos_runtime_files(context)?;
            verify_service_manifest(context)?;
            if mac_load_state(context, runner)? != MacLoadState::NotLoaded {
                run_checked(
                    runner,
                    OsStr::new("launchctl"),
                    &[OsString::from("bootout"), mac_service_target(context)],
                    "stopping the Executor LaunchAgent",
                )?;
            }
            launchctl_enable(context, runner)?;
            let output = launchctl_bootstrap(context, runner)?;
            Ok(ServiceOutcome::from_process(
                output,
                b"Executor service restarted.\n",
            ))
        }
        ServiceCommand::Remove => {
            let manifest_exists = service_manifest_exists(context)?;
            let existing = preflight_service_removal(context)?;
            let load_state = mac_load_state(context, runner)?;
            if load_state != MacLoadState::NotLoaded && !manifest_exists {
                bail!("the Executor LaunchAgent is loaded but has no ownership manifest");
            }
            if load_state != MacLoadState::NotLoaded {
                run_checked(
                    runner,
                    OsStr::new("launchctl"),
                    &[OsString::from("bootout"), mac_service_target(context)],
                    "stopping the Executor LaunchAgent",
                )?;
            }
            for (spec, exists) in managed_file_specs(context).iter().zip(existing) {
                if exists && spec.remove_with_service {
                    fs::remove_file(spec.path).with_context(|| {
                        format!("could not remove managed file {}", spec.path.display())
                    })?;
                }
            }
            if manifest_exists {
                sync_removed_managed_file_parents(context)?;
            }
            remove_service_manifest(context)?;
            Ok(ServiceOutcome::success(
                b"Executor service removed. Data and logs were preserved.\n".to_vec(),
            ))
        }
    }
}

fn linux_status(runner: &mut impl CommandRunner) -> Result<ServiceOutcome> {
    if linux_is_active(runner)? {
        Ok(ServiceOutcome::success(b"active\n".to_vec()))
    } else {
        Ok(ServiceOutcome::inactive())
    }
}

fn linux_is_active(runner: &mut impl CommandRunner) -> Result<bool> {
    let output = runner.run(
        OsStr::new("systemctl"),
        &os_args(&["is-active", SYSTEMD_SERVICE]),
    )?;
    if output.success() {
        return Ok(true);
    }
    let state = String::from_utf8_lossy(&output.stdout);
    if matches!(
        state.trim(),
        "inactive" | "failed" | "unknown" | "deactivating"
    ) || matches!(output.code, Some(3 | 4))
    {
        return Ok(false);
    }
    command_failure(output, "querying executor.service status")
}

fn mac_load_state(
    context: &ServiceContext,
    runner: &mut impl CommandRunner,
) -> Result<MacLoadState> {
    let output = runner.run(
        OsStr::new("launchctl"),
        &[OsString::from("print"), mac_service_target(context)],
    )?;
    if output.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        if text.lines().any(|line| line.trim() == "state = running") {
            return Ok(MacLoadState::Active);
        }
        return Ok(MacLoadState::LoadedInactive);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if output.code == Some(113)
        || stderr.contains("could not find service")
        || stderr.contains("not found")
    {
        return Ok(MacLoadState::NotLoaded);
    }
    command_failure(output, "querying the Executor LaunchAgent")
}

fn launchctl_enable(
    context: &ServiceContext,
    runner: &mut impl CommandRunner,
) -> Result<ProcessOutput> {
    run_checked(
        runner,
        OsStr::new("launchctl"),
        &[OsString::from("enable"), mac_service_target(context)],
        "enabling the Executor LaunchAgent",
    )
}

fn launchctl_bootstrap(
    context: &ServiceContext,
    runner: &mut impl CommandRunner,
) -> Result<ProcessOutput> {
    run_checked(
        runner,
        OsStr::new("launchctl"),
        &[
            OsString::from("bootstrap"),
            mac_domain(context),
            context.paths.mac_plist.clone().into_os_string(),
        ],
        "loading the Executor LaunchAgent",
    )
}

fn require_linux_root(context: &ServiceContext) -> Result<()> {
    if context.effective_uid != 0 {
        bail!("this command manages a system service; rerun it with sudo")
    }
    Ok(())
}

fn require_macos_user(context: &ServiceContext) -> Result<()> {
    if context.effective_uid == 0 {
        bail!(
            "the macOS LaunchAgent belongs to the logged-in user; do not run this command with sudo"
        )
    }
    Ok(())
}

fn prepare_macos_directories(context: &ServiceContext) -> Result<()> {
    validate_owned_directory(&context.home, context.filesystem_uid, "home directory")?;
    ensure_owned_directory(
        &context.paths.mac_executor_root,
        context.filesystem_uid,
        0o700,
        "Executor root directory",
        true,
    )?;
    ensure_owned_directory(
        &context.paths.mac_install_root,
        context.filesystem_uid,
        0o700,
        "Executor install directory",
        true,
    )?;
    ensure_owned_directory(
        &context.paths.mac_binary_dir,
        context.filesystem_uid,
        0o700,
        "Executor binary directory",
        true,
    )?;
    ensure_owned_directory(
        &context.paths.mac_library,
        context.filesystem_uid,
        0o700,
        "Library directory",
        false,
    )?;
    ensure_owned_directory(
        &context.paths.mac_launch_agents,
        context.filesystem_uid,
        0o700,
        "LaunchAgents directory",
        false,
    )
}

fn require_macos_runtime_files(context: &ServiceContext) -> Result<()> {
    require_regular_file(&context.paths.mac_plist, "LaunchAgent plist")?;
    require_regular_file(&context.paths.mac_wrapper, "LaunchAgent wrapper")?;
    require_regular_file(&context.paths.mac_logger, "bounded log helper")?;
    require_regular_file(&context.paths.mac_binary, "installed Executor binary")
}

fn mac_domain(context: &ServiceContext) -> OsString {
    OsString::from(format!("gui/{}", context.effective_uid))
}

fn mac_service_target(context: &ServiceContext) -> OsString {
    OsString::from(format!("gui/{}/{}", context.effective_uid, LAUNCHD_LABEL))
}

fn run_checked(
    runner: &mut impl CommandRunner,
    program: &OsStr,
    arguments: &[OsString],
    action: &str,
) -> Result<ProcessOutput> {
    let output = runner.run(program, arguments)?;
    if output.success() {
        Ok(output)
    } else {
        command_failure(output, action)
    }
}

fn command_failure<T>(output: ProcessOutput, action: &str) -> Result<T> {
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    if detail.is_empty() {
        bail!("{action} failed with exit status {:?}", output.code)
    }
    bail!("{action} failed: {detail}")
}

fn os_args(arguments: &[&str]) -> Vec<OsString> {
    arguments.iter().map(OsString::from).collect()
}

fn validate_optional_regular_file(path: &Path, description: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "refusing symbolic link at {description}: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => bail!("{description} is not a regular file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("could not inspect {description}: {}", path.display())),
    }
}

fn require_regular_file(path: &Path, description: &str) -> Result<()> {
    if !validate_optional_regular_file(path, description)? {
        bail!("{description} is not installed at {}", path.display());
    }
    Ok(())
}

fn validate_temporary_root(path: &Path, expected_uid: u32) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("could not inspect temporary directory {}", path.display()))?;
    let mut current = PathBuf::new();
    for component in canonical.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).with_context(|| {
            format!(
                "could not inspect temporary directory ancestor {}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "temporary path ancestor is not a canonical directory: {}",
                current.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !temporary_directory_metadata_is_safe(metadata.uid(), expected_uid, metadata.mode())
            {
                bail!(
                    "temporary directory ancestor has unsafe ownership or permissions: {}",
                    current.display()
                );
            }
        }
    }
    Ok(canonical)
}

#[cfg(unix)]
fn temporary_directory_metadata_is_safe(owner: u32, expected_uid: u32, mode: u32) -> bool {
    if owner != 0 && owner != expected_uid {
        return false;
    }
    if mode & 0o022 == 0 {
        return true;
    }
    owner == 0 && mode & 0o1000 != 0
}

fn create_private_directory(parent: &Path, prefix: &str, expected_uid: u32) -> Result<PathBuf> {
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    for _ in 0..16 {
        let path = parent.join(format!("{prefix}-{}", Uuid::new_v4()));
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => {
                let validation = (|| -> Result<()> {
                    set_mode(&path, 0o700)?;
                    let metadata = fs::symlink_metadata(&path).with_context(|| {
                        format!("could not inspect private directory {}", path.display())
                    })?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        bail!(
                            "private installer path is not a directory: {}",
                            path.display()
                        );
                    }
                    #[cfg(unix)]
                    if metadata.uid() != expected_uid || metadata.mode() & 0o777 != 0o700 {
                        bail!(
                            "private installer directory has unsafe ownership or permissions: {}",
                            path.display()
                        );
                    }
                    Ok(())
                })();
                if let Err(error) = validation {
                    let _ = fs::remove_dir(&path);
                    return Err(error);
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("could not create private directory {}", path.display())
                });
            }
        }
    }
    bail!("could not allocate a unique private installer directory")
}

fn create_private_tree(root: &Path, destination: &Path) -> Result<()> {
    let relative = destination
        .strip_prefix(root)
        .context("embedded installer path escaped its private directory")?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => set_mode(&current, 0o700)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!(
                        "installer bundle path is not a directory: {}",
                        current.display()
                    );
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "could not create installer bundle path {}",
                        current.display()
                    )
                });
            }
        }
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut file = options
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    set_mode(path, mode)
}

fn validate_owned_directory(path: &Path, expected_uid: u32, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {description}: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "{description} must be a non-symlinked directory: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != expected_uid {
            bail!(
                "{description} is not owned by the current user: {}",
                path.display()
            );
        }
        if metadata.mode() & 0o022 != 0 {
            bail!(
                "{description} must not be group-writable or world-writable: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn ensure_owned_directory(
    path: &Path,
    expected_uid: u32,
    mode: u32,
    description: &str,
    harden_existing: bool,
) -> Result<()> {
    let created = match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_owned_directory(path, expected_uid, description)?;
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(mode);
            builder
                .create(path)
                .with_context(|| format!("could not create {description}: {}", path.display()))?;
            true
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("could not inspect {description}: {}", path.display()));
        }
    };
    if created || harden_existing {
        set_mode(path, mode)
    } else {
        Ok(())
    }
}

fn atomic_copy_executable(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::metadata(source)
        .with_context(|| format!("could not inspect running binary {}", source.display()))?;
    if !metadata.is_file() {
        bail!(
            "running Executor path is not a regular file: {}",
            source.display()
        );
    }
    validate_optional_regular_file(destination, "installed Executor binary")?;
    let parent = destination
        .parent()
        .context("installed Executor path has no parent")?;
    let temporary = parent.join(format!(".executor-{}", Uuid::new_v4()));
    let copy_result = (|| -> Result<()> {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o700);
        let mut target = options.open(&temporary)?;
        let mut source = File::open(source)?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            target.write_all(&buffer[..read])?;
        }
        target.sync_all()?;
        set_mode(&temporary, 0o755)?;
        fs::rename(&temporary, destination)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if copy_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    copy_result.with_context(|| {
        format!(
            "could not install Executor binary at {}",
            destination.display()
        )
    })
}

fn copy_to_new_file(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut target = options
        .open(destination)
        .with_context(|| format!("could not create {}", destination.display()))?;
    let mut source = File::open(source)
        .with_context(|| format!("could not open running binary {}", source.display()))?;
    std::io::copy(&mut source, &mut target)?;
    target.sync_all()?;
    set_mode(destination, mode)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    bail!("service management is supported only on Linux and macOS")
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    use super::*;

    #[derive(Debug)]
    struct Invocation {
        program: OsString,
        arguments: Vec<OsString>,
    }

    #[derive(Default)]
    struct FakeRunner {
        responses: VecDeque<FakeResponse>,
        invocations: Vec<Invocation>,
    }

    struct FakeResponse {
        output: ProcessOutput,
        action: Option<Box<dyn FnOnce()>>,
    }

    impl FakeRunner {
        fn respond(&mut self, code: i32, stdout: &str, stderr: &str) {
            self.responses.push_back(FakeResponse {
                output: ProcessOutput {
                    code: Some(code),
                    stdout: stdout.as_bytes().to_vec(),
                    stderr: stderr.as_bytes().to_vec(),
                },
                action: None,
            });
        }

        fn respond_with(
            &mut self,
            code: i32,
            stdout: &str,
            stderr: &str,
            action: impl FnOnce() + 'static,
        ) {
            self.responses.push_back(FakeResponse {
                output: ProcessOutput {
                    code: Some(code),
                    stdout: stdout.as_bytes().to_vec(),
                    stderr: stderr.as_bytes().to_vec(),
                },
                action: Some(Box::new(action)),
            });
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&mut self, program: &OsStr, arguments: &[OsString]) -> Result<ProcessOutput> {
            self.invocations.push(Invocation {
                program: program.to_os_string(),
                arguments: arguments.to_vec(),
            });
            let response = self
                .responses
                .pop_front()
                .context("fake command response was not configured")?;
            if let Some(action) = response.action {
                action();
            }
            Ok(response.output)
        }
    }

    struct TestContext {
        _directory: tempfile::TempDir,
        context: ServiceContext,
    }

    impl TestContext {
        fn new(platform: Platform, effective_uid: u32) -> Self {
            let directory = tempfile::tempdir().expect("temporary directory");
            let home = directory.path().join("home");
            let temporary_root = directory.path().join("tmp");
            let linux_lock_root = directory.path().join("etc");
            fs::create_dir(&home).expect("home directory");
            fs::create_dir(&temporary_root).expect("temporary root");
            fs::create_dir(&linux_lock_root).expect("Linux lock root");
            set_mode(&home, 0o700).expect("home mode");
            set_mode(&temporary_root, 0o700).expect("temporary mode");
            set_mode(&linux_lock_root, 0o700).expect("Linux lock root mode");
            let current_exe = directory.path().join("executor-source");
            fs::write(&current_exe, b"test executor binary").expect("source binary");
            set_mode(&current_exe, 0o755).expect("source mode");
            let filesystem_uid = fs::metadata(&home).expect("home metadata").uid();
            let mut paths = ServicePaths::for_home(&home);
            paths.linux_binary = directory.path().join("usr/local/bin/executor");
            paths.linux_unit = directory.path().join("etc/systemd/system/executor.service");
            paths.linux_manifest = directory
                .path()
                .join("etc/executor/service-install.manifest");
            paths.linux_recovery = directory
                .path()
                .join("etc/executor/service-install.recovery");
            paths.linux_lock = directory.path().join("etc/executor/service-operation.lock");
            Self {
                context: ServiceContext {
                    platform,
                    effective_uid,
                    filesystem_uid,
                    installation_source: current_exe.clone(),
                    current_exe,
                    paths,
                    home,
                    temporary_root,
                    directory_sync_test: DirectorySyncTestState::default(),
                },
                _directory: directory,
            }
        }
    }

    fn write_managed_fixtures(context: &ServiceContext) {
        for spec in managed_file_specs(context) {
            fs::create_dir_all(spec.path.parent().expect("managed parent"))
                .expect("managed parent");
            fs::write(spec.path, format!("{} fixture", spec.name)).expect("managed fixture");
            set_mode(spec.path, spec.mode).expect("managed fixture mode");
        }
        fs::create_dir_all(
            service_manifest_path(context)
                .parent()
                .expect("manifest parent"),
        )
        .expect("manifest parent");
        write_service_manifest(context).expect("ownership manifest");
    }

    fn queue_successful_macos_install(runner: &mut FakeRunner, context: &ServiceContext) {
        queue_successful_macos_install_with_config(runner, context, b"config");
    }

    fn queue_successful_macos_install_with_config(
        runner: &mut FakeRunner,
        context: &ServiceContext,
        config_contents: &[u8],
    ) {
        runner.respond(0, "LaunchAgent paths and configuration are valid.\n", "");
        runner.respond(113, "", "Could not find service");
        let paths = context.paths.clone();
        let installed_context = context.clone();
        let config_contents = config_contents.to_vec();
        runner.respond_with(0, "installed\n", "", move || {
            for (path, contents, mode) in [
                (&paths.mac_plist, b"plist".as_slice(), 0o600),
                (&paths.mac_wrapper, b"wrapper".as_slice(), 0o700),
                (&paths.mac_logger, b"logger".as_slice(), 0o700),
            ] {
                fs::write(path, contents).expect("installed managed file");
                set_mode(path, mode).expect("managed file mode");
            }
            fs::write(&paths.mac_config, config_contents).expect("installed service config");
            set_mode(&paths.mac_config, 0o600).expect("service config mode");
            write_service_manifest(&installed_context).expect("installed manifest");
            fs::remove_file(&installed_context.paths.mac_recovery).expect("clear recovery marker");
        });
    }

    fn encode_service_config_value(value: &Path) -> String {
        value
            .to_string_lossy()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn write_archive_fixture(context: &ServiceContext, contents: &[u8]) -> (PathBuf, PathBuf) {
        let archive_directory = context.home.join(".executor/bin");
        let archive_binary = archive_directory.join("executor");
        let archive_manifest = archive_directory.join(".executor-install-manifest");
        fs::create_dir_all(&archive_directory).expect("archive directory");
        fs::write(&archive_binary, contents).expect("archive binary");
        set_mode(&archive_binary, 0o755).expect("archive binary mode");
        let binary_hash = hash_source_file(&archive_binary).expect("archive binary hash");
        fs::write(
            &archive_manifest,
            format!("executor-install-manifest-v1\n{binary_hash} executor\n"),
        )
        .expect("archive manifest");
        set_mode(&archive_manifest, 0o600).expect("archive manifest mode");
        (archive_binary, archive_manifest)
    }

    #[test]
    fn temporary_directory_metadata_requires_trusted_ownership_and_permissions() {
        let expected_uid = 501;
        assert!(temporary_directory_metadata_is_safe(
            0,
            expected_uid,
            0o40755
        ));
        assert!(temporary_directory_metadata_is_safe(
            expected_uid,
            expected_uid,
            0o40700
        ));
        assert!(temporary_directory_metadata_is_safe(
            0,
            expected_uid,
            0o41777
        ));
        assert!(!temporary_directory_metadata_is_safe(
            502,
            expected_uid,
            0o41777
        ));
        assert!(!temporary_directory_metadata_is_safe(
            expected_uid,
            expected_uid,
            0o41777
        ));
        assert!(!temporary_directory_metadata_is_safe(
            0,
            expected_uid,
            0o40777
        ));
    }

    #[test]
    fn unsafe_temporary_ancestor_is_rejected_before_bundle_files_are_written() {
        let mut test = TestContext::new(Platform::MacOs, 501);
        set_mode(&test.context.temporary_root, 0o1777).expect("sticky temporary root");
        test.context.filesystem_uid = if test.context.filesystem_uid == u32::MAX {
            test.context.filesystem_uid - 1
        } else {
            test.context.filesystem_uid + 1
        };

        let error = match InstallerBundle::create(&test.context, BundleKind::Launchd) {
            Ok(_) => panic!("attacker-owned sticky directory must fail closed"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("unsafe ownership or permissions")
        );
        assert!(
            fs::read_dir(&test.context.temporary_root)
                .expect("temporary root")
                .next()
                .is_none()
        );
    }

    #[test]
    fn temporary_root_is_canonicalized_before_bundle_creation() {
        let mut test = TestContext::new(Platform::MacOs, 501);
        let canonical_root = test.context.temporary_root.clone();
        let alias = test._directory.path().join("temporary-root-alias");
        std::os::unix::fs::symlink(&canonical_root, &alias).expect("temporary root alias");
        test.context.temporary_root = alias;

        let bundle = InstallerBundle::create(&test.context, BundleKind::Launchd)
            .expect("canonical temporary root");

        assert!(bundle.root.starts_with(&canonical_root));
        assert_eq!(
            fs::metadata(&bundle.root)
                .expect("bundle metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn linux_install_runs_the_embedded_hardened_installer() {
        let test = TestContext::new(Platform::Linux, 0);
        let mut runner = FakeRunner::default();
        let paths = test.context.paths.clone();
        let installed_context = test.context.clone();
        runner.respond_with(0, "installed\n", "", move || {
            fs::create_dir_all(paths.linux_binary.parent().expect("binary parent"))
                .expect("binary parent");
            fs::create_dir_all(paths.linux_unit.parent().expect("unit parent"))
                .expect("unit parent");
            fs::create_dir_all(paths.linux_manifest.parent().expect("manifest parent"))
                .expect("manifest parent");
            fs::write(&paths.linux_binary, b"test executor binary").expect("installed binary");
            fs::write(&paths.linux_unit, SYSTEMD_UNIT).expect("installed unit");
            set_mode(&paths.linux_binary, 0o755).expect("binary mode");
            set_mode(&paths.linux_unit, 0o644).expect("unit mode");
            write_service_manifest(&installed_context).expect("installed manifest");
        });

        let outcome = execute_with(
            &test.context,
            &mut runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("installation plan");

        assert_eq!(outcome.stdout, b"installed\n");
        let invocation = &runner.invocations[0];
        assert_eq!(invocation.program, OsStr::new("/bin/bash"));
        assert!(
            invocation.arguments[0]
                .to_string_lossy()
                .ends_with("scripts/install-systemd.sh")
        );
        assert_eq!(invocation.arguments[1], "--binary");
        assert_ne!(invocation.arguments[2], test.context.current_exe);
        assert!(
            invocation.arguments[2]
                .to_string_lossy()
                .ends_with("/executor")
        );
        assert_eq!(invocation.arguments[3], "--no-start");
    }

    #[test]
    fn linux_mutations_require_root_before_running_commands() {
        let test = TestContext::new(Platform::Linux, 1000);
        let mut runner = FakeRunner::default();
        let error = execute_with(
            &test.context,
            &mut runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: false }),
        )
        .expect_err("unprivileged install must fail");
        assert!(error.to_string().contains("sudo"));
        assert!(runner.invocations.is_empty());
    }

    #[test]
    fn service_operation_lock_serializes_without_pid_identity_and_recovers_on_owner_exit() {
        for (platform, effective_uid) in [(Platform::Linux, 0), (Platform::MacOs, 501)] {
            let test = TestContext::new(platform, effective_uid);
            let alternate_source = test._directory.path().join("alternate-executor");
            fs::write(&alternate_source, b"different executor binary").expect("alternate binary");
            set_mode(&alternate_source, 0o755).expect("alternate binary mode");
            let mut alternate = test.context.clone();
            alternate.current_exe = alternate_source.clone();
            alternate.installation_source = alternate_source;
            let held = acquire_service_operation_lock(&test.context).expect("first operation lock");

            for command in [
                ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
                ServiceCommand::Remove,
                ServiceCommand::Start,
                ServiceCommand::Stop,
                ServiceCommand::Restart,
            ] {
                let mut runner = FakeRunner::default();
                let error = execute_with(&alternate, &mut runner, command)
                    .expect_err("concurrent mutation must fail before planning");
                assert!(
                    error
                        .to_string()
                        .contains("another Executor service operation is already active")
                );
                assert!(runner.invocations.is_empty());
            }

            drop(held);
            acquire_service_operation_lock(&alternate)
                .expect("kernel lock should recover when its owner exits");
        }
    }

    #[test]
    fn service_operation_lock_rejects_preopened_and_spoofed_inodes() {
        for (platform, effective_uid) in [(Platform::Linux, 0), (Platform::MacOs, 501)] {
            let test = TestContext::new(platform, effective_uid);
            let lock_path = match platform {
                Platform::Linux => &test.context.paths.linux_lock,
                Platform::MacOs => &test.context.paths.mac_lock,
                Platform::Unsupported => unreachable!(),
            };
            let lock_parent = lock_path.parent().expect("lock parent");
            fs::create_dir_all(lock_parent).expect("lock parent");
            if platform == Platform::MacOs {
                set_mode(&test.context.paths.mac_executor_root, 0o700).expect("Executor root mode");
            }
            set_mode(lock_parent, 0o700).expect("lock parent mode");
            let victim = test._directory.path().join("lock-victim");
            fs::write(&victim, b"keep me").expect("lock victim");
            set_mode(&victim, 0o600).expect("lock victim mode");
            std::os::unix::fs::symlink(&victim, lock_path).expect("spoofed lock symlink");

            assert!(
                acquire_service_operation_lock(&test.context).is_err(),
                "symbolic-link lock must fail closed"
            );
            assert_eq!(fs::read(&victim).expect("victim contents"), b"keep me");

            fs::remove_file(lock_path).expect("remove spoofed symlink");
            fs::write(lock_path, b"").expect("broad lock file");
            set_mode(lock_path, 0o644).expect("broad lock mode");
            assert!(
                acquire_service_operation_lock(&test.context).is_err(),
                "broad lock mode must fail closed"
            );

            set_mode(lock_path, 0o600).expect("private lock mode");
            let alias = test
                ._directory
                .path()
                .join(format!("{platform:?}-lock-alias"));
            fs::hard_link(lock_path, &alias).expect("lock hard link");
            assert!(
                acquire_service_operation_lock(&test.context).is_err(),
                "hard-linked lock must fail closed"
            );
            assert_eq!(fs::metadata(lock_path).expect("lock metadata").nlink(), 2);
        }
    }

    #[test]
    fn restart_recovers_the_exact_service_recovery_publication_alias() {
        let test = TestContext::new(Platform::Linux, 0);
        let path = &test.context.paths.linux_recovery;
        let parent = path.parent().expect("recovery parent");
        fs::create_dir_all(parent).expect("recovery parent");
        fs::write(path, SERVICE_RECOVERY_CONTENTS).expect("recovery marker");
        set_mode(path, 0o600).expect("recovery mode");
        let alias = parent.join(format!(".service-recovery-{}.tmp", Uuid::new_v4()));
        fs::hard_link(path, &alias).expect("recovery publication alias");

        assert!(service_recovery_exists(&test.context).expect("recovery marker validation"));
        assert!(!alias.exists());
        assert_eq!(fs::metadata(path).expect("recovery metadata").nlink(), 1);
    }

    #[test]
    fn service_recovery_directory_sync_failure_is_retried_before_use() {
        let test = TestContext::new(Platform::Linux, 0);
        let path = &test.context.paths.linux_recovery;
        let parent = path.parent().expect("recovery parent").to_path_buf();
        fs::create_dir_all(&parent).expect("recovery parent");
        test.context
            .directory_sync_test
            .failure
            .replace(Some(parent.clone()));

        ensure_service_recovery_marker(&test.context)
            .expect_err("recovery directory sync failure must be returned");
        assert!(path.exists());
        assert_eq!(fs::metadata(path).expect("recovery metadata").nlink(), 1);

        test.context.directory_sync_test.failure.replace(None);
        ensure_service_recovery_marker(&test.context)
            .expect("recovery directory sync should be retried");
        assert_eq!(
            test.context.directory_sync_test.events.borrow().last(),
            Some(&parent)
        );
    }

    #[test]
    fn restart_rejects_substituted_and_unknown_service_recovery_aliases() {
        let test = TestContext::new(Platform::Linux, 0);
        let path = &test.context.paths.linux_recovery;
        let parent = path.parent().expect("recovery parent");
        fs::create_dir_all(parent).expect("recovery parent");
        fs::write(path, SERVICE_RECOVERY_CONTENTS).expect("recovery marker");
        set_mode(path, 0o600).expect("recovery mode");
        let unknown_alias = parent.join("unknown-recovery-alias");
        fs::hard_link(path, &unknown_alias).expect("unknown recovery alias");
        let substituted_alias = parent.join(format!(".service-recovery-{}.tmp", Uuid::new_v4()));
        fs::write(&substituted_alias, SERVICE_RECOVERY_CONTENTS)
            .expect("substituted recovery alias");
        set_mode(&substituted_alias, 0o600).expect("substituted recovery mode");

        service_recovery_exists(&test.context)
            .expect_err("unknown recovery hard link must remain rejected");

        assert_eq!(
            fs::read(path).expect("recovery contents"),
            SERVICE_RECOVERY_CONTENTS.as_bytes()
        );
        assert_eq!(
            fs::read(&substituted_alias).expect("substituted recovery contents"),
            SERVICE_RECOVERY_CONTENTS.as_bytes()
        );
        assert!(unknown_alias.exists());
        assert_eq!(fs::metadata(path).expect("recovery metadata").nlink(), 2);
    }

    #[test]
    fn interrupted_install_recovery_marker_allows_a_clean_rerun() {
        let test = TestContext::new(Platform::Linux, 0);
        for spec in managed_file_specs(&test.context) {
            fs::create_dir_all(spec.path.parent().expect("managed parent"))
                .expect("managed parent");
            fs::write(spec.path, b"partially replaced").expect("partial managed file");
            set_mode(spec.path, spec.mode).expect("managed mode");
        }
        fs::create_dir_all(
            test.context
                .paths
                .linux_recovery
                .parent()
                .expect("recovery parent"),
        )
        .expect("recovery parent");
        fs::write(
            &test.context.paths.linux_recovery,
            SERVICE_RECOVERY_CONTENTS,
        )
        .expect("recovery marker");
        set_mode(&test.context.paths.linux_recovery, 0o600).expect("recovery mode");

        let installed_context = test.context.clone();
        let mut runner = FakeRunner::default();
        runner.respond_with(0, "installed\n", "", move || {
            fs::write(
                &installed_context.paths.linux_binary,
                b"test executor binary",
            )
            .expect("installed binary");
            fs::write(&installed_context.paths.linux_unit, SYSTEMD_UNIT).expect("installed unit");
            set_mode(&installed_context.paths.linux_binary, 0o755).expect("binary mode");
            set_mode(&installed_context.paths.linux_unit, 0o644).expect("unit mode");
            write_service_manifest(&installed_context).expect("installed manifest");
            fs::remove_file(&installed_context.paths.linux_recovery)
                .expect("clear recovery marker");
        });

        let outcome = execute_with(
            &test.context,
            &mut runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("recovery install");

        assert_eq!(outcome.stdout, b"installed\n");
        assert!(!test.context.paths.linux_recovery.exists());
        verify_service_manifest(&test.context).expect("recovered manifest");
    }

    #[test]
    fn status_has_stable_active_and_inactive_exit_codes() {
        let test = TestContext::new(Platform::Linux, 1000);
        let mut active = FakeRunner::default();
        active.respond(0, "active\n", "");
        let outcome = execute_with(&test.context, &mut active, ServiceCommand::Status)
            .expect("active status");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout, b"active\n");

        let mut inactive = FakeRunner::default();
        inactive.respond(3, "inactive\n", "");
        let outcome = execute_with(&test.context, &mut inactive, ServiceCommand::Status)
            .expect("inactive status");
        assert_eq!(outcome.exit_code, STATUS_INACTIVE);
        assert_eq!(outcome.stdout, b"inactive\n");
    }

    #[test]
    fn linux_lifecycle_commands_use_systemctl_without_host_mutation() {
        let test = TestContext::new(Platform::Linux, 0);
        write_managed_fixtures(&test.context);
        let mut runner = FakeRunner::default();
        runner.respond(0, "", "");
        runner.respond(0, "active\n", "");
        runner.respond(0, "", "");
        runner.respond(0, "", "");

        execute_with(&test.context, &mut runner, ServiceCommand::Start).expect("start");
        execute_with(&test.context, &mut runner, ServiceCommand::Stop).expect("stop");
        execute_with(&test.context, &mut runner, ServiceCommand::Restart).expect("restart");

        let arguments = runner
            .invocations
            .iter()
            .map(|invocation| invocation.arguments.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            vec![
                os_args(&["start", SYSTEMD_SERVICE]),
                os_args(&["is-active", SYSTEMD_SERVICE]),
                os_args(&["stop", SYSTEMD_SERVICE]),
                os_args(&["restart", SYSTEMD_SERVICE]),
            ]
        );
    }

    #[test]
    fn macos_install_copies_the_binary_and_runs_the_embedded_installer() {
        let test = TestContext::new(Platform::MacOs, 501);
        let mut runner = FakeRunner::default();
        runner.respond(0, "LaunchAgent paths and configuration are valid.\n", "");
        runner.respond(113, "", "Could not find service");
        let paths = test.context.paths.clone();
        let installed_context = test.context.clone();
        runner.respond_with(0, "installed\n", "", move || {
            for (path, contents, mode) in [
                (&paths.mac_plist, b"plist".as_slice(), 0o600),
                (&paths.mac_wrapper, b"wrapper".as_slice(), 0o700),
                (&paths.mac_logger, b"logger".as_slice(), 0o700),
                (&paths.mac_config, b"config".as_slice(), 0o600),
            ] {
                fs::write(path, contents).expect("installed managed file");
                set_mode(path, mode).expect("managed file mode");
            }
            write_service_manifest(&installed_context).expect("installed manifest");
            fs::remove_file(&installed_context.paths.mac_recovery).expect("clear recovery marker");
        });

        let outcome = execute_with(
            &test.context,
            &mut runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("macOS installation");

        assert_eq!(outcome.stdout, b"installed\n");
        assert_eq!(
            fs::read(&test.context.paths.mac_binary).expect("installed binary"),
            b"test executor binary"
        );
        assert_eq!(
            fs::metadata(&test.context.paths.mac_binary)
                .expect("binary metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        let validation = &runner.invocations[0];
        assert_eq!(validation.program, OsStr::new("/bin/bash"));
        assert!(
            validation.arguments[0]
                .to_string_lossy()
                .ends_with("scripts/install-launchd.sh")
        );
        assert_eq!(validation.arguments[1], "--binary");
        assert_ne!(validation.arguments[2], test.context.paths.mac_binary);
        assert_eq!(validation.arguments[3], "--validate-only");
        assert_eq!(runner.invocations[1].program, OsStr::new("launchctl"));
        let invocation = &runner.invocations[2];
        assert_eq!(invocation.program, OsStr::new("/bin/bash"));
        assert!(
            invocation.arguments[0]
                .to_string_lossy()
                .ends_with("scripts/install-launchd.sh")
        );
        assert_eq!(invocation.arguments[1], "--binary");
        assert_eq!(invocation.arguments[2], test.context.paths.mac_binary);
        assert_eq!(invocation.arguments[3], "--no-start");
        assert_eq!(invocation.arguments.len(), 4);
    }

    #[test]
    fn macos_custom_data_configuration_uses_fixed_managed_paths_for_lifecycle() {
        let test = TestContext::new(Platform::MacOs, 501);
        let custom_data = test._directory.path().join("custom executor data");
        let custom_templates = custom_data.join("custom templates.json");
        let state_sentinel = custom_data.join("state-sentinel");
        fs::create_dir(&custom_data).expect("custom data directory");
        set_mode(&custom_data, 0o700).expect("custom data mode");
        fs::write(&custom_templates, b"{\"templates\":[]}").expect("custom templates");
        set_mode(&custom_templates, 0o600).expect("custom templates mode");
        fs::write(&state_sentinel, b"preserve custom state").expect("custom state");
        let config = format!(
            "executor-launchd-config-v1\ndata_dir_hex={}\ntemplates_file_hex={}\npublic_origin_hex=\n",
            encode_service_config_value(&custom_data),
            encode_service_config_value(&custom_templates)
        );
        let mut install_runner = FakeRunner::default();
        queue_successful_macos_install_with_config(
            &mut install_runner,
            &test.context,
            config.as_bytes(),
        );

        execute_with(
            &test.context,
            &mut install_runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("custom-data service install");

        assert_eq!(
            test.context
                .paths
                .mac_wrapper
                .parent()
                .expect("wrapper parent"),
            test.context.paths.mac_install_root
        );
        assert_eq!(
            test.context
                .paths
                .mac_logger
                .parent()
                .expect("logger parent"),
            test.context.paths.mac_install_root
        );
        assert!(!custom_data.join("run-launchd.sh").exists());
        assert!(!custom_data.join("bounded-log.sh").exists());
        verify_service_manifest(&test.context).expect("custom-data service manifest");

        let mut start_runner = FakeRunner::default();
        start_runner.respond(113, "", "Could not find service");
        start_runner.respond(0, "", "");
        start_runner.respond(0, "", "");
        execute_with(&test.context, &mut start_runner, ServiceCommand::Start)
            .expect("start custom-data service");

        let mut remove_runner = FakeRunner::default();
        remove_runner.respond(0, "state = running\n", "");
        remove_runner.respond(0, "", "");
        execute_with(&test.context, &mut remove_runner, ServiceCommand::Remove)
            .expect("remove custom-data service");

        assert_eq!(
            fs::read(&state_sentinel).expect("preserved custom state"),
            b"preserve custom state"
        );
        assert!(custom_templates.exists());
        assert_eq!(
            fs::read(&test.context.paths.mac_config).expect("preserved custom config"),
            config.as_bytes()
        );
        assert!(!test.context.paths.mac_wrapper.exists());
        assert!(!test.context.paths.mac_logger.exists());
    }

    #[test]
    fn macos_validation_failure_preserves_installation_and_does_not_block_remove() {
        let test = TestContext::new(Platform::MacOs, 501);
        write_managed_fixtures(&test.context);
        let before = managed_file_specs(&test.context)
            .iter()
            .map(|spec| fs::read(spec.path).expect("managed file snapshot"))
            .collect::<Vec<_>>();
        let manifest_before =
            fs::read(&test.context.paths.mac_manifest).expect("manifest snapshot");
        fs::write(&test.context.current_exe, b"replacement executor binary")
            .expect("replacement source");
        set_mode(&test.context.current_exe, 0o755).expect("replacement source mode");
        let mut install_runner = FakeRunner::default();
        install_runner.respond(
            1,
            "",
            "the MCP stdio template file must not overlap a managed service path",
        );

        let error = execute_with(
            &test.context,
            &mut install_runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect_err("colliding configuration must fail validation");

        assert!(error.to_string().contains("must not overlap"));
        assert_eq!(install_runner.invocations.len(), 1);
        assert_eq!(
            install_runner.invocations[0].program,
            OsStr::new("/bin/bash")
        );
        assert_eq!(
            install_runner.invocations[0].arguments[3],
            "--validate-only"
        );
        assert!(!test.context.paths.mac_recovery.exists());
        for (spec, expected) in managed_file_specs(&test.context).iter().zip(before) {
            assert_eq!(
                fs::read(spec.path).expect("preserved managed file"),
                expected,
                "preserved {}",
                spec.description
            );
        }
        assert_eq!(
            fs::read(&test.context.paths.mac_manifest).expect("preserved manifest"),
            manifest_before
        );
        verify_service_manifest(&test.context).expect("preserved ownership manifest");

        let preserved_config =
            fs::read(&test.context.paths.mac_config).expect("preserved config before remove");
        let mut remove_runner = FakeRunner::default();
        remove_runner.respond(113, "", "Could not find service");
        execute_with(&test.context, &mut remove_runner, ServiceCommand::Remove)
            .expect("remove after rejected install");
        assert_eq!(
            fs::read(&test.context.paths.mac_config).expect("config preserved by remove"),
            preserved_config
        );
    }

    #[test]
    fn archive_then_service_upgrades_keep_each_installation_independently_owned() {
        let test = TestContext::new(Platform::MacOs, 501);
        let (archive_binary, archive_manifest) =
            write_archive_fixture(&test.context, b"archive executor v1");
        let mut context = test.context.clone();
        context.current_exe = archive_binary.clone();
        context.installation_source = archive_binary.clone();

        let mut first_runner = FakeRunner::default();
        queue_successful_macos_install(&mut first_runner, &context);
        execute_with(
            &context,
            &mut first_runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("service install from archive binary");
        assert_eq!(
            fs::read(&context.paths.mac_binary).expect("service binary v1"),
            b"archive executor v1"
        );

        let (upgraded_archive_binary, upgraded_archive_manifest) =
            write_archive_fixture(&context, b"archive executor v2");
        assert_eq!(upgraded_archive_binary, archive_binary);
        assert_eq!(upgraded_archive_manifest, archive_manifest);
        let archive_manifest_contents =
            fs::read(&archive_manifest).expect("upgraded archive manifest contents");
        verify_service_manifest(&context).expect("archive upgrade must not alter service files");

        let mut second_runner = FakeRunner::default();
        queue_successful_macos_install(&mut second_runner, &context);
        execute_with(
            &context,
            &mut second_runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("service upgrade from upgraded archive binary");

        assert_eq!(
            fs::read(&context.paths.mac_binary).expect("service binary v2"),
            b"archive executor v2"
        );
        assert_eq!(
            fs::read(&archive_binary).expect("archive binary after service upgrade"),
            b"archive executor v2"
        );
        assert_eq!(
            fs::read(&archive_manifest).expect("archive manifest after service upgrade"),
            archive_manifest_contents
        );
    }

    #[test]
    fn service_then_archive_upgrades_preserve_the_service_ownership_boundary() {
        let test = TestContext::new(Platform::MacOs, 501);
        let mut first_runner = FakeRunner::default();
        queue_successful_macos_install(&mut first_runner, &test.context);
        execute_with(
            &test.context,
            &mut first_runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("initial service install");
        let service_manifest_before_archive =
            fs::read(&test.context.paths.mac_manifest).expect("service manifest");

        let (archive_binary, archive_manifest) =
            write_archive_fixture(&test.context, b"archive executor v2");
        let archive_manifest_contents =
            fs::read(&archive_manifest).expect("archive manifest contents");
        assert_eq!(
            fs::read(&test.context.paths.mac_manifest)
                .expect("service manifest after archive install"),
            service_manifest_before_archive
        );
        verify_service_manifest(&test.context)
            .expect("archive install must preserve service files");

        let mut upgraded_context = test.context.clone();
        upgraded_context.current_exe = archive_binary.clone();
        upgraded_context.installation_source = archive_binary.clone();
        let mut second_runner = FakeRunner::default();
        queue_successful_macos_install(&mut second_runner, &upgraded_context);
        execute_with(
            &upgraded_context,
            &mut second_runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("service upgrade after archive install");

        assert_eq!(
            fs::read(&upgraded_context.paths.mac_binary).expect("upgraded service binary"),
            b"archive executor v2"
        );
        assert_eq!(
            fs::read(&archive_binary).expect("preserved archive binary"),
            b"archive executor v2"
        );
        assert_eq!(
            fs::read(&archive_manifest).expect("preserved archive manifest"),
            archive_manifest_contents
        );
    }

    #[test]
    fn macos_remove_preserves_archive_install_and_config_and_remains_idempotent() {
        let test = TestContext::new(Platform::MacOs, 501);
        write_managed_fixtures(&test.context);
        let preserved_config =
            fs::read(&test.context.paths.mac_config).expect("persisted service config");
        let (archive_binary, archive_manifest) =
            write_archive_fixture(&test.context, b"archive executor");
        let archive_manifest_contents =
            fs::read(&archive_manifest).expect("archive manifest contents");
        let mut runner = FakeRunner::default();
        runner.respond(113, "", "Could not find service");
        runner.respond(113, "", "Could not find service");

        execute_with(&test.context, &mut runner, ServiceCommand::Remove)
            .expect("first service removal");
        execute_with(&test.context, &mut runner, ServiceCommand::Remove)
            .expect("idempotent service removal");

        assert_eq!(
            fs::read(&test.context.paths.mac_config).expect("preserved service config"),
            preserved_config
        );
        assert_eq!(
            fs::read(&archive_binary).expect("preserved archive binary"),
            b"archive executor"
        );
        assert_eq!(
            fs::read(&archive_manifest).expect("preserved archive manifest"),
            archive_manifest_contents
        );
        for path in [
            &test.context.paths.mac_binary,
            &test.context.paths.mac_plist,
            &test.context.paths.mac_wrapper,
            &test.context.paths.mac_logger,
            &test.context.paths.mac_manifest,
        ] {
            assert!(!path.exists(), "removed service file: {}", path.display());
        }
    }

    #[test]
    fn macos_remove_rejects_a_missing_persisted_config_while_manifest_exists() {
        let test = TestContext::new(Platform::MacOs, 501);
        write_managed_fixtures(&test.context);
        fs::remove_file(&test.context.paths.mac_config).expect("remove persisted config");
        let mut runner = FakeRunner::default();

        let error = execute_with(&test.context, &mut runner, ServiceCommand::Remove)
            .expect_err("missing preserved config must fail closed");

        assert!(
            error
                .to_string()
                .contains("persisted LaunchAgent configuration")
        );
        assert!(error.to_string().contains("is missing"));
        assert!(test.context.paths.mac_binary.exists());
        assert!(test.context.paths.mac_manifest.exists());
        assert!(runner.invocations.is_empty());
    }

    #[test]
    fn macos_bundle_failure_preserves_the_existing_installation_before_validation() {
        let test = TestContext::new(Platform::MacOs, 501);
        prepare_macos_directories(&test.context).expect("macOS directories");
        write_managed_fixtures(&test.context);
        let original_binary = fs::read(&test.context.paths.mac_binary).expect("original binary");
        let original_manifest =
            fs::read(&test.context.paths.mac_manifest).expect("original manifest");
        fs::write(&test.context.current_exe, b"replacement executor binary")
            .expect("replacement source");
        set_mode(&test.context.current_exe, 0o755).expect("replacement source mode");
        fs::remove_dir(&test.context.temporary_root).expect("remove temporary root");

        let mut first_runner = FakeRunner::default();
        let error = execute_with(
            &test.context,
            &mut first_runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect_err("bundle failure must leave the installation unchanged");

        assert!(error.to_string().contains("temporary directory"));
        assert!(!test.context.paths.mac_recovery.exists());
        assert_eq!(
            fs::read(&test.context.paths.mac_binary).expect("preserved binary"),
            original_binary
        );
        assert_eq!(
            fs::read(&test.context.paths.mac_manifest).expect("preserved manifest"),
            original_manifest
        );
        assert!(first_runner.invocations.is_empty());

        fs::create_dir(&test.context.temporary_root).expect("restore temporary root");
        set_mode(&test.context.temporary_root, 0o700).expect("temporary root mode");
        let mut second_runner = FakeRunner::default();
        queue_successful_macos_install(&mut second_runner, &test.context);

        execute_with(
            &test.context,
            &mut second_runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: true }),
        )
        .expect("installation after restoring the temporary root");

        assert!(!test.context.paths.mac_recovery.exists());
        assert_eq!(
            fs::read(&test.context.paths.mac_binary).expect("updated binary"),
            b"replacement executor binary"
        );
        verify_service_manifest(&test.context).expect("updated manifest");
    }

    #[test]
    fn macos_install_rejects_a_symlinked_binary_directory() {
        let test = TestContext::new(Platform::MacOs, 501);
        fs::create_dir_all(&test.context.paths.mac_install_root).expect("install root");
        let victim = test._directory.path().join("victim");
        fs::create_dir(&victim).expect("victim directory");
        std::os::unix::fs::symlink(&victim, &test.context.paths.mac_binary_dir)
            .expect("binary directory symlink");
        let mut runner = FakeRunner::default();
        runner.respond(0, "LaunchAgent paths and configuration are valid.\n", "");
        runner.respond(113, "", "Could not find service");

        let error = execute_with(
            &test.context,
            &mut runner,
            ServiceCommand::Install(ServiceInstallArgs { no_start: false }),
        )
        .expect_err("symlinked binary directory must fail");
        assert!(error.to_string().contains("non-symlinked directory"));
        assert!(
            fs::read_dir(victim)
                .expect("victim directory")
                .next()
                .is_none()
        );
    }

    #[test]
    fn macos_install_preserves_safe_shared_parent_directory_modes() {
        let test = TestContext::new(Platform::MacOs, 501);
        for path in [
            &test.context.paths.mac_library,
            &test.context.paths.mac_launch_agents,
        ] {
            fs::create_dir_all(path).expect("shared parent directory");
            set_mode(path, 0o755).expect("shared parent mode");
        }

        prepare_macos_directories(&test.context).expect("macOS directories");

        for path in [
            &test.context.paths.mac_library,
            &test.context.paths.mac_launch_agents,
        ] {
            assert_eq!(
                fs::metadata(path)
                    .expect("shared parent metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
        for path in [
            &test.context.paths.mac_executor_root,
            &test.context.paths.mac_install_root,
            &test.context.paths.mac_binary_dir,
        ] {
            assert_eq!(
                fs::metadata(path)
                    .expect("private directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn macos_install_rejects_writable_shared_parent_directories() {
        for unsafe_directory in ["Library", "LaunchAgents"] {
            let test = TestContext::new(Platform::MacOs, 501);
            let path = match unsafe_directory {
                "Library" => &test.context.paths.mac_library,
                "LaunchAgents" => {
                    fs::create_dir(&test.context.paths.mac_library).expect("Library directory");
                    set_mode(&test.context.paths.mac_library, 0o755).expect("Library mode");
                    &test.context.paths.mac_launch_agents
                }
                _ => unreachable!(),
            };
            fs::create_dir(path).expect("unsafe shared directory");
            set_mode(path, 0o777).expect("unsafe shared mode");

            let error = prepare_macos_directories(&test.context)
                .expect_err("writable shared directory must fail closed");

            assert!(error.to_string().contains("must not be group-writable"));
            assert_eq!(
                fs::metadata(path)
                    .expect("unsafe directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o777
            );
        }
    }

    #[test]
    fn macos_status_distinguishes_loaded_but_inactive() {
        let test = TestContext::new(Platform::MacOs, 501);
        let mut runner = FakeRunner::default();
        runner.respond(0, "state = exited\n", "");
        let outcome = execute_with(&test.context, &mut runner, ServiceCommand::Status)
            .expect("loaded status");
        assert_eq!(outcome.exit_code, STATUS_INACTIVE);
        assert_eq!(outcome.stdout, b"inactive\n");
    }

    #[test]
    fn macos_lifecycle_commands_use_the_user_launchctl_domain() {
        let test = TestContext::new(Platform::MacOs, 501);
        prepare_macos_directories(&test.context).expect("macOS directories");
        write_managed_fixtures(&test.context);
        let mut runner = FakeRunner::default();
        runner.respond(113, "", "Could not find service");
        runner.respond(0, "", "");
        runner.respond(0, "", "");
        runner.respond(0, "state = running\n", "");
        runner.respond(0, "", "");
        runner.respond(0, "state = running\n", "");
        runner.respond(0, "", "");
        runner.respond(0, "", "");
        runner.respond(0, "", "");

        execute_with(&test.context, &mut runner, ServiceCommand::Start).expect("start");
        execute_with(&test.context, &mut runner, ServiceCommand::Stop).expect("stop");
        execute_with(&test.context, &mut runner, ServiceCommand::Restart).expect("restart");

        assert_eq!(runner.invocations.len(), 9);
        assert_eq!(runner.invocations[0].arguments[0], "print");
        assert_eq!(
            runner.invocations[0].arguments[1],
            "gui/501/dev.executor.gateway"
        );
        assert_eq!(runner.invocations[1].arguments[0], "enable");
        assert_eq!(runner.invocations[2].arguments[0], "bootstrap");
        assert_eq!(runner.invocations[3].arguments[0], "print");
        assert_eq!(runner.invocations[4].arguments[0], "bootout");
        assert_eq!(runner.invocations[5].arguments[0], "print");
        assert_eq!(runner.invocations[6].arguments[0], "bootout");
        assert_eq!(runner.invocations[7].arguments[0], "enable");
        assert_eq!(runner.invocations[8].arguments[0], "bootstrap");
    }

    #[test]
    fn macos_service_commands_reject_sudo() {
        let test = TestContext::new(Platform::MacOs, 0);
        let mut runner = FakeRunner::default();
        let error = execute_with(&test.context, &mut runner, ServiceCommand::Status)
            .expect_err("root LaunchAgent management must fail");
        assert!(
            error
                .to_string()
                .contains("do not run this command with sudo")
        );
        assert!(runner.invocations.is_empty());
    }

    #[test]
    fn linux_remove_is_idempotent_and_preserves_state_paths() {
        let test = TestContext::new(Platform::Linux, 0);
        let mut runner = FakeRunner::default();
        runner.respond(3, "inactive\n", "");
        let outcome = execute_with(&test.context, &mut runner, ServiceCommand::Remove)
            .expect("idempotent remove");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(runner.invocations.len(), 1);
        assert!(outcome.stdout.starts_with(b"Executor service removed"));
    }

    #[test]
    fn linux_remove_retries_daemon_reload_after_files_were_removed() {
        let test = TestContext::new(Platform::Linux, 0);
        write_managed_fixtures(&test.context);
        let mut first_runner = FakeRunner::default();
        first_runner.respond(3, "inactive\n", "");
        first_runner.respond(0, "", "");
        first_runner.respond(1, "", "injected daemon-reload failure");

        let error = execute_with(&test.context, &mut first_runner, ServiceCommand::Remove)
            .expect_err("daemon-reload failure must be returned");

        assert!(error.to_string().contains("injected daemon-reload failure"));
        assert!(!test.context.paths.linux_binary.exists());
        assert!(!test.context.paths.linux_unit.exists());
        assert!(test.context.paths.linux_manifest.exists());

        let mut second_runner = FakeRunner::default();
        second_runner.respond(3, "inactive\n", "");
        second_runner.respond(0, "", "");
        execute_with(&test.context, &mut second_runner, ServiceCommand::Remove)
            .expect("removal retry");

        assert_eq!(
            second_runner.invocations[1].arguments,
            os_args(&["daemon-reload"])
        );
        assert!(!test.context.paths.linux_manifest.exists());
    }

    #[test]
    fn linux_remove_keeps_the_manifest_when_a_managed_parent_sync_fails() {
        let test = TestContext::new(Platform::Linux, 0);
        write_managed_fixtures(&test.context);
        let binary_parent = test
            .context
            .paths
            .linux_binary
            .parent()
            .expect("binary parent")
            .to_path_buf();
        test.context
            .directory_sync_test
            .failure
            .replace(Some(binary_parent.clone()));
        let mut first_runner = FakeRunner::default();
        first_runner.respond(3, "inactive\n", "");
        first_runner.respond(0, "", "");

        let error = execute_with(&test.context, &mut first_runner, ServiceCommand::Remove)
            .expect_err("managed parent sync failure must stop removal");

        assert!(
            error
                .to_string()
                .contains("injected directory sync failure")
        );
        assert!(test.context.paths.linux_manifest.exists());
        assert!(!test.context.paths.linux_binary.exists());
        assert!(!test.context.paths.linux_unit.exists());
        assert_eq!(
            test.context.directory_sync_test.events.borrow().as_slice(),
            [binary_parent.as_path()]
        );
        assert_eq!(first_runner.invocations.len(), 2);

        test.context.directory_sync_test.failure.replace(None);
        let mut second_runner = FakeRunner::default();
        second_runner.respond(3, "inactive\n", "");
        second_runner.respond(0, "", "");
        execute_with(&test.context, &mut second_runner, ServiceCommand::Remove)
            .expect("removal retry after managed parent sync failure");

        assert!(!test.context.paths.linux_manifest.exists());
        assert_eq!(
            second_runner.invocations[1].arguments,
            os_args(&["daemon-reload"])
        );
    }

    #[test]
    fn linux_remove_retries_a_manifest_parent_sync_after_manifest_unlink() {
        let test = TestContext::new(Platform::Linux, 0);
        write_managed_fixtures(&test.context);
        let manifest_parent = test
            .context
            .paths
            .linux_manifest
            .parent()
            .expect("manifest parent")
            .to_path_buf();
        test.context
            .directory_sync_test
            .failure
            .replace(Some(manifest_parent.clone()));
        let mut first_runner = FakeRunner::default();
        first_runner.respond(3, "inactive\n", "");
        first_runner.respond(0, "", "");
        first_runner.respond(0, "", "");

        let error = execute_with(&test.context, &mut first_runner, ServiceCommand::Remove)
            .expect_err("manifest parent sync failure must be returned");

        assert!(
            error
                .to_string()
                .contains("injected directory sync failure")
        );
        assert!(!test.context.paths.linux_manifest.exists());
        assert_eq!(
            test.context.directory_sync_test.events.borrow().last(),
            Some(&manifest_parent)
        );

        test.context.directory_sync_test.failure.replace(None);
        let mut second_runner = FakeRunner::default();
        second_runner.respond(3, "inactive\n", "");
        execute_with(&test.context, &mut second_runner, ServiceCommand::Remove)
            .expect("manifest directory sync retry");
        assert_eq!(
            test.context.directory_sync_test.events.borrow().last(),
            Some(&manifest_parent)
        );
    }

    #[test]
    fn macos_remove_syncs_managed_parents_before_the_manifest_parent() {
        let test = TestContext::new(Platform::MacOs, 501);
        write_managed_fixtures(&test.context);
        let binary_parent = test
            .context
            .paths
            .mac_binary
            .parent()
            .expect("binary parent")
            .to_path_buf();
        let manifest_parent = test
            .context
            .paths
            .mac_manifest
            .parent()
            .expect("manifest parent")
            .to_path_buf();
        let mut runner = FakeRunner::default();
        runner.respond(113, "", "Could not find service");

        execute_with(&test.context, &mut runner, ServiceCommand::Remove)
            .expect("macOS service removal");

        let events = test.context.directory_sync_test.events.borrow();
        assert_eq!(events.first(), Some(&binary_parent));
        assert_eq!(events.last(), Some(&manifest_parent));
        assert!(events.len() >= 2);
        assert!(!test.context.paths.mac_manifest.exists());
        assert!(test.context.paths.mac_config.exists());
    }

    #[test]
    fn macos_remove_keeps_the_manifest_when_a_managed_parent_sync_fails() {
        let test = TestContext::new(Platform::MacOs, 501);
        write_managed_fixtures(&test.context);
        let binary_parent = test
            .context
            .paths
            .mac_binary
            .parent()
            .expect("binary parent")
            .to_path_buf();
        test.context
            .directory_sync_test
            .failure
            .replace(Some(binary_parent));
        let mut first_runner = FakeRunner::default();
        first_runner.respond(113, "", "Could not find service");

        execute_with(&test.context, &mut first_runner, ServiceCommand::Remove)
            .expect_err("macOS managed parent sync failure must stop removal");
        assert!(test.context.paths.mac_manifest.exists());
        assert!(test.context.paths.mac_config.exists());

        test.context.directory_sync_test.failure.replace(None);
        let mut second_runner = FakeRunner::default();
        second_runner.respond(113, "", "Could not find service");
        execute_with(&test.context, &mut second_runner, ServiceCommand::Remove)
            .expect("macOS removal retry");
        assert!(!test.context.paths.mac_manifest.exists());
        assert!(test.context.paths.mac_config.exists());
    }

    #[test]
    fn remove_rejects_managed_symlinks_without_touching_the_target() {
        let test = TestContext::new(Platform::Linux, 0);
        fs::create_dir_all(test.context.paths.linux_unit.parent().expect("unit parent"))
            .expect("unit parent");
        let victim = test._directory.path().join("victim-unit");
        fs::write(&victim, b"keep me").expect("victim file");
        std::os::unix::fs::symlink(&victim, &test.context.paths.linux_unit).expect("unit symlink");
        let mut runner = FakeRunner::default();

        let error = execute_with(&test.context, &mut runner, ServiceCommand::Remove)
            .expect_err("managed symlink must fail");
        assert!(error.to_string().contains("must be a regular file"));
        assert_eq!(fs::read(victim).expect("victim contents"), b"keep me");
        assert!(runner.invocations.is_empty());
    }

    #[test]
    fn remove_rejects_replaced_managed_files_and_preserves_the_sentinel() {
        let test = TestContext::new(Platform::Linux, 0);
        write_managed_fixtures(&test.context);
        fs::write(&test.context.paths.linux_binary, b"unmanaged sentinel")
            .expect("replacement sentinel");
        set_mode(&test.context.paths.linux_binary, 0o755).expect("sentinel mode");
        let mut runner = FakeRunner::default();

        let error = execute_with(&test.context, &mut runner, ServiceCommand::Remove)
            .expect_err("replaced managed binary must fail closed");

        assert!(error.to_string().contains("contents do not match"));
        assert_eq!(
            fs::read(&test.context.paths.linux_binary).expect("sentinel contents"),
            b"unmanaged sentinel"
        );
        assert!(test.context.paths.linux_unit.exists());
        assert!(test.context.paths.linux_manifest.exists());
        assert!(runner.invocations.is_empty());
    }

    #[test]
    fn unsupported_platform_is_rejected_without_commands() {
        let test = TestContext::new(Platform::Unsupported, 1000);
        let mut runner = FakeRunner::default();
        let error = execute_with(&test.context, &mut runner, ServiceCommand::Status)
            .expect_err("unsupported platform");
        assert!(error.to_string().contains("only on Linux and macOS"));
        assert!(runner.invocations.is_empty());
    }

    #[test]
    fn systemd_unit_allows_the_environment_to_select_an_external_master_key() {
        let unit = std::str::from_utf8(SYSTEMD_UNIT).expect("UTF-8 systemd unit");
        let environment = std::str::from_utf8(SYSTEMD_ENV).expect("UTF-8 environment template");

        assert!(unit.contains("EnvironmentFile=-/etc/executor/executor.env"));
        assert!(!unit.contains("--master-key-file"));
        assert!(environment.contains("EXECUTOR_MASTER_KEY_FILE="));
    }

    #[test]
    fn systemd_external_master_key_rejects_service_managed_paths_without_mutation() {
        let test = TestContext::new(Platform::Linux, 0);
        write_managed_fixtures(&test.context);
        let key_check_data = test._directory.path().join("external-key-check-data");
        for path in [
            &test.context.paths.linux_binary,
            &test.context.paths.linux_unit,
            &test.context.paths.linux_manifest,
        ] {
            let before = fs::read(path).expect("managed file before key validation");
            crate::crypto::load_or_create_master_key(&key_check_data, true, Some(path))
                .expect_err("managed service file must not be accepted as an external key");
            assert_eq!(
                fs::read(path).expect("managed file after key validation"),
                before
            );
        }
        crate::crypto::load_or_create_master_key(
            &key_check_data,
            true,
            Some(&test.context.paths.linux_recovery),
        )
        .expect_err("an absent managed recovery path must not be created as an external key");
        assert!(!test.context.paths.linux_recovery.exists());
    }

    #[test]
    fn installers_publish_the_ownership_manifest_before_starting_services() {
        let systemd = std::str::from_utf8(SYSTEMD_INSTALLER).expect("UTF-8 systemd installer");
        let launchd = std::str::from_utf8(LAUNCHD_INSTALLER).expect("UTF-8 launchd installer");

        let systemd_hash = systemd
            .find("binary_hash=$(sha256sum")
            .expect("systemd binary hash");
        let systemd_manifest = systemd
            .find("mv -f -- \"${manifest_temporary}\" \"${MANIFEST_TARGET}\"")
            .expect("systemd manifest publication");
        let systemd_recovery_removal = systemd
            .find("rm -f -- \"${RECOVERY_TARGET}\"")
            .expect("systemd recovery marker removal");
        let systemd_start = systemd
            .find("systemctl start executor.service")
            .expect("systemd start");
        for description in [
            "the installed Executor binary",
            "the Executor binary directory",
            "the installed systemd unit",
            "the systemd unit directory",
        ] {
            let systemd_sync = systemd
                .find(description)
                .unwrap_or_else(|| panic!("missing systemd sync for {description}"));
            assert!(systemd_sync < systemd_hash);
        }
        assert!(systemd_hash < systemd_manifest);
        assert!(systemd_manifest < systemd_recovery_removal);
        assert!(systemd_recovery_removal < systemd_start);

        let launchd_manifest = launchd
            .find("mv -f \"$temporary_manifest\" \"$MANIFEST\"")
            .expect("launchd manifest publication");
        let launchd_start = launchd
            .find("launchctl bootstrap \"$domain\" \"$PLIST\"")
            .expect("launchd start");
        assert!(launchd_manifest < launchd_start);
        assert!(launchd.contains(
            "chmod 0600 \"$temporary_templates\"\n    sync\n    if ! ln \"$temporary_templates\" \"$TEMPLATES_FILE\""
        ));
        assert!(launchd.contains(
            "fi\n    sync\n    if [[ ${EXECUTOR_INSTALL_TEST_CRASH_AFTER_TEMPLATE_LINK:-} == 1 ]]"
        ));
        assert!(launchd.contains(
            "rm -f \"$temporary_templates\"\n    if [[ ${EXECUTOR_INSTALL_TEST_CRASH_AFTER_TEMPLATE_UNLINK:-} == 1 ]]"
        ));
        assert!(launchd.contains("kill -KILL \"${BASHPID}\"\n    fi\n    sync\n    trap - EXIT"));
    }

    #[test]
    fn embedded_installer_shell_regressions_pass() {
        let mut relative_paths = vec![
            "scripts/test-install-launchd-safety.sh",
            "scripts/test-bounded-log.sh",
        ];
        if cfg!(target_os = "linux") {
            relative_paths.push("scripts/test-install-systemd-master-key.sh");
        }
        for relative_path in relative_paths {
            let output = std::process::Command::new("bash")
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path))
                .output()
                .expect("shell regression should run");
            assert!(
                output.status.success(),
                "{relative_path} failed:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
