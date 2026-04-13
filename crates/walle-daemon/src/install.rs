use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::xdp::default_object_path;
use thiserror::Error;

const INSTALL_BIN_RELATIVE_PATH: &str = "usr/local/bin/walle";
const INSTALL_OBJECT_RELATIVE_PATH: &str = "usr/local/lib/walle/walle-ebpf";
const INSTALL_SCRIPT_RELATIVE_PATH: &str = "usr/local/lib/walle/walle-run.sh";
const INSTALL_UNIT_RELATIVE_PATH: &str = "etc/systemd/system/walle.service";
const INSTALL_CONFIG_RELATIVE_PATH: &str = "etc/walle/config.toml";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallOptions {
    pub root: PathBuf,
    pub xdp_object: Option<PathBuf>,
    pub service_manager: Option<ServiceManager>,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            xdp_object: None,
            service_manager: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallOptions {
    pub root: PathBuf,
}

impl Default for UninstallOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceManager {
    Systemd,
    Script,
}

impl ServiceManager {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Script => "script",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallReport {
    pub binary_path: PathBuf,
    pub object_path: PathBuf,
    pub config_path: PathBuf,
    pub service_manager: ServiceManager,
    pub service_path: PathBuf,
    pub config_created: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallReport {
    pub removed_paths: Vec<PathBuf>,
    pub preserved_config_path: PathBuf,
}

pub fn install(options: InstallOptions) -> Result<InstallReport, InstallError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(InstallError::UnsupportedHost)
    }

    #[cfg(target_os = "linux")]
    {
        ensure_install_privileges(&options.root)?;
        let current_executable =
            env::current_exe().map_err(|source| InstallError::CurrentExecutable { source })?;
        let source_object = resolve_xdp_object(options.xdp_object.as_deref(), &current_executable)?;
        install_with_sources(options, &current_executable, &source_object)
    }
}

pub fn uninstall(options: UninstallOptions) -> Result<UninstallReport, InstallError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(InstallError::UnsupportedHost)
    }

    #[cfg(target_os = "linux")]
    {
        ensure_install_privileges(&options.root)?;

        let mut removed_paths = Vec::new();
        for relative_path in [
            INSTALL_BIN_RELATIVE_PATH,
            INSTALL_OBJECT_RELATIVE_PATH,
            INSTALL_SCRIPT_RELATIVE_PATH,
            INSTALL_UNIT_RELATIVE_PATH,
        ] {
            let path = join_root(&options.root, relative_path);
            if remove_file_if_exists(&path)? {
                removed_paths.push(path);
            }
        }

        Ok(UninstallReport {
            removed_paths,
            preserved_config_path: join_root(&options.root, INSTALL_CONFIG_RELATIVE_PATH),
        })
    }
}

#[cfg(target_os = "linux")]
fn install_with_sources(
    options: InstallOptions,
    current_executable: &Path,
    source_object: &Path,
) -> Result<InstallReport, InstallError> {
    let binary_path = join_root(&options.root, INSTALL_BIN_RELATIVE_PATH);
    let object_path = join_root(&options.root, INSTALL_OBJECT_RELATIVE_PATH);
    let config_path = join_root(&options.root, INSTALL_CONFIG_RELATIVE_PATH);
    let service_manager = options
        .service_manager
        .unwrap_or_else(detect_service_manager);
    let service_path = join_root(
        &options.root,
        match service_manager {
            ServiceManager::Systemd => INSTALL_UNIT_RELATIVE_PATH,
            ServiceManager::Script => INSTALL_SCRIPT_RELATIVE_PATH,
        },
    );

    copy_with_parents(current_executable, &binary_path)?;
    copy_with_parents(source_object, &object_path)?;
    make_executable(&binary_path)?;

    let config_created = if config_path.exists() {
        false
    } else {
        write_file(&config_path, default_config_template())?;
        true
    };

    match service_manager {
        ServiceManager::Systemd => {
            write_file(&service_path, systemd_unit_template())?;
        }
        ServiceManager::Script => {
            write_file(&service_path, fallback_run_script())?;
            make_executable(&service_path)?;
        }
    }

    Ok(InstallReport {
        binary_path,
        object_path,
        config_path,
        service_manager,
        service_path,
        config_created,
    })
}

#[cfg(target_os = "linux")]
fn resolve_xdp_object(
    explicit: Option<&Path>,
    current_executable: &Path,
) -> Result<PathBuf, InstallError> {
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.to_path_buf());
        }

        return Err(InstallError::MissingXdpObject {
            searched: vec![path.to_path_buf()],
        });
    }

    let adjacent = current_executable
        .parent()
        .map(|parent| parent.join("walle-ebpf"));
    let workspace_default = default_object_path();
    let mut searched = Vec::new();

    if let Some(path) = adjacent {
        searched.push(path.clone());
        if path.exists() {
            return Ok(path);
        }
    }

    searched.push(workspace_default.clone());
    if workspace_default.exists() {
        return Ok(workspace_default);
    }

    Err(InstallError::MissingXdpObject { searched })
}

#[cfg(target_os = "linux")]
fn ensure_install_privileges(root: &Path) -> Result<(), InstallError> {
    if root != Path::new("/") {
        return Ok(());
    }

    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        Ok(())
    } else {
        Err(InstallError::MissingPrivileges {
            effective_uid: euid,
        })
    }
}

#[cfg(target_os = "linux")]
fn detect_service_manager() -> ServiceManager {
    if Path::new("/run/systemd/system").exists()
        || Path::new("/bin/systemctl").exists()
        || Path::new("/usr/bin/systemctl").exists()
    {
        ServiceManager::Systemd
    } else {
        ServiceManager::Script
    }
}

fn join_root(root: &Path, relative_path: &str) -> PathBuf {
    root.join(relative_path)
}

#[cfg(target_os = "linux")]
fn copy_with_parents(source: &Path, destination: &Path) -> Result<(), InstallError> {
    create_parent_dir(destination)?;
    fs::copy(source, destination).map_err(|source_error| InstallError::CopyFile {
        from_path: source.to_path_buf(),
        destination: destination.to_path_buf(),
        source_error,
    })?;
    Ok(())
}

fn write_file(path: &Path, content: &str) -> Result<(), InstallError> {
    create_parent_dir(path)?;
    fs::write(path, content).map_err(|source| InstallError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn create_parent_dir(path: &Path) -> Result<(), InstallError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    fs::create_dir_all(parent).map_err(|source| InstallError::CreateDir {
        path: parent.to_path_buf(),
        source,
    })
}

#[cfg(target_os = "linux")]
fn make_executable(path: &Path) -> Result<(), InstallError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|source| InstallError::WriteFile {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).map_err(|source| InstallError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_file_if_exists(path: &Path) -> Result<bool, InstallError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(InstallError::RemoveFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn default_config_template() -> &'static str {
    concat!(
        "version = 1\n",
        "\n",
        "[detectors.ssh]\n",
        "enabled = true\n",
        "failure_threshold = 5\n",
        "window_secs = 300\n",
        "ban_duration_secs = 900\n",
        "log_source_mode = \"auto\"\n",
        "log_file_paths = []\n",
        "\n",
        "[detectors.ssh.gp]\n",
        "enabled = false\n",
        "strategy = \"observe\"\n",
        "trigger_mode = \"decision_emitted\"\n",
        "\n",
        "[detectors.ssh.gp.sshjail]\n",
        "protected_port = 22\n",
        "listen_port = 0\n",
        "max_sessions = 32\n",
        "idle_timeout_secs = 600\n",
        "max_session_duration_secs = 3600\n",
        "audit_dir = \"/tmp/walle/gp/ssh\"\n",
        "hostname_strategy = \"generated\"\n",
        "\n",
        "[policy.access]\n",
        "mode = \"blacklist_only\"\n",
        "allowlist = []\n",
        "denylist = []\n",
        "\n",
        "[policy.logging]\n",
        "level = \"info\"\n",
        "\n",
        "[[interfaces]]\n",
        "name = \"eth0\"\n",
        "xdp_mode = \"driver\"\n",
        "\n",
        "[interfaces.filters.icmp]\n",
        "mode = \"disabled\"\n",
        "allow_rules = []\n",
    )
}

fn systemd_unit_template() -> &'static str {
    concat!(
        "[Unit]\n",
        "Description=Walle XDP firewall\n",
        "After=network-online.target\n",
        "Wants=network-online.target\n",
        "\n",
        "[Service]\n",
        "Type=simple\n",
        "ExecStart=/usr/local/bin/walle run --xdp-object /usr/local/lib/walle/walle-ebpf\n",
        "Restart=on-failure\n",
        "RestartSec=5\n",
        "\n",
        "[Install]\n",
        "WantedBy=multi-user.target\n",
    )
}

fn fallback_run_script() -> &'static str {
    concat!(
        "#!/bin/sh\n",
        "exec /usr/local/bin/walle run --xdp-object /usr/local/lib/walle/walle-ebpf \"$@\"\n",
    )
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("installation is only supported on Linux hosts")]
    UnsupportedHost,
    #[error("installation into '/' requires root privileges; effective uid was {effective_uid}")]
    MissingPrivileges { effective_uid: u32 },
    #[error("failed to resolve the current walle executable: {source}")]
    CurrentExecutable { source: std::io::Error },
    #[error(
        "failed to find the eBPF object to install; searched: {}. build it with `cargo run -p xtask -- build-ebpf`, place `walle-ebpf` next to the binary, or pass `--xdp-object`",
        .searched
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )]
    MissingXdpObject { searched: Vec<PathBuf> },
    #[error("failed to create directory '{path}': {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to copy '{from_path}' to '{destination}': {source_error}")]
    CopyFile {
        from_path: PathBuf,
        destination: PathBuf,
        source_error: std::io::Error,
    },
    #[error("failed to write '{path}': {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to remove '{path}': {source}")]
    RemoveFile {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        default_config_template, install_with_sources, join_root, uninstall, InstallOptions,
        ServiceManager, UninstallOptions, INSTALL_BIN_RELATIVE_PATH, INSTALL_CONFIG_RELATIVE_PATH,
        INSTALL_OBJECT_RELATIVE_PATH, INSTALL_SCRIPT_RELATIVE_PATH, INSTALL_UNIT_RELATIVE_PATH,
    };

    #[test]
    fn default_config_template_includes_disabled_gp_block() {
        let template = default_config_template();

        assert!(template.contains("[detectors.ssh.gp]"));
        assert!(template.contains("enabled = false"));
        assert!(template.contains("strategy = \"observe\""));
        assert!(template.contains("trigger_mode = \"decision_emitted\""));
        assert!(template.contains("[detectors.ssh.gp.sshjail]"));
        assert!(template.contains("listen_port = 0"));
    }

    fn temp_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("walle-{name}-{nanos}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn install_writes_systemd_unit_and_preserves_existing_config() {
        let root = temp_root("install-systemd");
        let source_dir = root.join("sources");
        std::fs::create_dir_all(&source_dir).unwrap();
        let current_executable = source_dir.join("walle");
        let xdp_object = source_dir.join("walle-ebpf");
        std::fs::write(&current_executable, "bin").unwrap();
        std::fs::write(&xdp_object, "obj").unwrap();

        let config_path = join_root(&root, INSTALL_CONFIG_RELATIVE_PATH);
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(&config_path, "version = 1\n").unwrap();

        let report = install_with_sources(
            InstallOptions {
                root: root.clone(),
                xdp_object: None,
                service_manager: Some(ServiceManager::Systemd),
            },
            &current_executable,
            &xdp_object,
        )
        .unwrap();

        assert_eq!(report.service_manager, ServiceManager::Systemd);
        assert!(!report.config_created);
        assert!(join_root(&root, INSTALL_BIN_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_OBJECT_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_UNIT_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_SCRIPT_RELATIVE_PATH).exists());
        assert!(std::fs::read_to_string(join_root(&root, INSTALL_UNIT_RELATIVE_PATH))
            .unwrap()
            .contains("ExecStart=/usr/local/bin/walle run --xdp-object /usr/local/lib/walle/walle-ebpf"));
    }

    #[test]
    fn uninstall_removes_managed_artifacts_but_preserves_config() {
        let root = temp_root("uninstall");
        for relative_path in [
            INSTALL_BIN_RELATIVE_PATH,
            INSTALL_OBJECT_RELATIVE_PATH,
            INSTALL_SCRIPT_RELATIVE_PATH,
        ] {
            let path = join_root(&root, relative_path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "managed").unwrap();
        }
        let config_path = join_root(&root, INSTALL_CONFIG_RELATIVE_PATH);
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(&config_path, "version = 1\n").unwrap();

        let report = uninstall(UninstallOptions { root: root.clone() }).unwrap();

        assert_eq!(report.preserved_config_path, config_path);
        assert!(report.removed_paths.len() >= 3);
        assert!(!join_root(&root, INSTALL_BIN_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_OBJECT_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_SCRIPT_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_CONFIG_RELATIVE_PATH).exists());
    }
}
