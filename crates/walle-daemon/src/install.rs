use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use similar::TextDiff;
use crate::ssh_overlay::{
    render_nsswitch_config_fragment, render_pam_config_fragment, render_sshd_config_fragment,
    render_trap_login_shell_wrapper,
};
use crate::xdp::{bundled_object_path, default_object_path};
use thiserror::Error;

const INSTALL_BIN_RELATIVE_PATH: &str = "usr/local/bin/walle";
const INSTALL_OBJECT_RELATIVE_PATH: &str = "usr/local/lib/walle/walle-ebpf";
const INSTALL_NSS_MODULE_RELATIVE_PATH: &str = "lib/libnss_walle.so.2";
const INSTALL_PAM_MODULE_RELATIVE_PATH: &str = "usr/local/lib/walle/pam_walle.so";
const INSTALL_SSH_OVERLAY_SAMPLE_RELATIVE_PATH: &str =
    "usr/local/lib/walle/walle-ssh-overlay.conf.sample";
const INSTALL_NSS_OVERLAY_SAMPLE_RELATIVE_PATH: &str =
    "usr/local/lib/walle/walle-nsswitch.conf.sample";
const INSTALL_PAM_OVERLAY_SAMPLE_RELATIVE_PATH: &str =
    "usr/local/lib/walle/walle-sshd-pam.conf.sample";
const INSTALL_TRAP_LOGIN_SHELL_RELATIVE_PATH: &str = "usr/local/lib/walle/walle-ssh-overlay-shell";
const INSTALL_SCRIPT_RELATIVE_PATH: &str = "usr/local/lib/walle/walle-run.sh";
const INSTALL_UNIT_RELATIVE_PATH: &str = "etc/systemd/system/walle.service";
const INSTALL_CONFIG_RELATIVE_PATH: &str = "etc/walle/config.toml";
const SSH_OVERLAY_HOOK_BACKUP_DIR_RELATIVE_PATH: &str = "etc/walle/ssh-overlay-hooks";
const SSHD_CONFIG_RELATIVE_PATH: &str = "etc/ssh/sshd_config";
const NSSWITCH_CONFIG_RELATIVE_PATH: &str = "etc/nsswitch.conf";
const SSHD_PAM_CONFIG_RELATIVE_PATH: &str = "etc/pam.d/sshd";
const NSS_MODULE_FILENAME: &str = "libnss_walle.so.2";
const NSS_MODULE_BUILD_ARTIFACT: &str = "libnss_walle.so";
const PAM_MODULE_FILENAME: &str = "pam_walle.so";
const PAM_MODULE_BUILD_ARTIFACT: &str = "libpam_walle.so";
const MANAGED_START_PREFIX: &str = "# managed by walle start ";
const MANAGED_END_PREFIX: &str = "# managed by walle end ";
const PRESERVED_ORIGINAL_PREFIX: &str = "# original by walle: ";
const SSHD_BLOCK_ID: &str = "sshd-authorized-keys";
const PAM_AUTH_BLOCK_ID: &str = "pam-auth";
const PAM_ACCOUNT_BLOCK_ID: &str = "pam-account";
const PAM_SESSION_BLOCK_ID: &str = "pam-session";
const NSS_PASSWD_BLOCK_ID: &str = "nsswitch-passwd";
const NSS_GROUP_BLOCK_ID: &str = "nsswitch-group";
const NSS_SHADOW_BLOCK_ID: &str = "nsswitch-shadow";
const NSS_INITGROUPS_BLOCK_ID: &str = "nsswitch-initgroups";

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshOverlayHookOptions {
    pub root: PathBuf,
}

impl Default for SshOverlayHookOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }
}

#[derive(Debug)]
pub struct SshOverlayHookPlan {
    pub preview: String,
    pub changed_paths: Vec<PathBuf>,
    pub backup_paths_to_create: Vec<PathBuf>,
    updates: Vec<PlannedFileUpdate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshOverlayHookApplyReport {
    pub changed_paths: Vec<PathBuf>,
    pub backup_paths_created: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshOverlayHookStatusEntry {
    pub path: PathBuf,
    pub present_block_ids: Vec<String>,
    pub expected_block_ids: Vec<String>,
    pub backup_path: PathBuf,
    pub backup_exists: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshOverlayHookStatusReport {
    pub entries: Vec<SshOverlayHookStatusEntry>,
}

#[derive(Clone, Debug)]
struct PlannedFileUpdate {
    path: PathBuf,
    original_content: String,
    updated_content: String,
    backup_path: PathBuf,
    ensure_backup: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookTargetKind {
    Sshd,
    Nsswitch,
    PamSshd,
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
    pub nss_module_path: PathBuf,
    pub pam_module_path: PathBuf,
    pub config_path: PathBuf,
    pub ssh_overlay_sample_path: PathBuf,
    pub nss_overlay_sample_path: PathBuf,
    pub pam_overlay_sample_path: PathBuf,
    pub trap_login_shell_path: PathBuf,
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
        let source_nss_module = resolve_nss_module(&current_executable)?;
        let source_pam_module = resolve_pam_module(&current_executable)?;
        install_with_sources(
            options,
            &current_executable,
            &source_object,
            &source_nss_module,
            &source_pam_module,
        )
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
            INSTALL_NSS_MODULE_RELATIVE_PATH,
            INSTALL_PAM_MODULE_RELATIVE_PATH,
            INSTALL_SSH_OVERLAY_SAMPLE_RELATIVE_PATH,
            INSTALL_NSS_OVERLAY_SAMPLE_RELATIVE_PATH,
            INSTALL_PAM_OVERLAY_SAMPLE_RELATIVE_PATH,
            INSTALL_TRAP_LOGIN_SHELL_RELATIVE_PATH,
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

pub fn plan_ssh_overlay_hook_install(
    options: SshOverlayHookOptions,
) -> Result<SshOverlayHookPlan, InstallError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(InstallError::UnsupportedHost)
    }

    #[cfg(target_os = "linux")]
    {
        ensure_install_privileges(&options.root)?;

        let hook_files = load_hook_files(&options.root)?;
        let mut updates = Vec::new();

        for hook_file in hook_files {
            let updated_content = render_install_hook_content(
                hook_file.kind,
                &hook_file.path,
                hook_file.contents.as_str(),
            )?;
            if updated_content != hook_file.contents {
                updates.push(PlannedFileUpdate {
                    path: hook_file.path.clone(),
                    original_content: hook_file.contents,
                    updated_content,
                    backup_path: hook_backup_path(&options.root, hook_file.kind),
                    ensure_backup: !hook_backup_path(&options.root, hook_file.kind).exists(),
                });
            }
        }

        Ok(build_hook_plan(updates))
    }
}

pub fn apply_ssh_overlay_hook_plan(
    plan: SshOverlayHookPlan,
) -> Result<SshOverlayHookApplyReport, InstallError> {
    apply_planned_file_updates(plan.updates)
}

pub fn ssh_overlay_hook_status(
    options: SshOverlayHookOptions,
) -> Result<SshOverlayHookStatusReport, InstallError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(InstallError::UnsupportedHost)
    }

    #[cfg(target_os = "linux")]
    {
        ensure_install_privileges(&options.root)?;
        let hook_files = load_hook_files(&options.root)?;
        let entries = hook_files
            .into_iter()
            .map(|hook_file| {
                let present_block_ids = collect_managed_block_ids(
                    hook_file.path.as_path(),
                    hook_file.contents.as_str(),
                )?;
                Ok(SshOverlayHookStatusEntry {
                    path: hook_file.path,
                    present_block_ids,
                    expected_block_ids: expected_block_ids(hook_file.kind)
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    backup_path: hook_backup_path(&options.root, hook_file.kind),
                    backup_exists: hook_backup_path(&options.root, hook_file.kind).exists(),
                })
            })
            .collect::<Result<Vec<_>, InstallError>>()?;

        Ok(SshOverlayHookStatusReport { entries })
    }
}

pub fn disable_ssh_overlay_hooks(
    options: SshOverlayHookOptions,
) -> Result<SshOverlayHookApplyReport, InstallError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(InstallError::UnsupportedHost)
    }

    #[cfg(target_os = "linux")]
    {
        ensure_install_privileges(&options.root)?;

        let hook_files = load_hook_files(&options.root)?;
        let mut updates = Vec::new();

        for hook_file in hook_files {
            let updated_content = render_disable_hook_content(
                hook_file.kind,
                &hook_file.path,
                hook_file.contents.as_str(),
            )?;
            if updated_content != hook_file.contents {
                updates.push(PlannedFileUpdate {
                    path: hook_file.path,
                    original_content: hook_file.contents,
                    updated_content,
                    backup_path: hook_backup_path(&options.root, hook_file.kind),
                    ensure_backup: false,
                });
            }
        }

        apply_planned_file_updates(updates)
    }
}

pub fn restore_ssh_overlay_hook_backup(
    options: SshOverlayHookOptions,
) -> Result<SshOverlayHookApplyReport, InstallError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(InstallError::UnsupportedHost)
    }

    #[cfg(target_os = "linux")]
    {
        ensure_install_privileges(&options.root)?;

        let hook_files = load_hook_files(&options.root)?;
        let mut updates = Vec::new();

        for hook_file in hook_files {
            let backup_path = hook_backup_path(&options.root, hook_file.kind);
            if !backup_path.exists() {
                return Err(InstallError::MissingHookBackup {
                    path: hook_file.path,
                    backup_path,
                });
            }

            let backup_content = read_file(&backup_path)?;
            if backup_content != hook_file.contents {
                updates.push(PlannedFileUpdate {
                    path: hook_file.path,
                    original_content: hook_file.contents,
                    updated_content: backup_content,
                    backup_path,
                    ensure_backup: false,
                });
            }
        }

        apply_planned_file_updates(updates)
    }
}

#[cfg(target_os = "linux")]
fn install_with_sources(
    options: InstallOptions,
    current_executable: &Path,
    source_object: &Path,
    source_nss_module: &Path,
    source_pam_module: &Path,
) -> Result<InstallReport, InstallError> {
    let binary_path = join_root(&options.root, INSTALL_BIN_RELATIVE_PATH);
    let object_path = join_root(&options.root, INSTALL_OBJECT_RELATIVE_PATH);
    let nss_module_path = join_root(&options.root, INSTALL_NSS_MODULE_RELATIVE_PATH);
    let pam_module_path = join_root(&options.root, INSTALL_PAM_MODULE_RELATIVE_PATH);
    let config_path = join_root(&options.root, INSTALL_CONFIG_RELATIVE_PATH);
    let ssh_overlay_sample_path =
        join_root(&options.root, INSTALL_SSH_OVERLAY_SAMPLE_RELATIVE_PATH);
    let nss_overlay_sample_path =
        join_root(&options.root, INSTALL_NSS_OVERLAY_SAMPLE_RELATIVE_PATH);
    let pam_overlay_sample_path =
        join_root(&options.root, INSTALL_PAM_OVERLAY_SAMPLE_RELATIVE_PATH);
    let trap_login_shell_path = join_root(&options.root, INSTALL_TRAP_LOGIN_SHELL_RELATIVE_PATH);
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
    copy_with_parents(source_nss_module, &nss_module_path)?;
    copy_with_parents(source_pam_module, &pam_module_path)?;
    make_executable(&binary_path)?;
    write_file(
        &ssh_overlay_sample_path,
        render_sshd_config_fragment(Path::new("/usr/local/bin/walle")).as_str(),
    )?;
    write_file(
        &nss_overlay_sample_path,
        render_nsswitch_config_fragment().as_str(),
    )?;
    write_file(
        &pam_overlay_sample_path,
        render_pam_config_fragment(Path::new("/usr/local/lib/walle/pam_walle.so")).as_str(),
    )?;
    write_file(
        &trap_login_shell_path,
        render_trap_login_shell_wrapper(Path::new("/usr/local/bin/walle")).as_str(),
    )?;
    make_executable(&trap_login_shell_path)?;

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
        nss_module_path,
        pam_module_path,
        config_path,
        ssh_overlay_sample_path,
        nss_overlay_sample_path,
        pam_overlay_sample_path,
        trap_login_shell_path,
        service_manager,
        service_path,
        config_created,
    })
}

struct HookFile {
    kind: HookTargetKind,
    path: PathBuf,
    contents: String,
}

fn load_hook_files(root: &Path) -> Result<Vec<HookFile>, InstallError> {
    let mut files = Vec::new();
    for kind in [
        HookTargetKind::Sshd,
        HookTargetKind::Nsswitch,
        HookTargetKind::PamSshd,
    ] {
        let path = hook_target_path(root, kind);
        files.push(HookFile {
            kind,
            contents: read_file(&path)?,
            path,
        });
    }
    Ok(files)
}

fn hook_target_path(root: &Path, kind: HookTargetKind) -> PathBuf {
    join_root(
        root,
        match kind {
            HookTargetKind::Sshd => SSHD_CONFIG_RELATIVE_PATH,
            HookTargetKind::Nsswitch => NSSWITCH_CONFIG_RELATIVE_PATH,
            HookTargetKind::PamSshd => SSHD_PAM_CONFIG_RELATIVE_PATH,
        },
    )
}

fn hook_backup_path(root: &Path, kind: HookTargetKind) -> PathBuf {
    let backup_dir = join_root(root, SSH_OVERLAY_HOOK_BACKUP_DIR_RELATIVE_PATH);
    join_root(
        backup_dir.as_path(),
        match kind {
            HookTargetKind::Sshd => "sshd_config.pre-walle",
            HookTargetKind::Nsswitch => "nsswitch.conf.pre-walle",
            HookTargetKind::PamSshd => "pam_sshd.pre-walle",
        },
    )
}

fn expected_block_ids(kind: HookTargetKind) -> Vec<&'static str> {
    match kind {
        HookTargetKind::Sshd => vec![SSHD_BLOCK_ID],
        HookTargetKind::Nsswitch => vec![
            NSS_PASSWD_BLOCK_ID,
            NSS_GROUP_BLOCK_ID,
            NSS_SHADOW_BLOCK_ID,
            NSS_INITGROUPS_BLOCK_ID,
        ],
        HookTargetKind::PamSshd => vec![
            PAM_AUTH_BLOCK_ID,
            PAM_ACCOUNT_BLOCK_ID,
            PAM_SESSION_BLOCK_ID,
        ],
    }
}

fn render_install_hook_content(
    kind: HookTargetKind,
    path: &Path,
    contents: &str,
) -> Result<String, InstallError> {
    match kind {
        HookTargetKind::Sshd => render_install_sshd_hook(path, contents),
        HookTargetKind::Nsswitch => render_install_nsswitch_hook(path, contents),
        HookTargetKind::PamSshd => render_install_pam_hook(path, contents),
    }
}

fn render_disable_hook_content(
    kind: HookTargetKind,
    path: &Path,
    contents: &str,
) -> Result<String, InstallError> {
    match kind {
        HookTargetKind::Sshd => remove_managed_blocks(path, contents, &[SSHD_BLOCK_ID]),
        HookTargetKind::PamSshd => remove_managed_blocks(
            path,
            contents,
            &[
                PAM_AUTH_BLOCK_ID,
                PAM_ACCOUNT_BLOCK_ID,
                PAM_SESSION_BLOCK_ID,
            ],
        ),
        HookTargetKind::Nsswitch => restore_nsswitch_original_lines(path, contents),
    }
}

fn render_install_sshd_hook(path: &Path, contents: &str) -> Result<String, InstallError> {
    let mut lines = to_lines(contents);
    let block = managed_block(
        SSHD_BLOCK_ID,
        render_sshd_config_fragment(Path::new("/usr/local/bin/walle")).trim_end(),
        None,
    );
    if replace_existing_block(path, &mut lines, SSHD_BLOCK_ID, &block)? {
        ensure_no_sshd_overlay_conflicts(path, &lines)?;
        return Ok(from_lines(&lines));
    }

    ensure_no_sshd_overlay_conflicts(path, &lines)?;
    let insert_index = lines
        .iter()
        .position(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("Match ")
        })
        .unwrap_or(lines.len());
    lines.splice(insert_index..insert_index, block);
    Ok(from_lines(&lines))
}

fn render_install_nsswitch_hook(path: &Path, contents: &str) -> Result<String, InstallError> {
    let mut lines = to_lines(contents);
    let group_fallback_tokens = active_nsswitch_sources(path, &lines, "group")?;

    for (block_id, key) in [
        (NSS_PASSWD_BLOCK_ID, "passwd"),
        (NSS_GROUP_BLOCK_ID, "group"),
        (NSS_SHADOW_BLOCK_ID, "shadow"),
        (NSS_INITGROUPS_BLOCK_ID, "initgroups"),
    ] {
        if let Some((start, end)) = find_managed_block_range(path, &lines, block_id)? {
            let original = parse_optional_preserved_original_line(&lines[start..end]);
            let desired_line = render_managed_nsswitch_line(
                path,
                key,
                original.as_deref().unwrap_or_else(|| match key {
                    "initgroups" => "initgroups: files",
                    _ => "",
                }),
                Some(group_fallback_tokens.as_slice()),
            )?;
            lines.splice(
                start..end,
                managed_block(block_id, desired_line.as_str(), original.as_deref()),
            );
            continue;
        }

        if let Some(line_index) = find_optional_active_setting_index(&lines, key) {
            let original_line = lines[line_index].clone();
            let desired_line = render_managed_nsswitch_line(
                path,
                key,
                original_line.as_str(),
                Some(group_fallback_tokens.as_slice()),
            )?;
            lines.splice(
                line_index..=line_index,
                managed_block(
                    block_id,
                    desired_line.as_str(),
                    Some(original_line.as_str()),
                ),
            );
            continue;
        }

        if key != "initgroups" {
            return Err(InstallError::HookConflict {
                path: path.to_path_buf(),
                message: format!("required active nsswitch entry '{key}:' was not found"),
            });
        }

        let desired_line = render_managed_nsswitch_line(
            path,
            key,
            "initgroups: files",
            Some(group_fallback_tokens.as_slice()),
        )?;
        let insert_index = find_initgroups_insert_index(path, &lines)?;
        lines.splice(
            insert_index..insert_index,
            managed_block(block_id, desired_line.as_str(), None),
        );
    }
    Ok(from_lines(&lines))
}

fn render_install_pam_hook(path: &Path, contents: &str) -> Result<String, InstallError> {
    let mut lines = to_lines(contents);
    ensure_no_manual_pam_overlay_conflicts(path, &lines)?;

    let auth_block = managed_block(
        PAM_AUTH_BLOCK_ID,
        format!(
            "auth    [success=done default=ignore] {}",
            Path::new("/usr/local/lib/walle/pam_walle.so").display()
        )
        .as_str(),
        None,
    );
    if !replace_existing_block(path, &mut lines, PAM_AUTH_BLOCK_ID, &auth_block)? {
        let index = find_exact_line_index(path, &lines, "@include common-auth")?;
        lines.splice(index..index, auth_block);
    }

    let account_block = managed_block(
        PAM_ACCOUNT_BLOCK_ID,
        format!(
            "account [success=done default=ignore] {}",
            Path::new("/usr/local/lib/walle/pam_walle.so").display()
        )
        .as_str(),
        None,
    );
    if !replace_existing_block(path, &mut lines, PAM_ACCOUNT_BLOCK_ID, &account_block)? {
        let before_index = find_line_containing(path, &lines, "pam_nologin.so")?;
        let after_index = find_exact_line_index(path, &lines, "@include common-account")?;
        if before_index >= after_index {
            return Err(InstallError::HookConflict {
                path: path.to_path_buf(),
                message: "expected pam_nologin.so before @include common-account".to_string(),
            });
        }
        lines.splice(before_index + 1..before_index + 1, account_block);
    }

    let session_block = managed_block(
        PAM_SESSION_BLOCK_ID,
        format!(
            "session [success=done default=ignore] {}",
            Path::new("/usr/local/lib/walle/pam_walle.so").display()
        )
        .as_str(),
        None,
    );
    if !replace_existing_block(path, &mut lines, PAM_SESSION_BLOCK_ID, &session_block)? {
        let before_index = find_line_containing(path, &lines, "pam_keyinit.so")?;
        let after_index = find_exact_line_index(path, &lines, "@include common-session")?;
        if before_index >= after_index {
            return Err(InstallError::HookConflict {
                path: path.to_path_buf(),
                message: "expected pam_keyinit.so before @include common-session".to_string(),
            });
        }
        lines.splice(before_index + 1..before_index + 1, session_block);
    }

    Ok(from_lines(&lines))
}

fn build_hook_plan(updates: Vec<PlannedFileUpdate>) -> SshOverlayHookPlan {
    let mut preview = String::new();
    let mut changed_paths = Vec::new();
    let mut backup_paths_to_create = Vec::new();

    for update in &updates {
        changed_paths.push(update.path.clone());
        if update.ensure_backup {
            backup_paths_to_create.push(update.backup_path.clone());
        }
        if !preview.is_empty() {
            preview.push('\n');
        }
        preview.push_str(
            render_unified_diff(
                update.path.as_path(),
                update.original_content.as_str(),
                update.updated_content.as_str(),
            )
            .as_str(),
        );
    }

    SshOverlayHookPlan {
        preview,
        changed_paths,
        backup_paths_to_create,
        updates,
    }
}

fn apply_planned_file_updates(
    updates: Vec<PlannedFileUpdate>,
) -> Result<SshOverlayHookApplyReport, InstallError> {
    let mut backup_paths_created = Vec::new();

    for update in &updates {
        let current = read_file(&update.path)?;
        if current != update.original_content {
            return Err(InstallError::HookChangedDuringConfirmation {
                path: update.path.clone(),
            });
        }
    }

    for update in &updates {
        if update.ensure_backup && !update.backup_path.exists() {
            write_file(
                update.backup_path.as_path(),
                update.original_content.as_str(),
            )?;
            backup_paths_created.push(update.backup_path.clone());
        }
    }

    let mut applied: Vec<PlannedFileUpdate> = Vec::new();
    for update in &updates {
        if let Err(error) =
            atomic_write_file(update.path.as_path(), update.updated_content.as_str())
        {
            for previous in applied.into_iter().rev() {
                let _ =
                    atomic_write_file(previous.path.as_path(), previous.original_content.as_str());
            }
            return Err(error);
        }
        applied.push(update.clone());
    }

    Ok(SshOverlayHookApplyReport {
        changed_paths: updates.into_iter().map(|update| update.path).collect(),
        backup_paths_created,
    })
}

fn ensure_no_sshd_overlay_conflicts(path: &Path, lines: &[String]) -> Result<(), InstallError> {
    let mut in_managed_block = false;
    for line in lines {
        if line.starts_with(MANAGED_START_PREFIX) {
            in_managed_block = true;
            continue;
        }
        if line.starts_with(MANAGED_END_PREFIX) {
            in_managed_block = false;
            continue;
        }
        if in_managed_block {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("AuthorizedKeysCommand ")
            || trimmed == "AuthorizedKeysCommand"
            || trimmed.starts_with("AuthorizedKeysCommandUser ")
            || trimmed == "AuthorizedKeysCommandUser"
        {
            return Err(InstallError::HookConflict {
                path: path.to_path_buf(),
                message: "existing AuthorizedKeysCommand settings must be removed before Walle can install hooks".to_string(),
            });
        }
    }
    Ok(())
}

fn ensure_no_manual_pam_overlay_conflicts(
    path: &Path,
    lines: &[String],
) -> Result<(), InstallError> {
    let mut in_managed_block = false;
    for line in lines {
        if line.starts_with(MANAGED_START_PREFIX) {
            in_managed_block = true;
            continue;
        }
        if line.starts_with(MANAGED_END_PREFIX) {
            in_managed_block = false;
            continue;
        }
        if in_managed_block {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains("/usr/local/lib/walle/pam_walle.so") {
            return Err(InstallError::HookConflict {
                path: path.to_path_buf(),
                message: "existing pam_walle.so directives must be removed before Walle can install managed PAM hooks".to_string(),
            });
        }
    }
    Ok(())
}

fn find_exact_line_index(
    path: &Path,
    lines: &[String],
    needle: &str,
) -> Result<usize, InstallError> {
    lines
        .iter()
        .position(|line| line.trim() == needle)
        .ok_or_else(|| InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!("required anchor '{needle}' was not found"),
        })
}

fn find_line_containing(
    path: &Path,
    lines: &[String],
    needle: &str,
) -> Result<usize, InstallError> {
    lines
        .iter()
        .position(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with('#') && trimmed.contains(needle)
        })
        .ok_or_else(|| InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!("required anchor containing '{needle}' was not found"),
        })
}

fn find_optional_active_setting_index(lines: &[String], key: &str) -> Option<usize> {
    let mut matches = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim();
            !trimmed.starts_with('#') && trimmed.starts_with(format!("{key}:").as_str())
        })
        .map(|(index, _)| index);
    let index = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(index)
}

fn find_unique_active_setting_index(
    path: &Path,
    lines: &[String],
    key: &str,
) -> Result<usize, InstallError> {
    let Some(index) = find_optional_active_setting_index(lines, key) else {
        return Err(InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!("required active nsswitch entry '{key}:' was not found"),
        });
    };
    let duplicates = lines
        .iter()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with('#') && trimmed.starts_with(format!("{key}:").as_str())
        })
        .count();
    if duplicates > 1 {
        return Err(InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!("expected exactly one active '{key}:' entry before installing hooks"),
        });
    }
    Ok(index)
}

fn restore_nsswitch_original_lines(path: &Path, contents: &str) -> Result<String, InstallError> {
    let mut lines = to_lines(contents);
    for block_id in [
        NSS_PASSWD_BLOCK_ID,
        NSS_GROUP_BLOCK_ID,
        NSS_SHADOW_BLOCK_ID,
        NSS_INITGROUPS_BLOCK_ID,
    ] {
        if let Some((start, end)) = find_managed_block_range(path, &lines, block_id)? {
            if let Some(original) = parse_optional_preserved_original_line(&lines[start..end]) {
                lines.splice(start..end, [original]);
            } else {
                lines.drain(start..end);
            }
        }
    }
    Ok(from_lines(&lines))
}

fn remove_managed_blocks(
    path: &Path,
    contents: &str,
    block_ids: &[&str],
) -> Result<String, InstallError> {
    let mut lines = to_lines(contents);
    for block_id in block_ids {
        if let Some((start, end)) = find_managed_block_range(path, &lines, block_id)? {
            lines.drain(start..end);
        }
    }
    Ok(from_lines(&lines))
}

fn replace_existing_block(
    path: &Path,
    lines: &mut Vec<String>,
    block_id: &str,
    replacement: &[String],
) -> Result<bool, InstallError> {
    if let Some((start, end)) = find_managed_block_range(path, lines, block_id)? {
        lines.splice(start..end, replacement.iter().cloned());
        Ok(true)
    } else {
        Ok(false)
    }
}

fn parse_optional_preserved_original_line(block_lines: &[String]) -> Option<String> {
    block_lines
        .iter()
        .find_map(|line| line.strip_prefix(PRESERVED_ORIGINAL_PREFIX))
        .map(str::to_string)
}

fn active_nsswitch_sources(
    path: &Path,
    lines: &[String],
    key: &str,
) -> Result<Vec<String>, InstallError> {
    let index = find_unique_active_setting_index(path, lines, key)?;
    parse_nsswitch_sources(path, key, lines[index].as_str())
}

fn parse_nsswitch_sources(path: &Path, key: &str, line: &str) -> Result<Vec<String>, InstallError> {
    let (line_key, rest) = line
        .split_once(':')
        .ok_or_else(|| InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!("invalid nsswitch line for '{key}': {line}"),
        })?;
    if line_key.trim() != key {
        return Err(InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!("expected '{key}:' entry but found '{line_key}:'"),
        });
    }
    let sources = rest
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if sources.is_empty() {
        return Err(InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!("nsswitch entry '{key}:' has no configured sources"),
        });
    }
    Ok(sources)
}

fn render_managed_nsswitch_line(
    path: &Path,
    key: &str,
    original_line: &str,
    group_fallback_sources: Option<&[String]>,
) -> Result<String, InstallError> {
    let mut sources = if key == "initgroups" && original_line.trim() == "initgroups: files" {
        group_fallback_sources
            .map(|value| value.to_vec())
            .unwrap_or_else(|| vec!["files".to_string()])
    } else {
        parse_nsswitch_sources(path, key, original_line)?
    };

    if sources.iter().any(|source| source == "walle") {
        return Err(InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!("nsswitch entry '{key}:' already contains unmanaged 'walle'"),
        });
    }
    let Some(files_index) = sources.iter().position(|source| source == "files") else {
        return Err(InstallError::HookConflict {
            path: path.to_path_buf(),
            message: format!(
                "nsswitch entry '{key}:' must contain 'files' before Walle can install hooks"
            ),
        });
    };
    sources.insert(files_index + 1, "walle".to_string());
    Ok(format!("{key}: {}", sources.join(" ")))
}

fn find_initgroups_insert_index(path: &Path, lines: &[String]) -> Result<usize, InstallError> {
    if let Some((_, end)) = find_managed_block_range(path, lines, NSS_GROUP_BLOCK_ID)? {
        return Ok(end);
    }
    Ok(find_unique_active_setting_index(path, lines, "group")? + 1)
}

fn find_managed_block_range(
    path: &Path,
    lines: &[String],
    block_id: &str,
) -> Result<Option<(usize, usize)>, InstallError> {
    let start_marker = format!("{MANAGED_START_PREFIX}{block_id}");
    let end_marker = format!("{MANAGED_END_PREFIX}{block_id}");
    let mut start = None;

    for (index, line) in lines.iter().enumerate() {
        if line == &start_marker {
            if start.is_some() {
                return Err(InstallError::InvalidHookManagedBlock {
                    path: path.to_path_buf(),
                    message: format!("managed block '{block_id}' has multiple start markers"),
                });
            }
            start = Some(index);
            continue;
        }
        if line == &end_marker {
            let Some(start_index) = start else {
                return Err(InstallError::InvalidHookManagedBlock {
                    path: path.to_path_buf(),
                    message: format!(
                        "managed block '{block_id}' has an end marker without a start marker"
                    ),
                });
            };
            return Ok(Some((start_index, index + 1)));
        }
    }

    if start.is_some() {
        return Err(InstallError::InvalidHookManagedBlock {
            path: path.to_path_buf(),
            message: format!("managed block '{block_id}' is missing an end marker"),
        });
    }

    Ok(None)
}

fn collect_managed_block_ids(path: &Path, contents: &str) -> Result<Vec<String>, InstallError> {
    let lines = to_lines(contents);
    let mut block_ids = Vec::new();
    for line in &lines {
        if let Some(block_id) = line.strip_prefix(MANAGED_START_PREFIX) {
            let block_id = block_id.trim().to_string();
            let _ = find_managed_block_range(path, &lines, block_id.as_str())?;
            block_ids.push(block_id);
        }
    }
    Ok(block_ids)
}

fn managed_block(block_id: &str, managed_content: &str, original: Option<&str>) -> Vec<String> {
    let mut lines = vec![format!("{MANAGED_START_PREFIX}{block_id}")];
    if let Some(original_line) = original {
        lines.push(format!("{PRESERVED_ORIGINAL_PREFIX}{original_line}"));
    }
    lines.extend(to_lines(managed_content));
    lines.push(format!("{MANAGED_END_PREFIX}{block_id}"));
    lines
}

fn to_lines(contents: &str) -> Vec<String> {
    contents.lines().map(str::to_string).collect()
}

fn from_lines(lines: &[String]) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        let mut rendered = lines.join("\n");
        rendered.push('\n');
        rendered
    }
}

fn render_unified_diff(path: &Path, before: &str, after: &str) -> String {
    const CONTEXT_LINES: usize = 10;

    let path_display = path.display().to_string();
    TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(CONTEXT_LINES)
        .header(path_display.as_str(), path_display.as_str())
        .missing_newline_hint(false)
        .to_string()
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
    let bundled = bundled_object_path(current_executable);
    let workspace_default = default_object_path();
    let mut searched = Vec::new();

    if let Some(path) = adjacent {
        searched.push(path.clone());
        if path.exists() {
            return Ok(path);
        }
    }

    if let Some(path) = bundled {
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
fn resolve_nss_module(current_executable: &Path) -> Result<PathBuf, InstallError> {
    let searched = nss_module_candidates(current_executable);
    searched
        .iter()
        .find(|path| path.exists())
        .cloned()
        .ok_or(InstallError::MissingNssModule { searched })
}

#[cfg(target_os = "linux")]
fn resolve_pam_module(current_executable: &Path) -> Result<PathBuf, InstallError> {
    let searched = pam_module_candidates(current_executable);
    searched
        .iter()
        .find(|path| path.exists())
        .cloned()
        .ok_or(InstallError::MissingPamModule { searched })
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

#[cfg(target_os = "linux")]
fn nss_module_candidates(current_executable: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(parent) = current_executable.parent() {
        push_unique(&mut candidates, parent.join(NSS_MODULE_FILENAME));
        push_unique(&mut candidates, parent.join(NSS_MODULE_BUILD_ARTIFACT));
    }

    if let Some(path) = bundled_nss_module_path(current_executable) {
        push_unique(&mut candidates, path);
    }

    let workspace_root = workspace_root();
    push_unique(
        &mut candidates,
        workspace_root.join(format!("target/release/{NSS_MODULE_BUILD_ARTIFACT}")),
    );
    push_unique(
        &mut candidates,
        workspace_root.join(format!("target/debug/{NSS_MODULE_BUILD_ARTIFACT}")),
    );

    candidates
}

#[cfg(target_os = "linux")]
fn pam_module_candidates(current_executable: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(parent) = current_executable.parent() {
        push_unique(&mut candidates, parent.join(PAM_MODULE_FILENAME));
        push_unique(&mut candidates, parent.join(PAM_MODULE_BUILD_ARTIFACT));
    }

    if let Some(path) = bundled_pam_module_path(current_executable) {
        push_unique(&mut candidates, path);
    }

    let workspace_root = workspace_root();
    push_unique(
        &mut candidates,
        workspace_root.join(format!("target/release/{PAM_MODULE_BUILD_ARTIFACT}")),
    );
    push_unique(
        &mut candidates,
        workspace_root.join(format!("target/debug/{PAM_MODULE_BUILD_ARTIFACT}")),
    );

    candidates
}

#[cfg(target_os = "linux")]
fn bundled_nss_module_path(current_executable: &Path) -> Option<PathBuf> {
    let executable_dir = current_executable.parent()?;
    if executable_dir.file_name().and_then(|name| name.to_str()) != Some("bin") {
        return None;
    }
    let bundle_root = executable_dir.parent()?;
    Some(bundle_root.join(format!("lib/{NSS_MODULE_FILENAME}")))
}

#[cfg(target_os = "linux")]
fn bundled_pam_module_path(current_executable: &Path) -> Option<PathBuf> {
    let executable_dir = current_executable.parent()?;
    if executable_dir.file_name().and_then(|name| name.to_str()) != Some("bin") {
        return None;
    }
    let bundle_root = executable_dir.parent()?;
    Some(bundle_root.join(format!("lib/walle/{PAM_MODULE_FILENAME}")))
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn push_unique(candidates: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !candidates.contains(&candidate) {
        candidates.push(candidate);
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

fn read_file(path: &Path) -> Result<String, InstallError> {
    fs::read_to_string(path).map_err(|source| InstallError::ReadFile {
        path: path.to_path_buf(),
        source,
    })
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

fn atomic_write_file(path: &Path, content: &str) -> Result<(), InstallError> {
    create_parent_dir(path)?;
    let parent = path.parent().ok_or_else(|| InstallError::WriteFile {
        path: path.to_path_buf(),
        source: std::io::Error::other("missing parent directory"),
    })?;
    let temp_path = parent.join(format!(
        ".{}.walle-tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::write(&temp_path, content).map_err(|source| InstallError::WriteFile {
        path: temp_path.clone(),
        source,
    })?;
    fs::rename(&temp_path, path).map_err(|source| InstallError::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
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
        "root_dir = \"/tmp/walle\"\n",
        "static_blacklist_keys_path = \"/etc/walle/blacklist_keys\"\n",
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
        "failed to find the eBPF object to install; searched: {}. build it with `cargo run -p xtask -- build-ebpf`, place `walle-ebpf` next to the binary or under `../lib/walle/walle-ebpf` relative to the binary, or pass `--xdp-object`",
        .searched
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )]
    MissingXdpObject { searched: Vec<PathBuf> },
    #[error(
        "failed to find the NSS identity-overlay module to install; searched: {}. build it with `cargo build -p walle-nss --release`, include `libnss_walle.so.2` in the release bundle under `lib/`, or rerun install from a workspace where `libnss_walle.so` was built",
        .searched
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )]
    MissingNssModule { searched: Vec<PathBuf> },
    #[error(
        "failed to find the PAM trap module to install; searched: {}. build it with `cargo build -p walle-pam --release`, include `pam_walle.so` in the release bundle under `lib/walle/`, or rerun install from a workspace where `libpam_walle.so` was built",
        .searched
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )]
    MissingPamModule { searched: Vec<PathBuf> },
    #[error("failed to read '{path}': {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
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
    #[error("hook install conflict in '{path}': {message}")]
    HookConflict { path: PathBuf, message: String },
    #[error("invalid managed hook block in '{path}': {message}")]
    InvalidHookManagedBlock { path: PathBuf, message: String },
    #[error("'{path}' changed after preview confirmation; rerun the hook command")]
    HookChangedDuringConfirmation { path: PathBuf },
    #[error("no hook backup exists for '{path}'; expected backup at '{backup_path}'")]
    MissingHookBackup { path: PathBuf, backup_path: PathBuf },
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        INSTALL_BIN_RELATIVE_PATH, INSTALL_CONFIG_RELATIVE_PATH, INSTALL_NSS_MODULE_RELATIVE_PATH,
        INSTALL_NSS_OVERLAY_SAMPLE_RELATIVE_PATH, INSTALL_OBJECT_RELATIVE_PATH,
        INSTALL_PAM_MODULE_RELATIVE_PATH, INSTALL_PAM_OVERLAY_SAMPLE_RELATIVE_PATH,
        INSTALL_SCRIPT_RELATIVE_PATH, INSTALL_SSH_OVERLAY_SAMPLE_RELATIVE_PATH,
        INSTALL_TRAP_LOGIN_SHELL_RELATIVE_PATH, INSTALL_UNIT_RELATIVE_PATH, InstallError,
        InstallOptions, NSSWITCH_CONFIG_RELATIVE_PATH, PAM_ACCOUNT_BLOCK_ID, PAM_AUTH_BLOCK_ID,
        PAM_SESSION_BLOCK_ID, SSHD_BLOCK_ID, SSHD_CONFIG_RELATIVE_PATH,
        SSHD_PAM_CONFIG_RELATIVE_PATH, ServiceManager, SshOverlayHookOptions, UninstallOptions,
        apply_ssh_overlay_hook_plan, bundled_nss_module_path, bundled_pam_module_path,
        default_config_template, disable_ssh_overlay_hooks, hook_backup_path, hook_target_path,
        install_with_sources, join_root, plan_ssh_overlay_hook_install, resolve_nss_module,
        resolve_pam_module, resolve_xdp_object, restore_ssh_overlay_hook_backup,
        ssh_overlay_hook_status, uninstall,
    };
    use crate::xdp::bundled_object_path;

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
        let nss_module = source_dir.join("libnss_walle.so.2");
        let pam_module = source_dir.join("pam_walle.so");
        std::fs::write(&current_executable, "bin").unwrap();
        std::fs::write(&xdp_object, "obj").unwrap();
        std::fs::write(&nss_module, "nss").unwrap();
        std::fs::write(&pam_module, "pam").unwrap();

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
            &nss_module,
            &pam_module,
        )
        .unwrap();

        assert_eq!(report.service_manager, ServiceManager::Systemd);
        assert!(!report.config_created);
        assert!(join_root(&root, INSTALL_BIN_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_OBJECT_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_NSS_MODULE_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_PAM_MODULE_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_SSH_OVERLAY_SAMPLE_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_NSS_OVERLAY_SAMPLE_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_PAM_OVERLAY_SAMPLE_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_TRAP_LOGIN_SHELL_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_UNIT_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_SCRIPT_RELATIVE_PATH).exists());
        assert!(std::fs::read_to_string(join_root(&root, INSTALL_UNIT_RELATIVE_PATH))
            .unwrap()
            .contains("ExecStart=/usr/local/bin/walle run --xdp-object /usr/local/lib/walle/walle-ebpf"));
        assert!(
            std::fs::read_to_string(join_root(&root, INSTALL_SSH_OVERLAY_SAMPLE_RELATIVE_PATH))
                .unwrap()
                .contains("AuthorizedKeysCommand /usr/local/bin/walle ssh overlay authorized-keys")
        );
        assert!(
            std::fs::read_to_string(join_root(&root, INSTALL_NSS_OVERLAY_SAMPLE_RELATIVE_PATH))
                .unwrap()
                .contains("passwd: files walle systemd")
        );
        assert!(
            std::fs::read_to_string(join_root(&root, INSTALL_PAM_OVERLAY_SAMPLE_RELATIVE_PATH))
                .unwrap()
                .contains(
                    "auth    [success=done default=ignore] /usr/local/lib/walle/pam_walle.so"
                )
        );
        assert!(
            std::fs::read_to_string(join_root(&root, INSTALL_TRAP_LOGIN_SHELL_RELATIVE_PATH))
                .unwrap()
                .contains("exec /usr/local/bin/walle ssh overlay trap-login")
        );
    }

    #[test]
    fn bundled_object_path_resolves_from_bin_layout() {
        let current_executable = PathBuf::from("/tmp/walle-release/bin/walle");
        let bundled = bundled_object_path(&current_executable).unwrap();
        assert_eq!(
            bundled,
            PathBuf::from("/tmp/walle-release/lib/walle/walle-ebpf")
        );
    }

    #[test]
    fn bundled_nss_module_path_resolves_from_bin_layout() {
        let current_executable = PathBuf::from("/tmp/walle-release/bin/walle");
        let bundled = bundled_nss_module_path(&current_executable).unwrap();
        assert_eq!(
            bundled,
            PathBuf::from("/tmp/walle-release/lib/libnss_walle.so.2")
        );
    }

    #[test]
    fn bundled_pam_module_path_resolves_from_bin_layout() {
        let current_executable = PathBuf::from("/tmp/walle-release/bin/walle");
        let bundled = bundled_pam_module_path(&current_executable).unwrap();
        assert_eq!(
            bundled,
            PathBuf::from("/tmp/walle-release/lib/walle/pam_walle.so")
        );
    }

    #[test]
    fn resolve_xdp_object_uses_bundle_layout_relative_to_bin() {
        let root = temp_root("install-bundle-lookup");
        let bin_dir = root.join("bin");
        let lib_dir = root.join("lib/walle");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&lib_dir).unwrap();

        let current_executable = bin_dir.join("walle");
        let bundled_object = lib_dir.join("walle-ebpf");
        std::fs::write(&current_executable, "bin").unwrap();
        std::fs::write(&bundled_object, "obj").unwrap();

        let resolved = resolve_xdp_object(None, &current_executable).unwrap();
        assert_eq!(resolved, bundled_object);
    }

    #[test]
    fn resolve_nss_module_uses_bundle_layout_relative_to_bin() {
        let root = temp_root("install-nss-bundle-lookup");
        let bin_dir = root.join("bin");
        let lib_dir = root.join("lib");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&lib_dir).unwrap();

        let current_executable = bin_dir.join("walle");
        let bundled_nss_module = lib_dir.join("libnss_walle.so.2");
        std::fs::write(&current_executable, "bin").unwrap();
        std::fs::write(&bundled_nss_module, "nss").unwrap();

        let resolved = resolve_nss_module(&current_executable).unwrap();
        assert_eq!(resolved, bundled_nss_module);
    }

    #[test]
    fn resolve_pam_module_uses_bundle_layout_relative_to_bin() {
        let root = temp_root("install-pam-bundle-lookup");
        let bin_dir = root.join("bin");
        let lib_dir = root.join("lib/walle");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&lib_dir).unwrap();

        let current_executable = bin_dir.join("walle");
        let bundled_pam_module = lib_dir.join("pam_walle.so");
        std::fs::write(&current_executable, "bin").unwrap();
        std::fs::write(&bundled_pam_module, "pam").unwrap();

        let resolved = resolve_pam_module(&current_executable).unwrap();
        assert_eq!(resolved, bundled_pam_module);
    }

    #[test]
    fn resolve_pam_module_accepts_workspace_build_artifact_name() {
        let root = temp_root("install-pam-workspace-lookup");
        let current_executable = root.join("walle");
        std::fs::write(&current_executable, "bin").unwrap();

        let release_artifact = super::workspace_root().join("target/release/libpam_walle.so");
        let debug_artifact = super::workspace_root().join("target/debug/libpam_walle.so");
        std::fs::create_dir_all(debug_artifact.parent().unwrap()).unwrap();
        let cleanup_needed = !debug_artifact.exists();
        if cleanup_needed {
            std::fs::write(&debug_artifact, "pam").unwrap();
        }

        let resolved = resolve_pam_module(&current_executable).unwrap();
        let expected = if release_artifact.exists() {
            release_artifact
        } else {
            debug_artifact.clone()
        };
        assert_eq!(resolved, expected);

        if cleanup_needed {
            let _ = std::fs::remove_file(&debug_artifact);
        }
    }

    #[test]
    fn uninstall_removes_managed_artifacts_but_preserves_config() {
        let root = temp_root("uninstall");
        for relative_path in [
            INSTALL_BIN_RELATIVE_PATH,
            INSTALL_OBJECT_RELATIVE_PATH,
            INSTALL_NSS_MODULE_RELATIVE_PATH,
            INSTALL_PAM_MODULE_RELATIVE_PATH,
            INSTALL_SSH_OVERLAY_SAMPLE_RELATIVE_PATH,
            INSTALL_NSS_OVERLAY_SAMPLE_RELATIVE_PATH,
            INSTALL_PAM_OVERLAY_SAMPLE_RELATIVE_PATH,
            INSTALL_TRAP_LOGIN_SHELL_RELATIVE_PATH,
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
        assert!(!join_root(&root, INSTALL_NSS_MODULE_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_PAM_MODULE_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_SSH_OVERLAY_SAMPLE_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_NSS_OVERLAY_SAMPLE_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_PAM_OVERLAY_SAMPLE_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_TRAP_LOGIN_SHELL_RELATIVE_PATH).exists());
        assert!(!join_root(&root, INSTALL_SCRIPT_RELATIVE_PATH).exists());
        assert!(join_root(&root, INSTALL_CONFIG_RELATIVE_PATH).exists());
    }

    fn write_hook_target_files(root: &Path) {
        let sshd_path = hook_target_path(root, super::HookTargetKind::Sshd);
        let nsswitch_path = hook_target_path(root, super::HookTargetKind::Nsswitch);
        let pam_path = hook_target_path(root, super::HookTargetKind::PamSshd);

        std::fs::create_dir_all(sshd_path.parent().unwrap()).unwrap();
        std::fs::write(
            &sshd_path,
            "Port 22\nUsePAM yes\nMatch User deploy\n    X11Forwarding no\n",
        )
        .unwrap();

        std::fs::create_dir_all(nsswitch_path.parent().unwrap()).unwrap();
        std::fs::write(
            &nsswitch_path,
            "passwd:         files systemd\ngroup:          files systemd\nshadow:         files systemd\ngshadow:        files systemd\n\nhosts:          files dns\n",
        )
        .unwrap();

        std::fs::create_dir_all(pam_path.parent().unwrap()).unwrap();
        std::fs::write(
            &pam_path,
            "auth requisite pam_nologin.so\n@include common-auth\naccount requisite pam_nologin.so\n@include common-account\nsession required pam_keyinit.so force revoke\n@include common-session\n",
        )
        .unwrap();
    }

    #[test]
    fn ssh_overlay_hook_plan_applies_and_creates_backups() {
        let root = temp_root("overlay-hook-install");
        write_hook_target_files(&root);

        let plan =
            plan_ssh_overlay_hook_install(SshOverlayHookOptions { root: root.clone() }).unwrap();
        assert_eq!(plan.changed_paths.len(), 3);
        assert!(plan.preview.contains("--- "));
        assert!(plan.preview.contains("+++ "));
        assert!(
            plan.preview
                .contains("AuthorizedKeysCommand /usr/local/bin/walle ssh overlay authorized-keys")
        );

        let report = apply_ssh_overlay_hook_plan(plan).unwrap();
        assert_eq!(report.changed_paths.len(), 3);
        assert_eq!(report.backup_paths_created.len(), 3);

        let sshd = std::fs::read_to_string(join_root(&root, SSHD_CONFIG_RELATIVE_PATH)).unwrap();
        assert!(sshd.contains("# managed by walle start sshd-authorized-keys"));
        assert!(sshd.contains("AuthorizedKeysCommandUser root"));
        assert!(
            sshd.find("AuthorizedKeysCommand").unwrap() < sshd.find("Match User deploy").unwrap()
        );

        let nsswitch =
            std::fs::read_to_string(join_root(&root, NSSWITCH_CONFIG_RELATIVE_PATH)).unwrap();
        assert!(nsswitch.contains("# managed by walle start nsswitch-passwd"));
        assert!(nsswitch.contains("# original by walle: passwd:         files systemd"));
        assert!(nsswitch.contains("passwd: files walle systemd"));
        assert!(nsswitch.contains("shadow: files walle systemd"));
        assert!(nsswitch.contains("# managed by walle start nsswitch-initgroups"));
        assert!(nsswitch.contains("initgroups: files walle systemd"));

        let pam = std::fs::read_to_string(join_root(&root, SSHD_PAM_CONFIG_RELATIVE_PATH)).unwrap();
        assert!(pam.contains("# managed by walle start pam-auth"));
        assert!(pam.contains("# managed by walle start pam-account"));
        assert!(pam.contains("# managed by walle start pam-session"));

        for kind in [
            super::HookTargetKind::Sshd,
            super::HookTargetKind::Nsswitch,
            super::HookTargetKind::PamSshd,
        ] {
            assert!(hook_backup_path(&root, kind).exists());
        }
    }

    #[test]
    fn ssh_overlay_hook_disable_restores_original_nsswitch_and_removes_blocks() {
        let root = temp_root("overlay-hook-disable");
        write_hook_target_files(&root);
        let plan =
            plan_ssh_overlay_hook_install(SshOverlayHookOptions { root: root.clone() }).unwrap();
        apply_ssh_overlay_hook_plan(plan).unwrap();

        let report =
            disable_ssh_overlay_hooks(SshOverlayHookOptions { root: root.clone() }).unwrap();
        assert_eq!(report.changed_paths.len(), 3);

        let sshd = std::fs::read_to_string(join_root(&root, SSHD_CONFIG_RELATIVE_PATH)).unwrap();
        assert!(!sshd.contains(SSHD_BLOCK_ID));
        assert!(!sshd.contains("AuthorizedKeysCommand "));

        let nsswitch =
            std::fs::read_to_string(join_root(&root, NSSWITCH_CONFIG_RELATIVE_PATH)).unwrap();
        assert!(nsswitch.contains("passwd:         files systemd"));
        assert!(nsswitch.contains("group:          files systemd"));
        assert!(nsswitch.contains("shadow:         files systemd"));
        assert!(!nsswitch.contains("initgroups:"));
        assert!(!nsswitch.contains("managed by walle"));

        let pam = std::fs::read_to_string(join_root(&root, SSHD_PAM_CONFIG_RELATIVE_PATH)).unwrap();
        assert!(!pam.contains(PAM_AUTH_BLOCK_ID));
        assert!(!pam.contains(PAM_ACCOUNT_BLOCK_ID));
        assert!(!pam.contains(PAM_SESSION_BLOCK_ID));
        assert!(!pam.contains("/usr/local/lib/walle/pam_walle.so"));
    }

    #[test]
    fn ssh_overlay_hook_restore_backup_restores_original_files() {
        let root = temp_root("overlay-hook-restore");
        write_hook_target_files(&root);
        let original_sshd =
            std::fs::read_to_string(join_root(&root, SSHD_CONFIG_RELATIVE_PATH)).unwrap();
        let original_nsswitch =
            std::fs::read_to_string(join_root(&root, NSSWITCH_CONFIG_RELATIVE_PATH)).unwrap();
        let original_pam =
            std::fs::read_to_string(join_root(&root, SSHD_PAM_CONFIG_RELATIVE_PATH)).unwrap();
        let plan =
            plan_ssh_overlay_hook_install(SshOverlayHookOptions { root: root.clone() }).unwrap();
        apply_ssh_overlay_hook_plan(plan).unwrap();

        let report =
            restore_ssh_overlay_hook_backup(SshOverlayHookOptions { root: root.clone() }).unwrap();
        assert_eq!(report.changed_paths.len(), 3);
        assert_eq!(
            std::fs::read_to_string(join_root(&root, SSHD_CONFIG_RELATIVE_PATH)).unwrap(),
            original_sshd
        );
        assert_eq!(
            std::fs::read_to_string(join_root(&root, NSSWITCH_CONFIG_RELATIVE_PATH)).unwrap(),
            original_nsswitch
        );
        assert_eq!(
            std::fs::read_to_string(join_root(&root, SSHD_PAM_CONFIG_RELATIVE_PATH)).unwrap(),
            original_pam
        );
    }

    #[test]
    fn ssh_overlay_hook_status_reports_expected_blocks_and_backups() {
        let root = temp_root("overlay-hook-status");
        write_hook_target_files(&root);
        let plan =
            plan_ssh_overlay_hook_install(SshOverlayHookOptions { root: root.clone() }).unwrap();
        apply_ssh_overlay_hook_plan(plan).unwrap();

        let status = ssh_overlay_hook_status(SshOverlayHookOptions { root: root.clone() }).unwrap();
        assert_eq!(status.entries.len(), 3);
        assert!(status.entries.iter().all(|entry| entry.backup_exists));
        assert!(
            status
                .entries
                .iter()
                .any(|entry| entry.present_block_ids.contains(&SSHD_BLOCK_ID.to_string()))
        );
        assert!(status.entries.iter().all(|entry| {
            entry
                .expected_block_ids
                .iter()
                .all(|id| entry.present_block_ids.contains(id))
        }));
    }

    #[test]
    fn ssh_overlay_hook_plan_fails_closed_on_existing_authorized_keys_command() {
        let root = temp_root("overlay-hook-conflict");
        write_hook_target_files(&root);
        let sshd_path = join_root(&root, SSHD_CONFIG_RELATIVE_PATH);
        std::fs::write(
            &sshd_path,
            "Port 22\nAuthorizedKeysCommand /usr/local/bin/custom\nUsePAM yes\n",
        )
        .unwrap();

        let error = plan_ssh_overlay_hook_install(SshOverlayHookOptions { root: root.clone() })
            .unwrap_err();
        match error {
            InstallError::HookConflict { path, .. } => assert_eq!(path, sshd_path),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn ssh_overlay_hook_apply_rejects_file_changes_after_preview() {
        let root = temp_root("overlay-hook-race");
        write_hook_target_files(&root);
        let plan =
            plan_ssh_overlay_hook_install(SshOverlayHookOptions { root: root.clone() }).unwrap();
        std::fs::write(
            join_root(&root, NSSWITCH_CONFIG_RELATIVE_PATH),
            "passwd: files alt\n",
        )
        .unwrap();

        let error = apply_ssh_overlay_hook_plan(plan).unwrap_err();
        match error {
            InstallError::HookChangedDuringConfirmation { path } => {
                assert_eq!(path, join_root(&root, NSSWITCH_CONFIG_RELATIVE_PATH))
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn unified_diff_preview_only_shows_changed_hunk_with_context() {
        let before = (1..=40)
            .map(|index| format!("alpha-{index:02}"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut after_lines = (1..=40)
            .map(|index| format!("alpha-{index:02}"))
            .collect::<Vec<_>>();
        after_lines[19] = "beta-20".to_string();
        let after = after_lines.join("\n") + "\n";

        let rendered =
            super::render_unified_diff(PathBuf::from("/tmp/example").as_path(), &before, &after);

        assert!(rendered.contains("--- /tmp/example"));
        assert!(rendered.contains("+++ /tmp/example"));
        assert!(rendered.contains("@@"));
        assert!(rendered.contains(" alpha-10"));
        assert!(rendered.contains("-alpha-20"));
        assert!(rendered.contains("+beta-20"));
        assert!(rendered.contains(" alpha-30"));
        assert!(!rendered.contains(" alpha-09"));
        assert!(!rendered.contains(" alpha-31"));
        assert!(!rendered.contains('\u{1b}'));
    }
}
