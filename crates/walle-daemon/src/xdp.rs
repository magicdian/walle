use std::path::{Path, PathBuf};

use thiserror::Error;
use tracing::{debug, info, warn};
use walle_common::{
    DEFAULT_MAP_PIN_PATH, MAP_NAME_ALLOW_V4, MAP_NAME_ALLOW_V6, MAP_NAME_CONFIG,
    MAP_NAME_CONTAIN_V4, MAP_NAME_CONTAIN_V6, MAP_NAME_DENY_V4, MAP_NAME_DENY_V6,
    MAP_NAME_ICMP_RULES, MAP_NAME_STATS, TC_EGRESS_PROGRAM_NAME, TC_INGRESS_PROGRAM_NAME,
    XDP_PROGRAM_NAME,
};

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "linux")]
use aya::{
    Ebpf, EbpfError, EbpfLoader,
    programs::{ProgramError, SchedClassifier, TcAttachType, Xdp, XdpFlags, tc},
};

pub struct XdpAttachment {
    interface: String,
    object_path: PathBuf,
    map_pin_path: PathBuf,
    #[cfg(target_os = "linux")]
    ebpf: Option<Ebpf>,
}

impl XdpAttachment {
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    #[must_use]
    pub fn object_path(&self) -> &Path {
        &self.object_path
    }

    #[must_use]
    pub fn map_pin_path(&self) -> &Path {
        &self.map_pin_path
    }

    #[cfg(target_os = "linux")]
    fn cleanup(&mut self) -> Result<(), XdpError> {
        if self.ebpf.take().is_none() {
            return Ok(());
        }

        reset_tc_programs(self.interface.as_str())?;
        reset_pinned_maps(self.map_pin_path.as_path())?;

        info!(
            component = "xdp",
            event = "detached",
            interface = self.interface.as_str(),
            map_pin_path = %self.map_pin_path.display(),
            "released managed XDP/tc programs and map pins"
        );

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for XdpAttachment {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            warn!(
                component = "xdp",
                event = "detach_failed",
                interface = self.interface.as_str(),
                error = %error,
                "failed to fully clean up managed XDP/tc state"
            );
        }
    }
}

pub fn attach(
    interface: &str,
    object_path: Option<&Path>,
    map_pin_path: Option<&Path>,
) -> Result<XdpAttachment, XdpError> {
    let object_path = object_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_object_path);
    let map_pin_path = map_pin_path_for_interface(interface, map_pin_path);

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface, object_path, map_pin_path);
        return Err(XdpError::UnsupportedHost);
    }

    if !object_path.exists() {
        return Err(XdpError::MissingObject { path: object_path });
    }

    #[cfg(target_os = "linux")]
    {
        attach_linux(interface, object_path, map_pin_path)
    }
}

pub fn maybe_attach(
    interface: Option<&str>,
    object_path: Option<&Path>,
    map_pin_path: Option<&Path>,
) -> Result<Option<XdpAttachment>, XdpError> {
    let Some(interface) = interface else {
        debug!(
            component = "xdp",
            event = "attach_skipped",
            reason = "no_interface",
            "skipping XDP attach because no interface was configured"
        );
        return Ok(None);
    };

    attach(interface, object_path, map_pin_path).map(Some)
}

#[must_use]
pub fn default_object_path() -> PathBuf {
    workspace_root().join("target/bpfel-unknown-none/release/walle-ebpf")
}

#[must_use]
pub fn default_map_pin_path() -> PathBuf {
    PathBuf::from(DEFAULT_MAP_PIN_PATH)
}

#[must_use]
pub fn map_pin_path_for_interface(interface: &str, map_pin_path: Option<&Path>) -> PathBuf {
    let base = map_pin_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_map_pin_path);
    base.join(interface)
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

#[cfg(target_os = "linux")]
fn attach_linux(
    interface: &str,
    object_path: PathBuf,
    map_pin_path: PathBuf,
) -> Result<XdpAttachment, XdpError> {
    fs::create_dir_all(&map_pin_path).map_err(|source| XdpError::CreatePinPath {
        path: map_pin_path.clone(),
        source,
    })?;
    reset_tc_programs(interface)?;
    reset_pinned_maps(&map_pin_path)?;

    let mut ebpf = EbpfLoader::new()
        .map_pin_path(&map_pin_path)
        .load_file(&object_path)
        .map_err(|source| XdpError::LoadObject {
            path: object_path.clone(),
            source,
        })?;

    let program = ebpf
        .program_mut(XDP_PROGRAM_NAME)
        .ok_or_else(|| XdpError::MissingProgram {
            program: XDP_PROGRAM_NAME,
            path: object_path.clone(),
        })?;
    let program: &mut Xdp = program
        .try_into()
        .map_err(|source| XdpError::ProgramAccess {
            program: XDP_PROGRAM_NAME,
            path: object_path.clone(),
            source,
        })?;

    program.load().map_err(|source| XdpError::ProgramLoad {
        program: XDP_PROGRAM_NAME,
        path: object_path.clone(),
        source,
    })?;
    program
        .attach(interface, XdpFlags::default())
        .map_err(|source| XdpError::ProgramAttach {
            program: XDP_PROGRAM_NAME,
            interface: interface.to_string(),
            source,
        })?;

    attach_tc_program(
        &mut ebpf,
        interface,
        object_path.as_path(),
        TC_INGRESS_PROGRAM_NAME,
        TcAttachType::Ingress,
    )?;
    attach_tc_program(
        &mut ebpf,
        interface,
        object_path.as_path(),
        TC_EGRESS_PROGRAM_NAME,
        TcAttachType::Egress,
    )?;

    info!(
        component = "xdp",
        event = "attached",
        interface,
        program = XDP_PROGRAM_NAME,
        object_path = %object_path.display(),
        map_pin_path = %map_pin_path.display(),
        "attached XDP program to interface"
    );

    Ok(XdpAttachment {
        interface: interface.to_string(),
        object_path,
        map_pin_path,
        ebpf: Some(ebpf),
    })
}

#[cfg(target_os = "linux")]
fn reset_pinned_maps(map_pin_path: &Path) -> Result<(), XdpError> {
    for map_name in [
        MAP_NAME_CONFIG,
        MAP_NAME_ALLOW_V4,
        MAP_NAME_ALLOW_V6,
        MAP_NAME_DENY_V4,
        MAP_NAME_DENY_V6,
        MAP_NAME_CONTAIN_V4,
        MAP_NAME_CONTAIN_V6,
        MAP_NAME_ICMP_RULES,
        MAP_NAME_STATS,
    ] {
        let pinned_path = map_pin_path.join(map_name);

        match fs::remove_file(&pinned_path) {
            Ok(()) => {
                debug!(
                    component = "xdp",
                    event = "stale_map_pin_removed",
                    map = map_name,
                    path = %pinned_path.display(),
                    "removed stale pinned map before loading the new object"
                );
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(XdpError::ResetPinnedMap {
                    path: pinned_path,
                    source,
                });
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn reset_tc_programs(interface: &str) -> Result<(), XdpError> {
    for (program_name, attach_type) in managed_tc_programs() {
        match tc::qdisc_detach_program(interface, attach_type, program_name) {
            Ok(()) => {
                info!(
                    component = "xdp",
                    event = "stale_tc_detached",
                    interface,
                    program = program_name,
                    attach_type = tc_attach_type_name(attach_type),
                    "detached stale tc classifier program before loading the new object"
                );
            }
            Err(source)
                if source.kind() == std::io::ErrorKind::NotFound
                    || source.raw_os_error() == Some(libc::ENODEV) => {}
            Err(source) => {
                return Err(XdpError::TcQdiscDetach {
                    interface: interface.to_string(),
                    program: program_name,
                    attach_type: tc_attach_type_name(attach_type),
                    source,
                });
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
const fn managed_tc_programs() -> [(&'static str, TcAttachType); 2] {
    [
        (TC_INGRESS_PROGRAM_NAME, TcAttachType::Ingress),
        (TC_EGRESS_PROGRAM_NAME, TcAttachType::Egress),
    ]
}

#[cfg(target_os = "linux")]
const fn tc_attach_type_name(attach_type: TcAttachType) -> &'static str {
    match attach_type {
        TcAttachType::Ingress => "ingress",
        TcAttachType::Egress => "egress",
        TcAttachType::Custom(_) => "custom",
    }
}

#[cfg(target_os = "linux")]
fn attach_tc_program(
    ebpf: &mut Ebpf,
    interface: &str,
    object_path: &Path,
    program_name: &'static str,
    attach_type: TcAttachType,
) -> Result<(), XdpError> {
    match tc::qdisc_add_clsact(interface) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(XdpError::TcQdiscAdd {
                interface: interface.to_string(),
                source,
            });
        }
    }

    let program = ebpf
        .program_mut(program_name)
        .ok_or_else(|| XdpError::MissingProgram {
            program: program_name,
            path: object_path.to_path_buf(),
        })?;
    let program: &mut SchedClassifier =
        program
            .try_into()
            .map_err(|source| XdpError::ProgramAccess {
                program: program_name,
                path: object_path.to_path_buf(),
                source,
            })?;

    program.load().map_err(|source| XdpError::ProgramLoad {
        program: program_name,
        path: object_path.to_path_buf(),
        source,
    })?;
    program
        .attach(interface, attach_type)
        .map_err(|source| XdpError::ProgramAttach {
            program: program_name,
            interface: interface.to_string(),
            source,
        })?;

    info!(
        component = "xdp",
        event = "tc_attached",
        interface,
        program = program_name,
        attach_type = tc_attach_type_name(attach_type),
        "attached tc classifier program to interface"
    );

    Ok(())
}

#[derive(Debug, Error)]
pub enum XdpError {
    #[error(
        "BPF object file '{path}' was not found; build it with `cargo run -p xtask -- build-ebpf` or pass `--xdp-object`"
    )]
    MissingObject { path: PathBuf },
    #[error("failed to create map pin directory '{path}': {source}")]
    CreatePinPath {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to reset pinned map '{path}': {source}")]
    ResetPinnedMap {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("failed to load eBPF object '{path}': {source}")]
    LoadObject { path: PathBuf, source: EbpfError },
    #[error("XDP program '{program}' is missing from object '{path}'")]
    MissingProgram {
        program: &'static str,
        path: PathBuf,
    },
    #[cfg(target_os = "linux")]
    #[error("failed to access XDP program '{program}' in '{path}': {source}")]
    ProgramAccess {
        program: &'static str,
        path: PathBuf,
        source: ProgramError,
    },
    #[cfg(target_os = "linux")]
    #[error("failed to load XDP program '{program}' from '{path}': {source}")]
    ProgramLoad {
        program: &'static str,
        path: PathBuf,
        source: ProgramError,
    },
    #[cfg(target_os = "linux")]
    #[error("failed to attach XDP program '{program}' to interface '{interface}': {source}")]
    ProgramAttach {
        program: &'static str,
        interface: String,
        source: ProgramError,
    },
    #[cfg(target_os = "linux")]
    #[error("failed to add clsact qdisc to interface '{interface}': {source}")]
    TcQdiscAdd {
        interface: String,
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error(
        "failed to detach stale tc program '{program}' ({attach_type}) from interface '{interface}': {source}"
    )]
    TcQdiscDetach {
        interface: String,
        program: &'static str,
        attach_type: &'static str,
        source: std::io::Error,
    },
    #[cfg(not(target_os = "linux"))]
    #[error("XDP attachment is only supported on Linux hosts")]
    UnsupportedHost,
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;
    use std::path::Path;
    #[cfg(target_os = "linux")]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(target_os = "linux")]
    use super::reset_pinned_maps;
    use super::{default_object_path, map_pin_path_for_interface, maybe_attach};
    #[cfg(target_os = "linux")]
    use walle_common::{
        MAP_NAME_ALLOW_V4, MAP_NAME_ALLOW_V6, MAP_NAME_CONFIG, MAP_NAME_CONTAIN_V4,
        MAP_NAME_CONTAIN_V6, MAP_NAME_DENY_V4, MAP_NAME_DENY_V6, MAP_NAME_ICMP_RULES,
        MAP_NAME_STATS,
    };

    #[test]
    fn default_object_path_points_to_workspace_target() {
        let path = default_object_path();
        assert!(path.ends_with("target/bpfel-unknown-none/release/walle-ebpf"));
    }

    #[test]
    fn map_pin_path_is_scoped_per_interface() {
        let path = map_pin_path_for_interface("eth0", Some(Path::new("/sys/fs/bpf/walle")));
        assert_eq!(path, Path::new("/sys/fs/bpf/walle/eth0"));
    }

    #[test]
    fn maybe_attach_skips_when_interface_is_missing() {
        assert!(matches!(maybe_attach(None, None, None), Ok(None)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reset_pinned_maps_removes_known_map_files() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let pin_dir = std::env::temp_dir().join(format!("walle-xdp-pins-{nanos}"));
        fs::create_dir_all(&pin_dir).expect("temporary map pin directory should be created");

        for map_name in [
            MAP_NAME_CONFIG,
            MAP_NAME_ALLOW_V4,
            MAP_NAME_ALLOW_V6,
            MAP_NAME_DENY_V4,
            MAP_NAME_DENY_V6,
            MAP_NAME_CONTAIN_V4,
            MAP_NAME_CONTAIN_V6,
            MAP_NAME_ICMP_RULES,
            MAP_NAME_STATS,
        ] {
            fs::write(pin_dir.join(map_name), b"pin").expect("test pin file should be created");
        }

        reset_pinned_maps(pin_dir.as_path()).expect("known map pins should be removed");

        for map_name in [
            MAP_NAME_CONFIG,
            MAP_NAME_ALLOW_V4,
            MAP_NAME_ALLOW_V6,
            MAP_NAME_DENY_V4,
            MAP_NAME_DENY_V6,
            MAP_NAME_CONTAIN_V4,
            MAP_NAME_CONTAIN_V6,
            MAP_NAME_ICMP_RULES,
            MAP_NAME_STATS,
        ] {
            assert!(
                !pin_dir.join(map_name).exists(),
                "expected map pin {map_name} to be removed"
            );
        }

        let _ = fs::remove_dir(&pin_dir);
    }
}
