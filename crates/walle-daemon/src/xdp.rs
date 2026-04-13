use std::path::{Path, PathBuf};

use thiserror::Error;
use tracing::{debug, info};
use walle_common::{DEFAULT_MAP_PIN_PATH, XDP_PROGRAM_NAME};

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "linux")]
use aya::{
    Ebpf, EbpfError, EbpfLoader,
    programs::{ProgramError, Xdp, XdpFlags},
};

pub struct XdpAttachment {
    interface: String,
    object_path: PathBuf,
    map_pin_path: PathBuf,
    #[cfg(target_os = "linux")]
    _ebpf: Ebpf,
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

    let object_path = object_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_object_path);
    let map_pin_path = map_pin_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_map_pin_path);

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
        attach_linux(interface, object_path, map_pin_path).map(Some)
    }
}

#[must_use]
pub fn default_object_path() -> PathBuf {
    workspace_root().join("target/bpfel-unknown-none/release/walle-ebpf")
}

#[must_use]
pub fn default_map_pin_path() -> PathBuf {
    PathBuf::from(DEFAULT_MAP_PIN_PATH)
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
        _ebpf: ebpf,
    })
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
    #[cfg(not(target_os = "linux"))]
    #[error("XDP attachment is only supported on Linux hosts")]
    UnsupportedHost,
}

#[cfg(test)]
mod tests {
    use super::{default_object_path, maybe_attach};

    #[test]
    fn default_object_path_points_to_workspace_target() {
        let path = default_object_path();
        assert!(path.ends_with("target/bpfel-unknown-none/release/walle-ebpf"));
    }

    #[test]
    fn maybe_attach_skips_when_interface_is_missing() {
        assert!(matches!(maybe_attach(None, None, None), Ok(None)));
    }
}
