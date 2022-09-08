use self::manifest::Manifest;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde_json::Value;
use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
};
use tar::Archive;
use thiserror::Error;

pub mod manifest;

/// An OPA bundle created by `opa build`.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// The manifest of the bundle, if any.
    pub manifest: Option<Manifest>,

    /// The OPA generated data that was bundled during build.
    pub data: Option<Value>,

    /// All `.rego` policy files with their respective paths within
    /// the bundle.
    pub rego_policies: HashMap<PathBuf, String>,

    /// All WASM module policies within the bundle.
    ///
    /// A WASM module policy should appear here
    /// only if it was listed in the manifest.
    pub wasm_policies: Vec<WasmPolicy>,

    #[cfg(feature = "wasmtime-aot")]
    pub(crate) wasmtime_bytes: Option<Bytes>,
}

impl Bundle {
    /// Load the bundle from a file.
    ///
    /// # Errors
    ///
    /// Errors are returned if the given bundle is invalid or
    /// the file operations fail.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let f = std::fs::File::open(path)?;
        Self::from_reader(f)
    }

    /// Load the bundle from the given bytes.
    ///
    /// Bundles are expected to be a `.tar.gz` format.
    ///
    /// # Errors
    ///
    /// Errors are returned if the bundle is invalid.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::from_reader(bytes.as_ref())
    }

    /// Load the bundle from the given reader.
    ///
    /// Bundles are expected to be a `.tar.gz` format.
    ///
    /// # Errors
    ///
    /// Errors are returned if the bundle is invalid or on i/o error.
    pub fn from_reader(reader: impl Read) -> Result<Self, Error> {
        let gz = GzDecoder::new(reader);
        let mut ar = Archive::new(gz);

        let mut manifest: Option<Manifest> = None;
        let mut data: Option<Value> = None;
        let mut rego_policies: HashMap<PathBuf, String> = HashMap::default();
        let mut wasm_policies: Vec<WasmPolicy> = Vec::new();

        let mut wasm_files: HashMap<PathBuf, Bytes> = HashMap::default();

        for entry in ar.entries()? {
            let mut entry = entry?;

            let path = entry.path()?;

            match path.to_str() {
                Some("/.manifest") => {
                    manifest = Some(serde_json::from_reader(entry).map_err(Error::InvalidData)?);
                }
                Some("/data.json") => {
                    data = Some(serde_json::from_reader(entry).map_err(Error::InvalidManifest)?);
                }
                Some(s) if has_ext(s, "rego") => {
                    let mut s = String::new();
                    let p = path.into_owned();
                    entry.read_to_string(&mut s)?;
                    rego_policies.insert(p, s);
                }
                Some(s) if has_ext(s, "wasm") => {
                    let mut s = Vec::new();
                    let p = path.into_owned();
                    entry.read_to_end(&mut s)?;
                    wasm_files.insert(p, s.into());
                }
                _ => {}
            }
        }

        if let Some(m) = &manifest {
            for wasm_manifest in &m.wasm {
                if let Some(b) = wasm_files.get(&wasm_manifest.module) {
                    wasm_policies.push(WasmPolicy {
                        entrypoint: wasm_manifest.entrypoint.clone(),
                        bytes: b.clone(),
                    });
                }
            }
        }

        Ok(Self {
            manifest,
            data,
            rego_policies,
            wasm_policies,
            #[cfg(feature = "wasmtime-aot")]
            wasmtime_bytes: None,
        })
    }

    // Set a precompiled WASM module for the bundle, intended
    // for precompiled bundles from the build script.
    //
    // [`wasmtime::Module::deserialize`]
    #[cfg(feature = "wasmtime-aot")]
    #[doc(hidden)]
    pub unsafe fn set_wasmtime_bytes(&mut self, bytes: Bytes) {
        self.wasmtime_bytes = Some(bytes);
    }
}

#[derive(Debug, Clone)]
pub struct WasmPolicy {
    pub entrypoint: String,
    pub bytes: Bytes,
}

fn has_ext(filename: &str, ext: &str) -> bool {
    filename
        .rsplit('.')
        .next()
        .map(|e| e.eq_ignore_ascii_case(ext))
        == Some(true)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid bundle: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid manifest: {0}")]
    InvalidManifest(serde_json::Error),
    #[error("invalid data file: {0}")]
    InvalidData(serde_json::Error),
}
