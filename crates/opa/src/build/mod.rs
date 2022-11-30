use anyhow::anyhow;
use std::{
    env, fs,
    io::Write,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Command,
};
use which::which;

use crate::bundle::Bundle;

pub fn policy(name: impl Into<String>) -> WasmPolicyBuilder {
    WasmPolicyBuilder::new(name)
}

/// Specify how the WASM module should be precompiled.
#[derive(Clone, Copy)]
pub enum AotMode {
    /// Use a `wasmtime` executable to compile the module.
    ///
    /// It needs to be installed and accessible in the path,
    /// moreover it should be the same version as `wasmtime`
    /// library.
    Executable,
    /// Build and use cranelift to compile the WASM module.
    #[cfg(feature = "wasmtime-cranelift")]
    Cranelift,
    /// Do not precompile WASM in the bundle.
    None,
}

impl Default for AotMode {
    fn default() -> Self {
        Self::None
    }
}

#[cfg(feature = "wasmtime-aot")]
#[derive(Default)]
struct WasmTimeAotOptions {
    mode: AotMode,
}

pub struct WasmPolicyBuilder {
    name: String,
    paths: Vec<String>,
    entrypoints: Vec<String>,
    opt_level: Option<NonZeroUsize>,
    #[cfg(feature = "wasmtime-aot")]
    aot: WasmTimeAotOptions,
}

impl WasmPolicyBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            paths: Vec::default(),
            entrypoints: Vec::default(),
            opt_level: None,
            #[cfg(feature = "wasmtime-aot")]
            aot: WasmTimeAotOptions::default(),
        }
    }

    /// Precompile the WASM module using an installed `wasmtime` executable.
    #[cfg(feature = "wasmtime-aot")]
    #[must_use]
    pub fn precompile_wasm(mut self, mode: AotMode) -> Self {
        self.aot.mode = mode;
        self
    }

    #[must_use]
    pub fn add_entrypoint(mut self, ep: impl Into<String>) -> Self {
        self.entrypoints.push(ep.into());
        self
    }

    #[must_use]
    pub fn add_entrypoints<S, I>(mut self, eps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entrypoints.extend(eps.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn add_source(mut self, path: impl Into<String>) -> Self {
        self.paths.push(path.into());
        self
    }

    #[must_use]
    pub fn add_sources<S, I>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.paths.extend(paths.into_iter().map(Into::into));
        self
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn opt_level(mut self, level: usize) -> Self {
        if level == 0 {
            self.opt_level = None;
        } else {
            self.opt_level = Some(level.try_into().unwrap());
        }

        self
    }

    /// Compile the given policy and build the bundle with `opa`.
    ///
    /// # Errors
    ///
    /// The `opa` binary must be found in any of the system paths.
    #[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
    pub fn compile(self) -> Result<(), anyhow::Error> {
        if self.paths.is_empty() {
            return Err(anyhow!("no sources provided"));
        }

        if self.entrypoints.is_empty() {
            return Err(anyhow!("no entrypoints provided"));
        }

        let opa_executable = which("opa")?;

        let root_dir = env::var("CARGO_MANIFEST_DIR")?;
        let out_dir = env::var("OUT_DIR")?;
        println!("cargo:rustc-env=OUT_DIR={out_dir}");
        let out_dir = Path::new(&out_dir).join("opa");

        let mut opa_cmd = Command::new(&opa_executable);

        let mut input_paths = Vec::new();

        for path in self.paths {
            let p = Path::new(&path);

            let input_file_path: PathBuf = if p.is_absolute() {
                p.into()
            } else {
                Path::new(&root_dir).join(p)
            };

            if input_file_path.is_dir() {
                for entry in walkdir::WalkDir::new(&input_file_path)
                    .into_iter()
                    .filter_map(Result::ok)
                {
                    if !entry.path().extension().map_or(false, |s| s == "rego") {
                        continue;
                    }
                    input_paths.push(entry.path().into());
                }
            } else {
                input_paths.push(input_file_path);
            }
        }

        for path in &mut input_paths {
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());

            if !path.extension().map_or(false, |s| s == "rego") {
                return Err(anyhow!("the policy file must have `.rego` extension"));
            }

            *path = path.canonicalize()?;
        }

        let output_file_name = self.name;
        let output_file_path = out_dir.join(&format!("{output_file_name}.tar.gz"));

        opa_cmd.args([
            "build",
            "-t",
            "wasm",
            "-o",
            output_file_path.to_str().unwrap(),
        ]);

        if let Some(opt) = self.opt_level {
            opa_cmd.arg("-O");
            opa_cmd.arg(opt.to_string());
        }

        for entrypoint in self.entrypoints {
            opa_cmd.arg("-e");
            opa_cmd.arg(&entrypoint.replace('.', "/"));
        }

        for input_path in input_paths {
            opa_cmd.arg(input_path.to_str().unwrap());
        }

        fs::create_dir_all(&out_dir)?;
        let out = opa_cmd.output()?;

        if !out.status.success() {
            let o = String::from_utf8_lossy(&out.stdout).to_string()
                + String::from_utf8_lossy(&out.stderr).as_ref();
            return Err(anyhow!("opa error: {o}"));
        }

        #[cfg(feature = "wasmtime-aot")]
        {
            let cwasm_output_path = out_dir.join(format!("{output_file_name}.cwasm"));

            match self.aot.mode {
                AotMode::Executable => {
                    let mut bundle = Bundle::from_file(&output_file_path).unwrap();

                    let mut f = tempfile::NamedTempFile::new().unwrap();

                    f.write_all(&bundle.wasm_policies.pop().unwrap().bytes)
                        .unwrap();

                    let p = f.into_temp_path();

                    let wasmtime_executable = which("wasmtime")?;

                    let mut wasmtime_cmd = Command::new(wasmtime_executable);

                    wasmtime_cmd.args([
                        "compile",
                        "-o",
                        cwasm_output_path.to_str().unwrap(),
                        p.to_str().unwrap(),
                    ]);

                    let out = wasmtime_cmd.output()?;

                    if !out.status.success() {
                        let o = String::from_utf8_lossy(&out.stdout).to_string()
                            + String::from_utf8_lossy(&out.stderr).as_ref();
                        return Err(anyhow!("wasmtime error: {o}"));
                    }
                }
                #[cfg(feature = "wasmtime-cranelift")]
                AotMode::Cranelift => {
                    let mut bundle = Bundle::from_file(&output_file_path)?;
                    let engine = wasmtime::Engine::new(
                        wasmtime::Config::default()
                            .cranelift_opt_level(wasmtime::OptLevel::SpeedAndSize),
                    )?;
                    let m = engine.precompile_module(&bundle.wasm_policies.pop().unwrap().bytes)?;
                    std::fs::write(cwasm_output_path, m)?;
                }
                AotMode::None => {
                    // Still create the file as the `include_policy!` macro expects it:
                    std::fs::File::create(cwasm_output_path).unwrap();
                }
            }
        }

        Ok(())
    }
}
