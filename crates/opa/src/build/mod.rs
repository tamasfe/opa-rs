use anyhow::anyhow;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
use which::which;

pub fn policy(name: impl Into<String>) -> WasmPolicyBuilder {
    WasmPolicyBuilder::new(name)
}

pub struct WasmPolicyBuilder {
    name: String,
    paths: Vec<String>,
    entrypoints: Vec<String>,
}

impl WasmPolicyBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            paths: Vec::default(),
            entrypoints: Vec::default(),
        }
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

    /// Compile the given policy and build the bundle with `opa`.
    ///
    /// # Errors
    ///
    /// The `opa` binary must be found in any of the system paths.
    #[allow(clippy::missing_panics_doc)]
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
            "-O",
            "1",
            "-o",
            output_file_path.to_str().unwrap(),
        ]);

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
            let o = String::from_utf8(out.stdout).unwrap();
            return Err(anyhow!("opa error: {o}"));
        }

        Ok(())
    }
}
