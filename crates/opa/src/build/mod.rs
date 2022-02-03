use anyhow::anyhow;
use std::{env, fs, path::Path, process::Command};
use which::which;

pub fn policy(path: impl Into<String>, name: impl Into<String>) -> WasmPolicyBuilder {
    WasmPolicyBuilder::new(path, name)
}

pub struct WasmPolicyBuilder {
    path: String,
    name: String,
    entrypoints: Vec<String>,
}

impl WasmPolicyBuilder {
    pub fn new(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            entrypoints: Vec::default(),
        }
    }

    pub fn add_entrypoint(mut self, ep: impl Into<String>) -> Self {
        self.entrypoints.push(ep.into());
        self
    }

    pub fn add_entrypoints<S, I>(mut self, eps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entrypoints.extend(eps.into_iter().map(Into::into));
        self
    }

    /// Compile the given policy and build the bundle with `opa`.
    /// 
    /// # Errors 
    /// 
    /// The `opa` binary must be found in any of the system paths.
    #[allow(clippy::missing_panics_doc)]
    pub fn compile(self) -> Result<(), anyhow::Error> {
        let opa_executable = which("opa")?;

        let root_dir = env::var("CARGO_MANIFEST_DIR")?;
        let out_dir = env::var("OUT_DIR")?;
        println!("cargo:rustc-env=OUT_DIR={out_dir}");
        let out_dir = Path::new(&out_dir).join("opa");

        let mut opa_cmd = Command::new(&opa_executable);

        let mut input_file_path = Path::new(&root_dir).join(self.path);

        println!(
            "cargo:rerun-if-changed={}",
            input_file_path.to_str().unwrap()
        );

        if !input_file_path
            .extension()
            .map_or(false, |s| s == "rego")
        {
            return Err(anyhow!("the policy file must have `.rego` extension"));
        }

        input_file_path = input_file_path.canonicalize()?;

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
            opa_cmd.arg(&entrypoint.replace(".", "/"));
        }

        opa_cmd.arg(input_file_path.to_str().unwrap());

        fs::create_dir_all(&out_dir)?;
        opa_cmd.output()?;

        Ok(())
    }
}
