use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub roots: Vec<String>,
    #[serde(default)]
    pub wasm: Vec<Wasm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wasm {
    #[serde(default)]
    pub entrypoint: String,
    #[serde(default)]
    pub module: PathBuf,
}
