#![warn(clippy::pedantic)]

use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "bundle")]
pub mod bundle;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "build")]
pub mod build;

/// A helper trait for defining strongly-typed input/decision pairs
/// for given policies.
pub trait PolicyDecision {
    /// A `.` or `/` separated path to the policy decision.
    const POLICY_PATH: &'static str;

    /// The input type for the decision.
    type Input: Serialize;

    /// The output type expected to be returned by OPA.
    type Output: DeserializeOwned;
}

/// Include a bundle built at compile-time.
///
/// # Example
///
/// Build the policy with `opa`:
///
/// ```rust,ignore
/// opa::build::policy("example")
///     .add_source("./example.rego")
///     .add_entrypoint("example.project_permissions")
///     .compile()
///     .unwrap();
/// ```
///
/// Then include the bundle:
/// 
/// ```rust,ignore
/// let bundle = include_policy!("example");
/// ```
/// 
#[cfg(all(feature = "bundle", feature = "build"))]
#[macro_export]
macro_rules! include_policy {
    ($name:literal) => {
        $crate::bundle::Bundle::from_bytes(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/opa/",
            $name,
            ".tar.gz"
        )))
        .unwrap()
    };
}
