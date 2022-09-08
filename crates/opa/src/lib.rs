#![warn(clippy::pedantic)]

use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "bundle")]
pub mod bundle;

#[cfg(feature = "http")]
pub mod http;

#[cfg(any(feature = "wasmtime-cranelift", feature = "wasmtime-aot"))]
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
    ($name:literal) => {{
        let mut bundle = $crate::bundle::Bundle::from_bytes(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/opa/",
            $name,
            ".tar.gz"
        )))
        .unwrap();

        // SAFETY: The WASM module was compiled by
        // this library, so it is correct.
        let b = include_bytes!(concat!(env!("OUT_DIR"), "/opa/", $name, ".cwasm"));

        if !b.is_empty() {
            $crate::include_aot!(bundle, b);
        }

        bundle
    }};
}

#[doc(hidden)]
pub mod private {
    pub use bytes;
}

#[cfg(all(feature = "build", feature = "wasmtime-aot"))]
#[doc(hidden)]
#[macro_export]
macro_rules! include_aot {
    ($bundle:ident, $bytes:ident) => {
        unsafe { $bundle.set_wasmtime_bytes($crate::private::bytes::Bytes::from(&$bytes[..])) }
    };
}

#[cfg(all(feature = "build", not(feature = "wasmtime-aot")))]
#[doc(hidden)]
#[macro_export]
macro_rules! include_aot {
    ($bundle:ident, $bytes:ident) => {};
}
