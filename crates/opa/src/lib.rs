#![warn(clippy::pedantic)]

use serde::{Serialize, de::DeserializeOwned};

#[cfg(feature = "bundle")]
pub mod bundle;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "wasm")]
pub mod wasm;

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
