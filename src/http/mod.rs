#![allow(clippy::missing_errors_doc)]

use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

mod data;
mod health;
mod policy;
mod query;

#[derive(Debug, Deserialize)]
pub struct Decision<T> {
    /// The result document of the decision.
    pub result: T,
    /// Unique identifier of the decision.
    pub decision_id: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    /// The identifier of the policy.
    pub id: String,
    /// Raw policy code in textual format.
    pub raw: String,
}

impl Policy {
    #[must_use]
    pub fn new(id: impl Into<String>, raw: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            raw: raw.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Opa {
    policy_url: Url,
    #[allow(dead_code)]
    query_url: Url,
    data_url: Url,
    health_url: Url,
    client: reqwest::Client,
}

impl Opa {
    pub fn new(url: impl AsRef<str>) -> Result<Self, Error> {
        let mut base_url: Url = url.as_ref().parse()?;

        if base_url.as_str().ends_with('/') {
            base_url = (String::from(base_url) + "/").parse()?;
        }

        let policy_url = base_url.join("/v1/policies/")?;
        let query_url = base_url.clone();
        let data_url = base_url.join("/v1/data/")?;
        let health_url = base_url.join("/health")?;

        Ok(Self {
            policy_url,
            query_url,
            data_url,
            health_url,
            client: reqwest::Client::default(),
        })
    }

    #[must_use]
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct OpaResponse<T> {
    pub(crate) result: T,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("{0}")]
    Http(#[from] reqwest::Error),
}
