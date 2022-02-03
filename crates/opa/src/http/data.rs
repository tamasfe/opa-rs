use crate::PolicyDecision;

use super::{Decision, Error, Opa};
use serde::{de::DeserializeOwned, Serialize};
use std::borrow::Cow;

/// Routes for the [OPA Data API](https://www.openpolicyagent.org/docs/latest/rest-api/#data-api).
impl Opa {
    /// Endpoint for: <https://www.openpolicyagent.org/docs/latest/rest-api/#get-a-document>
    pub async fn set_document(
        &self,
        path: impl AsRef<str>,
        document: &impl Serialize,
    ) -> Result<(), Error> {
        self.client
            .put(self.data_url.join(path.as_ref())?)
            .header("Content-Type", "application/json")
            .json(document)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    /// Endpoint for: <https://www.openpolicyagent.org/docs/latest/rest-api/#delete-a-document>
    pub async fn delete_document(&self, path: impl AsRef<str>) -> Result<(), Error> {
        self.client
            .delete(self.data_url.join(path.as_ref())?)
            .header("Content-Type", "application/json")
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    /// Same as [`Opa::get_decision`] with an alternative API.
    pub async fn decide<P: PolicyDecision>(
        &self,
        input: &P::Input,
    ) -> Result<Decision<P::Output>, Error> {
        self.get_decision(P::POLICY_PATH, input).await
    }

    /// Get a decision document based on a policy.
    ///
    /// The given policy path is either a package name such as `example.policy.allow` or a
    /// path such as `example/policy/allow`.
    ///
    /// Endpoint for: <https://www.openpolicyagent.org/docs/latest/rest-api/#get-a-document-with-input>
    pub async fn get_decision<I, R>(&self, policy: &str, input: &I) -> Result<Decision<R>, Error>
    where
        I: Serialize,
        R: DeserializeOwned,
    {
        #[derive(Serialize)]
        struct InputRequest<'a, T> {
            input: &'a T,
        }

        let policy_path = if policy.contains('.') {
            Cow::Owned(policy.replace('.', "/"))
        } else {
            Cow::Borrowed(policy)
        };

        let res: Decision<R> = self
            .client
            .post(self.data_url.join(&policy_path)?)
            .header("Content-Type", "application/json")
            .json(&InputRequest { input })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(res)
    }
}
