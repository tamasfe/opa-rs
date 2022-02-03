use super::{Error, Opa, OpaResponse, Policy};

/// Routes for the [OPA Policy API](https://www.openpolicyagent.org/docs/latest/rest-api/#policy-api).
impl Opa {
    pub async fn set_policy(&self, policy: Policy) -> Result<(), Error> {
        self.client
            .put(self.policy_url.join(&policy.id)?)
            .header("Content-Type", "text/plain")
            .body(policy.raw)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn delete_policy(&self, policy_id: &str) -> Result<(), Error> {
        self.client
            .delete(self.policy_url.join(policy_id)?)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn get_policy(&self, policy_id: &str) -> Result<Policy, Error> {
        let res: OpaResponse<Policy> = self
            .client
            .get(self.policy_url.join(policy_id)?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(res.result)
    }

    pub async fn list_policies(&self) -> Result<Vec<Policy>, Error> {
        let res: OpaResponse<Vec<Policy>> = self
            .client
            .get(self.policy_url.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(res.result)
    }
}
