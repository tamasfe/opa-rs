use super::{Error, Opa};

impl Opa {
    /// Basic health-checking.
    pub async fn health(&self) -> Result<(), Error> {
        self.client
            .get(self.health_url.clone())
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
