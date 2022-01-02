use opa_client::{
    http::{Opa, Policy},
    PolicyDecision,
};
use serde::Serialize;
use serde_json::json;
use std::collections::HashSet;

enum ProjectPermissions {}

#[derive(Serialize)]
struct OpaInput {
    user_id: String,
    project_id: String,
}

impl PolicyDecision for ProjectPermissions {
    const POLICY_PATH: &'static str = "example.project_permissions";
    type Input = OpaInput;
    type Output = HashSet<String>;
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opa = Opa::new("http://localhost:8181")?;

    opa.set_policy(Policy::new("example", include_str!("../example.rego")))
        .await?;

    opa.set_document(
        "users",
        &json!({
            "test": {
                "projects": {
                    "test": {
                        "roles": ["owner"]
                    }
                }
            }
        }),
    )
    .await?;

    opa.set_document(
        "projects",
        &json!({
            "test": {}
        }),
    )
    .await?;

    let decision = opa
        .decide::<ProjectPermissions>(&OpaInput {
            user_id: "test".into(),
            project_id: "test".into(),
        })
        .await?;

    println!("{:?}", decision.result);

    Ok(())
}
