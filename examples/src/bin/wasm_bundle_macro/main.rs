use std::time::Instant;

use opa::{include_policy, wasm::Opa};
use serde_json::{json, Value};

fn main() -> Result<(), anyhow::Error> {
    let bundle = include_policy!("example");

    let start = Instant::now();

    let mut opa = Opa::new().build_from_bundle(&bundle)?;

    let data = json!({
        "users": {
            "test": {
                "projects": {
                    "test": {
                        "roles": ["owner"]
                    }
                }
            }
        },
        "projects": {
            "test": {}
        }
    });

    let input = json!({
        "user_id": "test",
        "project_id": "test",
    });

    println!("available entrypoints:");
    for e in opa.entrypoints() {
        println!("{}", e);
    }

    opa.set_data(&data)?;

    let results: Value = opa.eval("example.project_permissions", &input)?;

    println!("{}", results);
    println!("{:.4}s", Instant::now().duration_since(start).as_secs_f64());

    Ok(())
}
