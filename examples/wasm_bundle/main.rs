use opa::{bundle::Bundle, wasm::Opa};
use serde_json::{json, Value};

fn main() -> Result<(), anyhow::Error> {
    let mut bundle = Bundle::from_bytes(include_bytes!("./example.tar.gz"))?;

    let mut opa = Opa::new().build(bundle.wasm_policies.pop().unwrap().bytes)?;

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

    Ok(())
}
