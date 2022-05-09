
use opa::{bundle::Bundle, wasm::Opa};
use serde_json::{json, Value};

#[test]
fn test_eval_context_reuse() {
    let mut bundle = Bundle::from_bytes(include_bytes!(
        "../../../examples/src/bin/wasm_bundle/example.tar.gz"
    ))
    .unwrap();

    let mut opa = Opa::new()
        .build(bundle.wasm_policies.pop().unwrap().bytes)
        .unwrap();

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

    opa.set_data(&data).unwrap();

    opa.eval_context(&input).unwrap().eval::<Value>("example.project_permissions").unwrap();

    let mut ctx = opa.eval_context(&input).unwrap();

    for _ in 0..100 {
        ctx.eval::<Value>("example/project_permissions").unwrap();
    }
}

