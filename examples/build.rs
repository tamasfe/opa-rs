fn main() {
    opa::build::policy("example")
        .add_source("./example.rego")
        .add_source("./example2.rego")
        .add_entrypoint("example.project_permissions")
        .add_entrypoint("example2.project_permissions2")
        .compile()
        .unwrap();
}
