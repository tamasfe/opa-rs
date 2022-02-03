fn main() {
    opa::build::policy("./example.rego", "example")
        .add_entrypoint("example.project_permissions")
        .compile()
        .unwrap(); 
}
