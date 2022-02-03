use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use sha1::{Sha1, Digest};
use std::{env, fs, path::Path, process::Command};
use syn::{
    bracketed, parse::Parse, parse_macro_input, punctuated::Punctuated, token::Bracket, LitStr,
    Token,
};
use which::which;

extern crate proc_macro;

struct PolicyInput {
    file_path: LitStr,
    _semi: Token!(=>),
    _parens: Bracket,
    entrypoints: Punctuated<LitStr, Token!(,)>,
}

impl Parse for PolicyInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let content;
        Ok(Self {
            file_path: input.parse()?,
            _semi: input.parse()?,
            _parens: bracketed!(content in input),
            entrypoints: Punctuated::parse_terminated(&content)?,
        })
    }
}

#[proc_macro]
pub fn include_wasm_policy(tokens: TokenStream) -> TokenStream {
    let input = parse_macro_input!(tokens as PolicyInput);

    let opa_executable = which("opa").unwrap();

    let root_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = Path::new(&root_dir).join("target/opa");

    let mut opa_cmd = Command::new(&opa_executable);

    let mut input_file_path = Path::new(&root_dir).join(&input.file_path.value());

    if !input_file_path
        .extension()
        .map(|s| s == "rego")
        .unwrap_or(false)
    {
        panic!("the policy file must have .rego extension");
    }

    input_file_path = input_file_path.canonicalize().unwrap();

    let mut hasher = Sha1::new();

    hasher.update(input_file_path.to_str().unwrap().as_bytes());

    let output_file_name =
        hex::encode(&hasher.finalize()[..]);
    let output_file_path = Path::new(&out_dir).join(&output_file_name);

    opa_cmd.args([
        "build",
        "-t",
        "wasm",
        "-O",
        "1",
        "-o",
        output_file_path.to_str().unwrap(),
    ]);

    for entrypoint in input.entrypoints {
        let entrypoint = entrypoint.value();
        opa_cmd.arg("-e");
        opa_cmd.arg(&entrypoint.replace(".", "/"));
    }

    opa_cmd.arg(input_file_path.to_str().unwrap());

    fs::create_dir_all(&out_dir).unwrap();
    opa_cmd.output().unwrap();

    let in_path_lit = LitStr::new(input_file_path.to_str().unwrap(), Span::call_site());
    let out_path_lit = LitStr::new(output_file_path.to_str().unwrap(), Span::call_site());

    quote! {
        {
            use opa::{bundle::Bundle, wasm::Opa};
            let _ = include_str!(#in_path_lit);
            Bundle::from_bytes(include_bytes!(#out_path_lit)).unwrap()
        }
    }
    .into()
}
