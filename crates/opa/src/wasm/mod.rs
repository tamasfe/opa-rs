#![allow(clippy::cast_possible_truncation)]

use crate::PolicyDecision;
use anyhow::anyhow;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    borrow::Cow, collections::HashMap, io::copy, mem::ManuallyDrop, string::String, sync::Arc,
};
use wasmtime::{Caller, Engine, Instance, Linker, Memory, MemoryType, Module, Store};

#[derive(Default)]
pub struct OpaBuilder {
    abort_cb: Option<Box<dyn Fn(&str) + Send + Sync>>,
    println_cb: Option<Box<dyn Fn(&str) + Send + Sync>>,
    buffer_max_mem_pages: Option<u32>,
    engine: Engine,
}

impl OpaBuilder {
    /// Set a handler function for OPA aborts.
    ///
    /// If not set, the default handler will panic on abort.
    #[must_use]
    pub fn on_abort<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.abort_cb = Some(Box::new(f));
        self
    }

    /// Set the handler for the builtin `println` function.
    #[must_use]
    pub fn on_println<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.println_cb = Some(Box::new(f));
        self
    }

    #[must_use]
    pub fn max_memory_pages(mut self, opt: impl Into<Option<u32>>) -> Self {
        self.buffer_max_mem_pages = opt.into();
        self
    }

    #[must_use]
    pub fn with_engine(mut self, engine: Engine) -> Self {
        self.engine = engine;
        self
    }

    /// Build the OPA WASM instance from a module in a bundle.
    ///
    /// # Errors
    ///
    /// The bundle must contain at least one compiled WASM module.
    /// The OPA module will be initialized with any error returned.
    #[cfg(feature = "bundle")]
    pub fn build_from_bundle(self, bundle: &crate::bundle::Bundle) -> Result<Opa, anyhow::Error> {
        self.build(
            &bundle
                .wasm_policies
                .first()
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("the bundle must at least one WASM module"))?
                .bytes,
        )
    }

    /// Build the OPA WASM instance.
    ///
    /// # Errors
    ///
    /// The OPA module will be initialized with any error returned.
    pub fn build(self, wasm_bytes: impl AsRef<[u8]>) -> Result<Opa, anyhow::Error> {
        let engine = self.engine;
        let module = Module::from_binary(&engine, wasm_bytes.as_ref())?;
        let mut linker = Linker::<()>::new(&engine);
        let mut store = Store::new(&engine, ());
        let env_buffer = Memory::new(&mut store, MemoryType::new(2, self.buffer_max_mem_pages))?;

        let on_abort = Arc::<Box<dyn Fn(&str) + Send + Sync>>::from(
            self.abort_cb.unwrap_or_else(|| Box::new(default_opa_abort)),
        );
        let on_abort1 = on_abort.clone();
        let on_println = self
            .println_cb
            .unwrap_or_else(|| Box::new(default_opa_println));

        // https://www.openpolicyagent.org/docs/latest/wasm/#memory-buffer
        linker.define("env", "memory", env_buffer)?;

        // https://www.openpolicyagent.org/docs/latest/wasm/#imports
        linker.func_wrap(
            "env",
            "opa_abort",
            move |caller: Caller<'_, ()>, addr: u32| {
                let addr = addr as usize;
                let mem = env_buffer.data(&caller);
                let s = null_terminated_str(&mem[addr..]).unwrap_or("invalid string in memory");
                on_abort1(s);
            },
        )?;
        linker.func_wrap(
            "env",
            "opa_println",
            move |caller: Caller<'_, ()>, addr: u32| {
                let addr = addr as usize;
                let mem = env_buffer.data(&caller);
                match null_terminated_str(&mem[addr..]) {
                    Some(s) => on_println(s),
                    None => on_abort("invalid string in memory"),
                }
            },
        )?;

        // TODO: builtins are not supported for now.
        linker.func_wrap("env", "opa_builtin0", move |_id: u32, _ctx: u32| 0_u32)?;
        linker.func_wrap(
            "env",
            "opa_builtin1",
            move |_id: u32, _ctx: u32, _1: u32| 0_u32,
        )?;
        linker.func_wrap(
            "env",
            "opa_builtin2",
            move |_id: u32, _ctx: u32, _1: u32, _2: u32| 0_u32,
        )?;
        linker.func_wrap(
            "env",
            "opa_builtin3",
            move |_id: u32, _ctx: u32, _1: u32, _2: u32, _3: u32| 0_u32,
        )?;
        linker.func_wrap(
            "env",
            "opa_builtin4",
            move |_id: u32, _ctx: u32, _1: u32, _2: u32, _3: u32, _4: u32| 0_u32,
        )?;

        let instance = linker.instantiate(&mut store, &module)?;

        env_buffer.data(&mut store);

        let mut opa = Opa {
            store,
            instance,
            env_buffer,
            entrypoints: HashMap::default(),
            data_addr: None,
        };

        opa.init()?;

        Ok(opa)
    }
}

#[derive(Debug)]
pub struct Opa {
    store: Store<()>,
    instance: Instance,
    env_buffer: Memory,
    entrypoints: HashMap<String, u32>,

    data_addr: Option<Addr>,
}

impl Opa {
    /// Create a new [`OpaBuilder`] instance.
    #[allow(clippy::new_ret_no_self)]
    #[must_use]
    pub fn new() -> OpaBuilder {
        OpaBuilder::default()
    }

    /// List all available entrypoints.
    pub fn entrypoints(&self) -> impl Iterator<Item = &str> {
        self.entrypoints.keys().map(String::as_str)
    }

    /// Set or override the contextual data for OPA.
    ///
    /// Unlike the OPA HTTP API, the entire dataset must be
    /// provided every time and no patching is possible.
    ///
    /// # Errors
    ///
    /// Internal WASM errors are returned.
    pub fn set_data(&mut self, data: &impl Serialize) -> Result<(), anyhow::Error> {
        if let Some(addr) = self.data_addr.take() {
            self.free(addr)?;
        }

        self.data_addr = Some(self.write_json(data)?);

        Ok(())
    }

    /// Evaluate a policy at the entrypoint with the given permissions.
    ///
    /// # Errors
    ///
    /// The entrypoint must exist.
    ///
    /// Data must be set at least once beforehand with [`Self::set_data`], otherwise evaluation will always fail.
    ///
    /// Internal WASM errors are also returned.
    pub fn eval<I, R>(&mut self, entrypoint: &str, input: &I) -> Result<R, anyhow::Error>
    where
        I: Serialize,
        R: DeserializeOwned,
    {
        let mut ctx = EvalContext::create(self, input)?;
        let res = ctx.eval(entrypoint)?;
        ctx.destroy()?;
        Ok(res)
    }

    /// Create an evaluation context ([`EvalContext`]) with the given input.
    ///
    /// # Errors
    ///
    /// Data must be set at least once beforehand with [`Self::set_data`], otherwise evaluation will always fail.
    ///
    /// Internal WASM errors are also returned.
    pub fn eval_context<'c>(
        &'c mut self,
        input: &impl Serialize,
    ) -> Result<EvalContext<'c>, anyhow::Error> {
        EvalContext::create(self, input)
    }

    /// Same as [`Self::eval`] with an alternative API.
    ///
    /// # Errors
    ///
    /// The entrypoint (policy path) for `P` must exist within this instance.
    ///
    /// Data must be set at least once beforehand with [`Self::set_data`], otherwise evaluation will always fail.
    ///
    /// Internal WASM errors are also returned.
    pub fn decide<P: PolicyDecision>(
        &mut self,
        input: &P::Input,
    ) -> Result<P::Output, anyhow::Error> {
        self.eval(P::POLICY_PATH, input)
    }
}

impl Opa {
    fn init(&mut self) -> Result<(), anyhow::Error> {
        let opa_entrypoints = self
            .instance
            .get_typed_func::<(), u32, _>(&mut self.store, "entrypoints")?;
        let ep_addr = opa_entrypoints.call(&mut self.store, ())?;
        self.entrypoints = self.json_at(ep_addr.into())?;

        Ok(())
    }

    fn bytes_at(&self, addr: Addr) -> Option<&[u8]> {
        let data = self.env_buffer.data(&self.store);
        null_terminated_slice(&data[addr.into()..])
    }

    #[allow(dead_code)]
    fn str_at(&self, addr: usize) -> Option<&str> {
        let data = self.env_buffer.data(&self.store);
        null_terminated_str(&data[addr..])
    }

    fn json_at<T: DeserializeOwned>(&mut self, addr: Addr) -> Result<T, anyhow::Error> {
        let opa_json_dump = self
            .instance
            .get_typed_func::<(u32,), u32, _>(&mut self.store, "opa_json_dump")?;

        let json_addr: Addr = opa_json_dump.call(&mut self.store, (addr.into(),))?.into();
        let json_result = serde_json::from_slice::<T>(self.bytes_at(json_addr).unwrap());
        self.free(json_addr)?;

        Ok(json_result?)
    }

    fn write_json(&mut self, value: &impl Serialize) -> Result<Addr, anyhow::Error> {
        let opa_json_parse = self
            .instance
            .get_typed_func::<(u32, u32), u32, _>(&mut self.store, "opa_json_parse")?;

        let json = serde_json::to_vec(value)?;
        let json_size = json.len();

        let json_addr = self.write_bytes(json)?;

        let addr = opa_json_parse.call(&mut self.store, (json_addr.into(), json_size as _))?;

        self.free(json_addr)?;

        Ok(addr.into())
    }

    fn write_bytes(&mut self, bytes: impl AsRef<[u8]>) -> Result<Addr, anyhow::Error> {
        let bytes = bytes.as_ref();
        let (addr, mut data) = self.alloc(bytes.len())?;

        copy(&mut &*bytes, &mut data)?;

        Ok(addr)
    }

    fn alloc(&mut self, len: usize) -> Result<(Addr, &mut [u8]), anyhow::Error> {
        let opa_malloc = self
            .instance
            .get_typed_func::<(u32,), u32, _>(&mut self.store, "opa_malloc")?;

        let addr = opa_malloc.call(&mut self.store, (len as _,))?;
        let data =
            &mut self.env_buffer.data_mut(&mut self.store)[addr as usize..addr as usize + len];

        Ok((addr.into(), data))
    }

    fn free(&mut self, addr: Addr) -> Result<(), anyhow::Error> {
        let opa_free = self
            .instance
            .get_typed_func::<(u32,), (), _>(&mut self.store, "opa_free")?;
        opa_free.call(&mut self.store, (addr.into(),))?;
        Ok(())
    }
}

/// An evaluation context that allows evaluating multiple
/// entrypoints multiple times with the same input.
/// 
/// # Remarks
/// 
/// The data of the context has to be freed after use,
/// this can be done with the [`Self::destroy`] method.
/// 
/// Data is also freed on drop, but in this case the **context will panic on failure**.
pub struct EvalContext<'c> {
    opa: &'c mut Opa,
    input_addr: Addr,
    ctx_addr: Addr,
}

impl<'c> EvalContext<'c> {
    fn create(opa: &'c mut Opa, input: &impl Serialize) -> Result<Self, anyhow::Error> {
        let opa_eval_ctx_new = opa
            .instance
            .get_typed_func::<(), u32, _>(&mut opa.store, "opa_eval_ctx_new")?;
        let opa_eval_ctx_set_input = opa
            .instance
            .get_typed_func::<(u32, u32), (), _>(&mut opa.store, "opa_eval_ctx_set_input")?;
        let opa_eval_ctx_set_data = opa
            .instance
            .get_typed_func::<(u32, u32), (), _>(&mut opa.store, "opa_eval_ctx_set_data")?;

        let data_addr = opa
            .data_addr
            .ok_or_else(|| anyhow!("no data provided, all decisions will return undefined"))?;
        let input_addr = opa.write_json(input)?;

        let ctx_addr = opa_eval_ctx_new.call(&mut opa.store, ())?;

        opa_eval_ctx_set_input.call(&mut opa.store, (ctx_addr, input_addr.into()))?;
        opa_eval_ctx_set_data.call(&mut opa.store, (ctx_addr, data_addr.into()))?;

        Ok(EvalContext {
            opa,
            input_addr,
            ctx_addr: ctx_addr.into(),
        })
    }

    /// Evaluate a policy at the entrypoint.
    ///
    /// # Errors
    ///
    /// The entrypoint must exist.
    ///
    /// Deserialization errors and internal WASM errors are also returned.
    pub fn eval<R>(&mut self, entrypoint: &str) -> Result<R, anyhow::Error>
    where
        R: DeserializeOwned,
    {
        #[derive(Deserialize)]
        struct OpaOutput<R> {
            result: R,
        }

        let opa_eval_ctx_set_entrypoint = self.opa.instance.get_typed_func::<(u32, u32), (), _>(
            &mut self.opa.store,
            "opa_eval_ctx_set_entrypoint",
        )?;

        let opa_eval_ctx_get_result = self
            .opa
            .instance
            .get_typed_func::<(u32,), u32, _>(&mut self.opa.store, "opa_eval_ctx_get_result")?;
        let opa_eval = self
            .opa
            .instance
            .get_typed_func::<(u32,), u32, _>(&mut self.opa.store, "eval")?; // does not start with opa_ on purpose

        let entrypoint = if entrypoint.contains('.') {
            Cow::Owned(entrypoint.replace('.', "/"))
        } else {
            Cow::Borrowed(entrypoint)
        };

        let entrypoint_id = self
            .opa
            .entrypoints
            .get(entrypoint.as_ref())
            .copied()
            .ok_or_else(|| anyhow!("invalid entrypoint `{}`", &entrypoint))?;

        opa_eval_ctx_set_entrypoint
            .call(&mut self.opa.store, (self.ctx_addr.into(), entrypoint_id))?;
        opa_eval.call(&mut self.opa.store, (self.ctx_addr.into(),))?;

        let result_addr =
            opa_eval_ctx_get_result.call(&mut self.opa.store, (self.ctx_addr.into(),))?;

        // TODO: this will return an array of results (OpaOutput<_>)
        //      I'm not sure about the reason for this, but for now we are only interested
        //      in the first one.
        let result: Result<Vec<OpaOutput<R>>, _> = self.opa.json_at(result_addr.into());

        self.opa.free(result_addr.into())?;

        result.and_then(|mut out| {
            out.pop()
                .map(|r| r.result)
                .ok_or_else(|| anyhow!("the query produced no results"))
        })
    }

    /// Destroy and free the eval context.
    ///
    /// # Errors
    ///
    /// WASM and OPA errors are returned.
    pub fn destroy(mut self) -> Result<(), anyhow::Error> {
        self.destroy_mut()?;
        let _ = ManuallyDrop::new(self);
        Ok(())
    }

    fn destroy_mut(&mut self) -> Result<(), anyhow::Error> {
        self.opa.free(self.input_addr)?;
        self.opa.free(self.ctx_addr)?;
        Ok(())
    }
}

impl Drop for EvalContext<'_> {
    fn drop(&mut self) {
        if let Err(err) = self.destroy_mut() {
            #[allow(clippy::manual_assert)]
            if !std::thread::panicking() {
                panic!("{err:?}");
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
struct Addr(u32);

impl From<u32> for Addr {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<usize> for Addr {
    fn from(v: usize) -> Self {
        Self(v as _)
    }
}

impl From<Addr> for u32 {
    fn from(v: Addr) -> Self {
        v.0
    }
}

impl From<Addr> for usize {
    fn from(v: Addr) -> Self {
        v.0 as _
    }
}

fn null_terminated_slice(slice: &[u8]) -> Option<&[u8]> {
    slice.iter().position(|b| *b == 0).map(|end| &slice[0..end])
}

fn null_terminated_str(slice: &[u8]) -> Option<&str> {
    slice
        .iter()
        .position(|b| *b == 0)
        .and_then(|end| std::str::from_utf8(&slice[0..end]).ok())
}

fn default_opa_abort(error: &str) {
    panic!("OPA abort was called: {}", error);
}

fn default_opa_println(value: &str) {
    println!("{}", value);
}
