use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use once_cell::sync::OnceCell;
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::time::{sleep, timeout};
use tracing::{debug, warn};

use crate::PglitePaths;

use super::{
    create_engine, ensure_cluster, ensure_runtime, locate_runtime_module, prepare_default_mount,
    resolve_io_socket, standard_wasi_builder, MountInfo,
};

use md5::{Digest, Md5};
use wasmtime::{Engine, Instance, Linker, Memory, Module, Store, Trap, TypedFunc};
use wasmtime_wasi::preview1::add_to_linker_sync;
use wasmtime_wasi::I32Exit;
use wasmtime_wasi::WasiP1Ctx;

static DEFAULT_RUNTIME: OnceCell<Mutex<InteractiveRuntime>> = OnceCell::new();

/// Produce a hex + ASCII view of a byte buffer.
pub fn hexc(data: &[u8], way: &str, line_limit: Option<usize>) -> String {
    const BYTES_PER_LINE: usize = 16;

    let len = data.len();
    let total_lines = len.div_ceil(BYTES_PER_LINE);
    let mut result = String::new();

    let mut lower = 0usize;
    let mut upper = len;
    if let Some(limit) = line_limit {
        if limit > 0 && total_lines > limit {
            let preserve = BYTES_PER_LINE * (limit / 2);
            lower = preserve;
            upper = len.saturating_sub(preserve);
            if upper <= lower {
                lower = 0;
                upper = len;
            }
        }
    }

    let total_as_lines = len as f64 / BYTES_PER_LINE as f64;
    if lower == 0 && upper == len {
        let _ = writeln!(
            result,
            "{} : {} bytes, {:.2}/{total_lines} lines",
            way, len, total_as_lines,
        );
    } else {
        let _ = writeln!(
            result,
            "{} : {} bytes, {:.2}/{total_lines} lines, showing prefix/suffix {} bytes",
            way, len, total_as_lines, lower,
        );
    }

    let mut offset = 0usize;
    let mut skipped = false;
    while offset < len {
        if offset >= lower && offset < upper {
            if !skipped {
                let _ = writeln!(
                    result,
                    "... {:08x}  <skipping {} to {}>",
                    upper, lower, upper,
                );
                skipped = true;
            }
            offset = upper;
            continue;
        }

        let line = &data[offset..usize::min(offset + BYTES_PER_LINE, len)];
        let mut hex_repr = String::new();
        for byte in line {
            if !hex_repr.is_empty() {
                hex_repr.push(' ');
            }
            let _ = write!(hex_repr, "{:02x}", byte);
        }
        let ascii_repr: String = line
            .iter()
            .map(|b| {
                if (32..=126).contains(b) {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        let _ = writeln!(result, "{:08x} {:<47}  {}", offset, hex_repr, ascii_repr);
        offset += BYTES_PER_LINE;
    }

    result
}

/// Render a byte count using IEC (KiB, MiB, ...) units.
pub fn si_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let value = bytes as f64;
    if bytes < 1024 {
        return format!("{bytes:3} B");
    }
    if value / KIB < 999.0 {
        return format!("{:.2} KiB", value / KIB);
    }
    if value / MIB < 999.0 {
        return format!("{:.2} MiB", value / MIB);
    }
    if value / GIB < 999.0 {
        return format!("{:.2} GiB", value / GIB);
    }
    format!("{value:.2}")
}

/// Lazily open stdin for asynchronous reads.
pub fn get_reader() -> BufReader<io::Stdin> {
    BufReader::new(io::stdin())
}

/// Prompt for a line of input asynchronously. Returns `None` on EOF.
pub async fn ainput(prompt: &str) -> io::Result<Option<Vec<u8>>> {
    let mut stdout = io::stdout();
    stdout.write_all(prompt.as_bytes()).await?;
    stdout.flush().await?;

    let mut reader = get_reader();
    let mut buf = Vec::new();
    let read = reader.read_until(b'\n', &mut buf).await?;
    if read == 0 {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// Resolve the expected socket path for the embedded cluster.
pub fn get_io_base_path(paths: &PglitePaths) -> PathBuf {
    resolve_io_socket(paths)
}

/// Return the host directory that should be mounted into the WASI filesystem.
pub fn get_mount_root(paths: &PglitePaths) -> PathBuf {
    paths.mount_root().to_path_buf()
}

/// Global, lazily prepared interactive runtime akin to the Python sync importer.
pub fn with_default_runtime<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut InteractiveRuntime) -> Result<T>,
{
    let runtime_mutex = DEFAULT_RUNTIME
        .get_or_try_init(|| InteractiveRuntime::prepare_default().map(Mutex::new))?;

    let mut runtime = runtime_mutex
        .lock()
        .map_err(|_| anyhow!("interactive runtime lock poisoned"))?;
    f(&mut runtime)
}

/// Locate a WASM module using the default runtime, mirroring the Python helper.
pub fn wasm_import(alias: &str, wasmfile: Option<&Path>) -> Result<PathBuf> {
    with_default_runtime(|runtime| runtime.module_path(alias, wasmfile))
}

/// Resolve the host path to the bundled pg_dump shim inside the default runtime.
pub fn pg_dump_path() -> Result<PathBuf> {
    with_default_runtime(|runtime| runtime.pg_dump_path())
}

/// Execute pg_dump via Wasmtime when available. Returns `Ok(None)` if the
/// pg_dump shim is not present in the runtime.
pub fn run_pg_dump(argv: &[&str], env: &[(&str, &str)]) -> Result<Option<i32>> {
    with_default_runtime(|runtime| runtime.run_pg_dump(argv, env))
}

/// Access the default mount information produced during initialization.
pub fn default_mount() -> Result<MountInfo> {
    with_default_runtime(|runtime| Ok(runtime.mount_info().clone()))
}

/// Copy bytes into the interactive input buffer, matching the Python helper's behaviour.
pub fn poke(input: PokeInput<'_>) -> Result<(Vec<u8>, usize)> {
    with_default_runtime(|runtime| runtime.poke(input))
}

/// Write a payload and run a single interactive frame, returning the raw response bytes.
pub fn exec_interactive(input: PokeInput<'_>) -> Result<Vec<u8>> {
    with_default_runtime(|runtime| runtime.exec_interactive(input))
}

pub fn is_file_transport_mode() -> Result<bool> {
    with_default_runtime(|rt| {
        let session = rt.interactive_session()?;
        Ok(session.is_file_transport())
    })
}

pub async fn run_tests_quick() -> Result<()> {
    const TESTS: &str = r#"
        SHOW client_encoding;
        CREATE OR REPLACE FUNCTION test_func() RETURNS TEXT AS $$ BEGIN RETURN 'test'; END; $$ LANGUAGE plpgsql;
        CREATE OR REPLACE FUNCTION addition (entier1 integer, entier2 integer)
        RETURNS integer LANGUAGE plpgsql IMMUTABLE AS '
        DECLARE resultat integer;
        BEGIN resultat := entier1 + entier2; RETURN resultat; END ';
        SELECT test_func();
        SELECT now(), current_database(), session_user, current_user;
        SELECT addition(40,2);
    "#;

    if !is_file_transport_mode()? {
        return Ok(());
    }

    for stmt in TESTS.split(";\n\n") {
        let sql = stmt.trim();
        if sql.is_empty() {
            continue;
        }
        let sql = format!("{sql};");
        with_default_runtime(|rt| {
            rt.poke(PokeInput::Str(&sql))?;
            rt.interactive_one()
        })?;
        sleep(Duration::from_millis(100)).await;
    }

    Ok(())
}

/// Start a Unix/TCP proxy server that forwards PostgreSQL wire protocol to pglite.
/// This provides the same functionality as the Python implementation.
///
/// # Arguments
/// * `use_tcp` - If true, bind to TCP 0.0.0.0:5432, otherwise bind to Unix domain socket /tmp/.s.PGSQL.5432
///
/// # Example
///
/// ```no_run
/// use pglite_oxide::interactive;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     // Start Unix domain socket proxy
///     interactive::start_proxy(false).await?;
///
///     // Or start TCP proxy
///     interactive::start_proxy(true).await?;
///     Ok(())
/// }
/// ```
pub async fn start_proxy(use_tcp: bool) -> Result<()> {
    let file_mode = with_default_runtime(|rt| {
        let session = rt.interactive_session()?;
        Ok(session.is_file_transport())
    })
    .context("prepare pglite interactive runtime")?;

    if file_mode {
        debug!("Running pre-connection tests (file transport mode)...");
        if let Err(err) = run_tests_quick().await {
            warn!("Pre-connection tests failed: {err:#}");
        }
    }

    if use_tcp {
        let listener = TcpListener::bind(("0.0.0.0", 5432))
            .await
            .context("Failed to bind TCP listener on 0.0.0.0:5432")?;
        debug!("listening on TCP 0.0.0.0:5432");
        loop {
            let (mut sock, addr) = listener
                .accept()
                .await
                .context("Failed to accept TCP connection")?;
            debug!("Accepted TCP connection from {}", addr);
            tokio::spawn(async move {
                if let Err(e) = handle_client(&mut sock).await {
                    warn!("Error handling TCP client: {}", e);
                }
            });
        }
    } else {
        // UDS path MUST be /tmp/.s.PGSQL.5432 to match Python exactly
        let uds_path = "/tmp/.s.PGSQL.5432";
        let _ = std::fs::remove_file(uds_path);
        let listener = UnixListener::bind(uds_path).context("Failed to bind Unix domain socket")?;
        debug!("listening on UDS {}", uds_path);
        loop {
            let (mut sock, addr) = listener
                .accept()
                .await
                .context("Failed to accept UDS connection")?;
            debug!("Accepted UDS connection from {:?}", addr);
            tokio::spawn(async move {
                if let Err(e) = handle_uds(&mut sock).await {
                    warn!("Error handling UDS client: {}", e);
                }
            });
        }
    }
}

async fn handle_uds(sock: &mut UnixStream) -> Result<()> {
    handle_client(sock).await
}

async fn handle_client<S>(sock: &mut S) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let poll_interval = Duration::from_millis(16);

    loop {
        let pending = with_default_runtime(|rt| rt.drain_wire())?;
        if !pending.is_empty() {
            for reply in pending {
                if !reply.is_empty() {
                    sock.write_all(&reply)
                        .await
                        .context("Failed to write reply to client")?;
                }
            }
            continue;
        }

        match timeout(poll_interval, sock.read(&mut buf)).await {
            Ok(Ok(0)) => {
                debug!("Client disconnected");
                break;
            }
            Ok(Ok(n)) => {
                if n == 0 {
                    debug!("Client disconnected");
                    break;
                }

                let replies = with_default_runtime(|rt| rt.forward_wire(&buf[..n]))
                    .context("Failed to forward client bytes through pglite")?;
                for reply in replies {
                    if !reply.is_empty() {
                        sock.write_all(&reply)
                            .await
                            .context("Failed to write reply to client")?;
                    }
                }
            }
            Ok(Err(err)) => {
                return Err(err).context("Failed to read from client socket");
            }
            Err(_) => {
                // timeout -> loop to poll for backend replies again
                continue;
            }
        }
    }
    Ok(())
}

pub struct InteractiveRuntime {
    mount: MountInfo,
    module_cache: HashMap<String, PathBuf>,
    interactive: Option<InteractiveSession>,
}

impl InteractiveRuntime {
    pub fn prepare_default() -> Result<Self> {
        Ok(Self {
            mount: prepare_default_mount()?,
            module_cache: HashMap::new(),
            interactive: None,
        })
    }

    pub fn mount_root(&self) -> &Path {
        self.mount.mount()
    }

    pub fn io_socket(&self) -> &Path {
        self.mount.io_socket()
    }

    pub fn reused_existing(&self) -> bool {
        self.mount.reused_existing()
    }

    pub fn paths(&self) -> &PglitePaths {
        self.mount.paths()
    }

    pub fn mount_info(&self) -> &MountInfo {
        &self.mount
    }

    pub fn module_path(&mut self, alias: &str, wasmfile: Option<&Path>) -> Result<PathBuf> {
        if let Some(explicit) = wasmfile {
            return resolve_module(self.mount.paths(), Some(explicit));
        }

        if let Some(cached) = self.module_cache.get(alias) {
            return Ok(cached.clone());
        }

        let module = resolve_module(self.mount.paths(), None)?;
        self.module_cache.insert(alias.to_string(), module.clone());
        Ok(module)
    }

    pub fn pg_dump_path(&self) -> Result<PathBuf> {
        resolve_pg_dump(self.mount.paths())
    }

    pub fn run_pg_dump(&mut self, argv: &[&str], env: &[(&str, &str)]) -> Result<Option<i32>> {
        let path = match resolve_pg_dump(self.mount.paths()) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        match run_wasi_command(self.mount.paths(), &path, argv, env) {
            Ok(code) => Ok(Some(code)),
            Err(err) => {
                warn!("pg_dump execution failed: {err:#}");
                Err(err)
            }
        }
    }

    fn interactive_session(&mut self) -> Result<&mut InteractiveSession> {
        if self.interactive.is_none() {
            let session = InteractiveSession::new(self.mount.paths())?;
            self.interactive = Some(session);
        }
        self.interactive
            .as_mut()
            .ok_or_else(|| anyhow!("interactive session could not be initialized"))
    }

    pub fn poke(&mut self, input: PokeInput<'_>) -> Result<(Vec<u8>, usize)> {
        let session = self.interactive_session()?;
        let (buf, len) = prepare_cstring(input);

        session.use_wire(false)?;
        session.write(&buf)?;
        session.set_cma_length(len as i32)?;

        Ok((buf, len))
    }

    pub fn exec_interactive(&mut self, input: PokeInput<'_>) -> Result<Vec<u8>> {
        let session = self.interactive_session()?;
        session.ensure_handshake()?;
        let payload = match input {
            PokeInput::Str(sql) => build_simple_query(sql),
            PokeInput::Bytes(bytes) => bytes.to_vec(),
        };
        session.run_wire(&payload)
    }

    pub fn forward_wire(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        let session = self.interactive_session()?;
        session.forward_wire(payload)
    }

    pub fn drain_wire(&mut self) -> Result<Vec<Vec<u8>>> {
        let session = self.interactive_session()?;
        session.drain_wire()
    }

    pub fn use_wire(&mut self, enable: bool) -> Result<()> {
        let session = self.interactive_session()?;
        session.use_wire(enable)
    }

    pub fn interactive_one(&mut self) -> Result<()> {
        let session = self.interactive_session()?;
        session.run_once()
    }

    pub fn interactive_read(&mut self, payload_len: usize) -> Result<Vec<u8>> {
        let session = self.interactive_session()?;
        session.read_response(payload_len)
    }

    pub fn set_cma_length(&mut self, len: i32) -> Result<()> {
        let session = self.interactive_session()?;
        session.set_cma_length(len)
    }

    pub fn clear_error(&mut self) -> Result<()> {
        let session = self.interactive_session()?;
        session.clear_error()
    }

    pub fn pgl_closed(&mut self) -> Result<Option<i32>> {
        let session = self.interactive_session()?;
        session.pgl_closed()
    }

    pub fn buffer_addr(&mut self) -> Result<usize> {
        let session = self.interactive_session()?;
        Ok(session.buffer_addr())
    }

    pub fn buffer_size(&mut self) -> Result<usize> {
        let session = self.interactive_session()?;
        Ok(session.buffer_size())
    }

    pub fn ensure_handshake(&mut self) -> Result<()> {
        let session = self.interactive_session()?;
        session.ensure_handshake()
    }

    pub fn write_buffer(&mut self, bytes: &[u8]) -> Result<()> {
        let session = self.interactive_session()?;
        session.write(bytes)
    }
}

const INTERACTIVE_ARGV: &[&str] = &["/tmp/pglite/bin/postgres", "--single", "postgres"];

const STARTUP_PROTOCOL: u32 = 196_608; // Protocol 3.0
const DEFAULT_USER: &str = "postgres";
const DEFAULT_DATABASE: &str = "template1";
const APPLICATION_NAME: &str = "pglite-oxide";
const CLIENT_ENCODING: &str = "UTF8";

struct Message<'a> {
    tag: u8,
    body: &'a [u8],
}

enum Transport {
    Cma {
        pending_wire_len: usize,
    },
    File {
        sinput: PathBuf,
        slock: PathBuf,
        cinput: PathBuf,
        clock: PathBuf,
    },
}

struct InteractiveSession {
    paths: PglitePaths,
    _engine: Engine,
    store: Store<WasiP1Ctx>,
    _instance: Instance,
    memory: Memory,
    interactive_write: TypedFunc<i32, ()>,
    interactive_one: TypedFunc<(), ()>,
    interactive_read: TypedFunc<(), i32>,
    use_wire: Option<TypedFunc<i32, ()>>,
    clear_error: Option<TypedFunc<(), ()>>,
    pgl_closed: Option<TypedFunc<(), i32>>,
    buffer_addr: usize,
    buffer_size: usize,
    transport: Transport,
    handshake_complete: bool,
    password_cache: Option<String>,
}

impl InteractiveSession {
    fn new(paths: &PglitePaths) -> Result<Self> {
        ensure_runtime(paths)?;
        if !paths.pgdata.join("PG_VERSION").exists() {
            ensure_cluster(paths)?;
        }

        let module_path = resolve_module(paths, None)?;
        let engine = create_engine()?;
        let module = Module::from_file(&engine, &module_path)?;

        let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
        add_to_linker_sync(&mut linker, |cx: &mut WasiP1Ctx| cx)?;

        let mut builder = standard_wasi_builder(paths)?;
        for arg in INTERACTIVE_ARGV {
            builder.arg(arg);
        }

        let wasi = builder.build();
        let mut store = Store::new(&engine, WasiP1Ctx::new(wasi));
        let instance = linker.instantiate(&mut store, &module)?;

        if let Ok(start) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
            let _ = start.call(&mut store, ());
        }

        if let Ok(initdb) = instance.get_typed_func::<(), i32>(&mut store, "pgl_initdb") {
            let _ = initdb.call(&mut store, ());
        }

        if let Ok(backend) = instance.get_typed_func::<(), ()>(&mut store, "pgl_backend") {
            let _ = backend.call(&mut store, ());
        }

        let memory: Memory = instance
            .get_memory(&mut store, "memory")
            .context("interactive module missing 'memory' export")?;
        let interactive_write = instance
            .get_typed_func::<i32, ()>(&mut store, "interactive_write")
            .context("interactive module missing 'interactive_write' export")?;
        let interactive_one = instance
            .get_typed_func::<(), ()>(&mut store, "interactive_one")
            .context("interactive module missing 'interactive_one' export")?;
        let interactive_read = instance
            .get_typed_func::<(), i32>(&mut store, "interactive_read")
            .context("interactive module missing 'interactive_read' export")?;
        let get_channel = instance
            .get_typed_func::<(), i32>(&mut store, "get_channel")
            .context("interactive module missing 'get_channel' export")?;
        let channel = get_channel.call(&mut store, ())?;
        let get_buffer_addr = instance
            .get_typed_func::<i32, i32>(&mut store, "get_buffer_addr")
            .context("interactive module missing 'get_buffer_addr' export")?;
        let addr = get_buffer_addr.call(&mut store, channel)?;
        ensure!(addr >= 0, "interactive buffer address is negative: {addr}");
        let get_buffer_size = instance
            .get_typed_func::<i32, i32>(&mut store, "get_buffer_size")
            .context("interactive module missing 'get_buffer_size' export")?;
        let size = get_buffer_size.call(&mut store, channel)?;
        ensure!(size >= 0, "interactive buffer size is negative: {size}");
        debug!("interactive transport channel={channel} addr={addr} size={size}");

        let io_socket = resolve_io_socket(paths);
        let transport = if channel >= 0 {
            Transport::Cma {
                pending_wire_len: 0,
            }
        } else {
            let sinput = append_suffix(&io_socket, ".in");
            let slock = append_suffix(&io_socket, ".lock.in");
            let cinput = append_suffix(&io_socket, ".out");
            let clock = append_suffix(&io_socket, ".lock.out");
            Transport::File {
                sinput,
                slock,
                cinput,
                clock,
            }
        };

        let use_wire = instance
            .get_typed_func::<i32, ()>(&mut store, "use_wire")
            .ok();
        let clear_error = instance
            .get_typed_func::<(), ()>(&mut store, "clear_error")
            .ok();
        let pgl_closed = instance
            .get_typed_func::<(), i32>(&mut store, "pgl_closed")
            .ok();

        Ok(Self {
            paths: paths.clone(),
            _engine: engine,
            store,
            _instance: instance,
            memory,
            interactive_write,
            interactive_one,
            interactive_read,
            use_wire,
            clear_error,
            pgl_closed,
            buffer_addr: addr as usize,
            buffer_size: size as usize,
            transport,
            handshake_complete: false,
            password_cache: None,
        })
    }

    fn write(&mut self, payload: &[u8]) -> Result<()> {
        ensure!(
            payload.len() <= self.buffer_size,
            "poke payload {} exceeds interactive buffer {}",
            payload.len(),
            self.buffer_size
        );
        ensure!(
            payload.len() <= i32::MAX as usize,
            "poke payload {} exceeds i32::MAX",
            payload.len()
        );
        let write_offset = self.buffer_addr;
        let end = write_offset
            .checked_add(payload.len())
            .context("interactive payload overflow")?;
        let buffer_end = self
            .buffer_addr
            .checked_add(self.buffer_size)
            .context("interactive buffer end overflow")?;
        ensure!(
            end <= buffer_end,
            "payload end {end:#x} exceeds buffer bounds"
        );
        self.memory
            .write(&mut self.store, write_offset, payload)
            .context("write poke payload into WASM memory")?;
        Ok(())
    }

    fn set_cma_length(&mut self, len: i32) -> Result<()> {
        self.interactive_write
            .call(&mut self.store, len)
            .context("call interactive_write export")?;
        Ok(())
    }

    fn run_once(&mut self) -> Result<()> {
        self.interactive_one
            .call(&mut self.store, ())
            .context("call interactive_one export")?;
        Ok(())
    }

    fn clear_wire_pending(&mut self) -> Result<()> {
        if matches!(self.transport, Transport::Cma { .. }) {
            self.set_cma_length(0)?;
            if let Transport::Cma { pending_wire_len } = &mut self.transport {
                *pending_wire_len = 0;
            }
        }
        Ok(())
    }

    fn send_wire(&mut self, payload: &[u8]) -> Result<()> {
        if matches!(self.transport, Transport::Cma { .. }) {
            if payload.is_empty() {
                self.clear_wire_pending()?;
            } else {
                self.write(payload)?;
                self.set_cma_length(payload.len() as i32)?;
                if let Transport::Cma {
                    pending_wire_len, ..
                } = &mut self.transport
                {
                    *pending_wire_len = payload.len();
                }
            }
            return Ok(());
        }

        if let Transport::File { sinput, slock, .. } = &self.transport {
            if payload.is_empty() {
                return Ok(());
            }
            if let Some(parent) = sinput.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("ensure directory {}", parent.display()))?;
            }
            let _ = fs::remove_file(slock);
            fs::write(slock, payload).with_context(|| format!("write {}", slock.display()))?;
            fs::rename(slock, sinput)
                .with_context(|| format!("rename {} -> {}", slock.display(), sinput.display()))?;
            return Ok(());
        }
        Ok(())
    }

    fn try_recv_wire(&mut self) -> Result<Option<Vec<u8>>> {
        if matches!(self.transport, Transport::Cma { .. }) {
            return self.try_recv_wire_cma();
        }

        if let Transport::File { cinput, clock, .. } = &self.transport {
            match fs::read(cinput) {
                Ok(data) => {
                    let _ = fs::remove_file(cinput);
                    let _ = fs::remove_file(clock);
                    Ok(Some(data))
                }
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(None)
        }
    }

    fn try_recv_wire_cma(&mut self) -> Result<Option<Vec<u8>>> {
        let pending = if let Transport::Cma {
            pending_wire_len, ..
        } = &self.transport
        {
            *pending_wire_len
        } else {
            return Ok(None);
        };

        let reply_len = self
            .interactive_read
            .call(&mut self.store, ())
            .context("call interactive_read export")? as usize;
        if reply_len == 0 {
            return Ok(None);
        }

        let base = self
            .buffer_addr
            .checked_add(pending)
            .and_then(|offset| offset.checked_add(1))
            .context("interactive reply offset overflow")?;
        let end = base
            .checked_add(reply_len)
            .context("interactive reply overflow")?;
        let buffer_end = self
            .buffer_addr
            .checked_add(self.buffer_size)
            .context("interactive buffer end overflow")?;
        ensure!(
            end <= buffer_end,
            "interactive reply {end:#x} exceeds buffer bounds {buffer_end:#x}"
        );
        let data_size = self.memory.data_size(&self.store);
        ensure!(
            end <= data_size,
            "interactive reply {end:#x} exceeds memory size {data_size:#x}"
        );

        let mut buf = vec![0u8; reply_len];
        self.memory
            .read(&mut self.store, base, &mut buf)
            .context("read interactive reply from WASM memory")?;
        self.set_cma_length(0)?;
        if let Transport::Cma {
            pending_wire_len, ..
        } = &mut self.transport
        {
            *pending_wire_len = 0;
        }
        Ok(Some(buf))
    }

    fn collect_replies(&mut self, replies: &mut Vec<Vec<u8>>) -> Result<bool> {
        let mut produced = false;
        while let Some(reply) = self.try_recv_wire()? {
            produced = true;
            if !reply.is_empty() {
                replies.push(reply);
            }
        }
        Ok(produced)
    }

    fn drain_wire(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut replies = Vec::new();
        const MAX_TICKS: usize = 128;
        for _ in 0..MAX_TICKS {
            let produced_before = self.collect_replies(&mut replies)?;
            if !produced_before {
                self.run_once()?;
                let produced_after = self.collect_replies(&mut replies)?;
                if !produced_after {
                    break;
                }
            } else {
                self.run_once()?;
                if !self.collect_replies(&mut replies)? {
                    break;
                }
            }
        }
        Ok(replies)
    }

    fn forward_wire(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        if !payload.is_empty() {
            self.use_wire(true)?;
            self.send_wire(payload)?;
        }

        let mut replies = Vec::new();
        const MAX_TICKS: usize = 256;
        for _ in 0..MAX_TICKS {
            let produced_before = self.collect_replies(&mut replies)?;
            self.run_once()?;
            let produced_after = self.collect_replies(&mut replies)?;
            if !produced_before && !produced_after {
                break;
            }
        }
        Ok(replies)
    }

    fn read_response(&mut self, payload_len: usize) -> Result<Vec<u8>> {
        match &mut self.transport {
            Transport::Cma { .. } => {
                let response_len =
                    self.interactive_read
                        .call(&mut self.store, ())
                        .context("call interactive_read export")? as usize;

                if response_len == 0 {
                    return Ok(Vec::new());
                }

                let response_offset = self
                    .buffer_addr
                    .checked_add(payload_len)
                    .and_then(|offset| offset.checked_add(1))
                    .context("interactive response offset overflow")?;
                let end = response_offset
                    .checked_add(response_len)
                    .context("interactive response overflow")?;
                let buffer_end = self
                    .buffer_addr
                    .checked_add(self.buffer_size)
                    .context("interactive buffer end overflow")?;
                ensure!(
                    end <= buffer_end,
                    "interactive response {end:#x} exceeds buffer bounds {buffer_end:#x}"
                );
                let data_size = self.memory.data_size(&self.store);
                ensure!(
                    end <= data_size,
                    "interactive response {end:#x} exceeds memory size {data_size:#x}"
                );

                let mut buf = vec![0u8; response_len];
                self.memory
                    .read(&mut self.store, response_offset, &mut buf)
                    .context("read interactive response from WASM memory")?;
                Ok(buf)
            }
            Transport::File { cinput, clock, .. } => match fs::read(cinput.as_path()) {
                Ok(data) => {
                    let _ = fs::remove_file(cinput.as_path());
                    let _ = fs::remove_file(clock.as_path());
                    Ok(data)
                }
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(Vec::new()),
                Err(err) => Err(err.into()),
            },
        }
    }

    fn run_wire(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut combined = Vec::new();
        for reply in self.forward_wire(payload)? {
            combined.extend(reply);
        }
        if combined.is_empty() {
            bail!("interactive response timeout");
        }
        Ok(combined)
    }

    fn ensure_handshake(&mut self) -> Result<()> {
        if self.handshake_complete {
            return Ok(());
        }

        self.clear_wire_pending()?;
        let startup = build_startup_message(DEFAULT_USER, DEFAULT_DATABASE);
        let mut response = self.run_wire(&startup)?;

        loop {
            let next = self.process_handshake_response(&response)?;
            if self.handshake_complete {
                return Ok(());
            }
            if let Some(payload) = next {
                response = self.run_wire(&payload)?;
            } else {
                bail!("interactive handshake did not complete");
            }
        }
    }

    fn process_handshake_response(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut next_payload: Option<Vec<u8>> = None;
        for message in parse_messages(data)? {
            match message.tag {
                b'R' => {
                    ensure!(message.body.len() >= 4, "authentication response too short");
                    let code = u32::from_be_bytes(message.body[0..4].try_into().unwrap());
                    match code {
                        0 => {}
                        3 => {
                            let password = self.password()?.as_bytes();
                            ensure!(next_payload.is_none(), "multiple auth responses");
                            next_payload = Some(build_password_message(password));
                        }
                        5 => {
                            ensure!(
                                message.body.len() >= 8,
                                "AuthenticationMD5Password missing salt"
                            );
                            let salt: [u8; 4] = message.body[4..8].try_into().unwrap();
                            let hashed = build_md5_password(self.password()?, DEFAULT_USER, &salt)?;
                            ensure!(next_payload.is_none(), "multiple auth responses");
                            next_payload = Some(build_password_message(hashed.as_bytes()));
                        }
                        other => bail!("unsupported authentication method: {other}"),
                    }
                }
                b'S' => {
                    if let Some((key, value)) = parse_parameter_status(message.body) {
                        debug!("[pglite_oxide] parameter status: {key}={value}");
                    }
                }
                b'K' => {
                    debug!("[pglite_oxide] backend key data received");
                }
                b'Z' => {
                    self.handshake_complete = true;
                }
                b'E' => {
                    let message = parse_error_message(message.body);
                    bail!("postgres handshake error: {message}");
                }
                b'N' => {
                    let message = parse_error_message(message.body);
                    debug!("[pglite_oxide] notice: {message}");
                }
                _ => {}
            }
        }

        Ok(next_payload)
    }

    fn password(&mut self) -> Result<&str> {
        if self.password_cache.is_none() {
            let path = self.paths.pgroot.join("pglite").join("password");
            let mut contents = fs::read_to_string(&path)
                .with_context(|| format!("read password file {}", path.display()))?;
            contents = contents.trim_end_matches(['\n', '\r']).to_string();
            self.password_cache = Some(contents);
        }
        Ok(self.password_cache.as_ref().unwrap())
    }

    fn use_wire(&mut self, enable: bool) -> Result<()> {
        if let Some(func) = &self.use_wire {
            func.call(&mut self.store, if enable { 1 } else { 0 })
                .context("call use_wire export")?;
        }
        Ok(())
    }

    fn clear_error(&mut self) -> Result<()> {
        if let Some(func) = &self.clear_error {
            func.call(&mut self.store, ())
                .context("call clear_error export")?;
        }
        Ok(())
    }

    fn pgl_closed(&mut self) -> Result<Option<i32>> {
        if let Some(func) = &self.pgl_closed {
            return Ok(Some(
                func.call(&mut self.store, ())
                    .context("call pgl_closed export")?,
            ));
        }
        Ok(None)
    }

    fn buffer_addr(&self) -> usize {
        self.buffer_addr
    }

    fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    fn is_file_transport(&self) -> bool {
        matches!(self.transport, Transport::File { .. })
    }
}

fn build_simple_query(sql: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(sql.len() + 6);
    buf.push(b'Q');
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(sql.as_bytes());
    buf.push(0);
    let len = (buf.len() - 1) as u32;
    buf[1..5].copy_from_slice(&len.to_be_bytes());
    buf
}

fn build_startup_message(user: &str, database: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&STARTUP_PROTOCOL.to_be_bytes());

    for (key, value) in [
        ("user", user),
        ("database", database),
        ("client_encoding", CLIENT_ENCODING),
        ("application_name", APPLICATION_NAME),
    ] {
        buf.extend_from_slice(key.as_bytes());
        buf.push(0);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
    }

    buf.push(0);
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_be_bytes());
    buf
}

fn build_password_message(password: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(password.len() + 6);
    buf.push(b'p');
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(password);
    if !password.ends_with(&[0]) {
        buf.push(0);
    }
    let len = (buf.len() - 1) as u32;
    buf[1..5].copy_from_slice(&len.to_be_bytes());
    buf
}

fn build_md5_password(password: &str, user: &str, salt: &[u8; 4]) -> Result<String> {
    let mut inner = Vec::with_capacity(password.len() + user.len());
    inner.extend_from_slice(password.as_bytes());
    inner.extend_from_slice(user.as_bytes());
    let inner_hex = md5_hex(&inner);

    let mut outer = Vec::with_capacity(inner_hex.len() + salt.len());
    outer.extend_from_slice(inner_hex.as_bytes());
    outer.extend_from_slice(salt);
    let outer_hex = md5_hex(&outer);

    Ok(format!("md5{}", outer_hex))
}

fn md5_hex(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("{:032x}", digest)
}

fn parse_messages(data: &[u8]) -> Result<Vec<Message<'_>>> {
    let mut messages = Vec::new();
    let mut index = 0usize;
    while index < data.len() {
        let remaining = &data[index..];
        if remaining.len() < 5 {
            bail!("incomplete postgres message");
        }
        let tag = remaining[0];
        let len = u32::from_be_bytes(remaining[1..5].try_into().unwrap()) as usize;
        ensure!(len >= 4, "invalid postgres message length {len}");
        let total = 1 + len;
        ensure!(
            index + total <= data.len(),
            "postgres message overruns buffer"
        );
        let body = &data[index + 5..index + total];
        messages.push(Message { tag, body });
        index += total;
    }
    Ok(messages)
}

fn parse_parameter_status(body: &[u8]) -> Option<(String, String)> {
    let nul = body.iter().position(|&b| b == 0)?;
    let key = str::from_utf8(&body[..nul]).ok()?.to_string();
    let rest = &body[nul + 1..];
    let nul2 = rest.iter().position(|&b| b == 0)?;
    let value = str::from_utf8(&rest[..nul2]).ok()?.to_string();
    Some((key, value))
}

fn parse_info_fields(body: &[u8]) -> Vec<(char, String)> {
    let mut fields = Vec::new();
    let mut index = 0usize;
    while index < body.len() {
        let code = body[index];
        if code == 0 {
            break;
        }
        index += 1;
        if let Some(end) = body[index..].iter().position(|&b| b == 0) {
            let value = str::from_utf8(&body[index..index + end])
                .unwrap_or_default()
                .to_string();
            fields.push((code as char, value));
            index += end + 1;
        } else {
            break;
        }
    }
    fields
}

fn parse_error_message(body: &[u8]) -> String {
    let fields = parse_info_fields(body);
    if let Some((_, message)) = fields.iter().find(|(code, _)| *code == 'M') {
        return message.clone();
    }
    fields
        .iter()
        .map(|(code, message)| format!("{code}:{message}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Inputs supported by poke helper.
pub enum PokeInput<'a> {
    Str(&'a str),
    Bytes(&'a [u8]),
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os: OsString = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

fn prepare_cstring(input: PokeInput<'_>) -> (Vec<u8>, usize) {
    match input {
        PokeInput::Str(s) => {
            let mut data = s.as_bytes().to_vec();
            data.push(0);
            let len = data.len();
            (data, len)
        }
        PokeInput::Bytes(bytes) => {
            let mut data = bytes.to_vec();
            if !data.ends_with(&[0]) {
                data.push(0);
            }
            let len = data.len();
            (data, len)
        }
    }
}

fn resolve_module(paths: &PglitePaths, wasmfile: Option<&Path>) -> Result<PathBuf> {
    ensure_runtime(paths)?;

    if let Some(explicit) = wasmfile {
        let candidate = if explicit.is_absolute() {
            explicit.to_path_buf()
        } else {
            paths.pgroot.join(explicit)
        };
        ensure!(
            candidate.exists(),
            "wasm module {} does not exist",
            candidate.display()
        );
        return Ok(candidate);
    }

    if let Some((module, _bin_dir)) = locate_runtime_module(paths) {
        Ok(module)
    } else {
        Err(anyhow!(
            "runtime module not found under {}",
            paths.pgroot.display()
        ))
    }
}

fn resolve_pg_dump(paths: &PglitePaths) -> Result<PathBuf> {
    ensure_runtime(paths)?;
    let bin_dir = paths.pgroot.join("pglite").join("bin");
    let candidates = [
        "pg_dump",
        "pg_dump.wasi",
        "pg_dump.wasm",
        "pgdump.wasi",
        "pgdump.wasm",
    ];

    for name in candidates {
        let candidate = bin_dir.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    anyhow::bail!(
        "pg_dump binary not found under {} (looked for {:?})",
        bin_dir.display(),
        candidates
    )
}

fn run_wasi_command(
    paths: &PglitePaths,
    module_path: &Path,
    argv: &[&str],
    env: &[(&str, &str)],
) -> Result<i32> {
    ensure_runtime(paths)?;
    let engine = create_engine()?;
    let module = Module::from_file(&engine, module_path)?;

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    add_to_linker_sync(&mut linker, |cx: &mut WasiP1Ctx| cx)?;

    let mut builder = standard_wasi_builder(paths)?;

    for (key, value) in env {
        builder.env(key, value);
    }

    let mut argv_vec: Vec<String> = if argv.is_empty() {
        vec![module_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("pg_dump")
            .to_string()]
    } else {
        argv.iter().map(|s| (*s).to_string()).collect()
    };

    if let Some(first) = argv_vec.first_mut() {
        if Path::new(first).is_relative() {
            let guest_path = module_path
                .strip_prefix(&paths.pgroot)
                .map(|rel| Path::new("/tmp").join(rel))
                .unwrap_or_else(|_| PathBuf::from("/tmp/pglite/bin/pg_dump"));
            *first = guest_path.to_string_lossy().into_owned();
        }
    }

    for arg in &argv_vec {
        builder.arg(arg);
    }

    let wasi = builder.build();
    let mut store = Store::new(&engine, WasiP1Ctx::new(wasi));
    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;

    match start.call(&mut store, ()) {
        Ok(()) => Ok(0),
        Err(err) => {
            for cause in err.chain() {
                if let Some(exit) = cause.downcast_ref::<I32Exit>() {
                    return Ok(exit.0);
                }
                if let Some(trap) = cause.downcast_ref::<Trap>() {
                    let module_name = module_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default();
                    if matches!(trap, Trap::UnreachableCodeReached)
                        && module_name.contains("pg_dump")
                    {
                        warn!("pg_dump exited via unreachable trap; treating as success (0)");
                        return Ok(0);
                    }
                }
            }
            let message = err.to_string();
            if let Some(rest) = message.strip_prefix("Exited with i32 exit status ") {
                if let Ok(code) = rest.trim().parse::<i32>() {
                    return Ok(code);
                }
            }
            Err(err)
        }
    }
}
