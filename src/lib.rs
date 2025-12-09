use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use std::{
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};
use tar::Archive;
use tracing::{debug, info, warn};
use xz2::read::XzDecoder;

use flate2::read::GzDecoder;

pub mod interactive;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::preview1::add_to_linker_sync;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder, WasiP1Ctx};

/// Initialize tracing with verbose logging
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("pglite_oxide=trace,info"))
        .init();
}

const EMBEDDED_TAR_XZ: &[u8] = include_bytes!("../assets/pglite-wasi.tar.xz");

#[cfg(unix)]
fn ensure_shim(src: &Path, dst: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;
    if !dst.exists() {
        if let Err(e) = symlink(src, dst) {
            let _ = std::fs::copy(src, dst).with_context(|| {
                format!(
                    "copy {} -> {} (fallback after symlink error: {e})",
                    src.display(),
                    dst.display()
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_shim(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        std::fs::copy(src, dst)
            .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
    }
    Ok(())
}

pub(crate) fn seed_urandom_once(dev_host: &Path) -> Result<()> {
    fs::create_dir_all(dev_host)?;
    let urandom_path = dev_host.join("urandom");
    if !urandom_path.exists() {
        let mut buf = [0u8; 128];
        getrandom::getrandom(&mut buf)?; // real entropy
        fs::write(&urandom_path, buf)?; // create once
    }
    Ok(())
}

pub(crate) fn create_engine() -> Result<Engine> {
    let mut cfg = wasmtime::Config::new();
    cfg.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
    Engine::new(&cfg)
}

pub(crate) fn prepare_guest_dirs(paths: &PglitePaths) -> Result<()> {
    let dev_host = paths.pgroot.join("dev");
    seed_urandom_once(&dev_host)?;
    fs::create_dir_all(&paths.pgdata)?;
    Ok(())
}

pub(crate) fn standard_wasi_builder(paths: &PglitePaths) -> Result<WasiCtxBuilder> {
    prepare_guest_dirs(paths)?;

    let pgroot_dir = Dir::open_ambient_dir(&paths.pgroot, ambient_authority())?;
    let pgdata_dir = Dir::open_ambient_dir(&paths.pgdata, ambient_authority())?;
    let dev_dir_path = paths.pgroot.join("dev");
    let dev_dir = Dir::open_ambient_dir(&dev_dir_path, ambient_authority())?;

    let mut builder = WasiCtxBuilder::new();
    builder
        .inherit_stdin()
        .preopened_dir(pgroot_dir, DirPerms::all(), FilePerms::all(), "/tmp")
        .preopened_dir(
            pgdata_dir,
            DirPerms::all(),
            FilePerms::all(),
            "/tmp/pglite/base",
        )
        .preopened_dir(dev_dir, DirPerms::all(), FilePerms::all(), "/dev")
        .env("ENVIRONMENT", "wasm32_wasi_preview1")
        .env("PREFIX", "/tmp/pglite")
        .env("PGDATA", "/tmp/pglite/base")
        .env("PGSYSCONFDIR", "/tmp/pglite")
        .env("PGUSER", "postgres")
        .env("PGDATABASE", "template1")
        .env("MODE", "REACT")
        .env("REPL", "N")
        .env("TZ", "UTC")
        .env("PGTZ", "UTC")
        .env("PATH", "/tmp/pglite/bin");

    let stdio_mode = std::env::var("PGLITE_WASI_STDIO").unwrap_or_default();
    if matches!(stdio_mode.as_str(), "1" | "true" | "TRUE" | "True") {
        builder.inherit_stdout().inherit_stderr();
    }

    Ok(builder)
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn assets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets")
}

fn install_optional_pg_dump(paths: &PglitePaths) -> Result<()> {
    let src = assets_dir().join("bin/pg_dump.wasm");
    if !src.exists() {
        return Ok(());
    }

    let dest_dir = paths.pgroot.join("pglite/bin");
    fs::create_dir_all(&dest_dir)?;

    let wasm_dest = dest_dir.join("pg_dump.wasm");
    fs::copy(&src, &wasm_dest)
        .with_context(|| format!("copy {} -> {}", src.display(), wasm_dest.display()))?;

    let plain_dest = dest_dir.join("pg_dump");
    if !plain_dest.exists() {
        fs::copy(&wasm_dest, &plain_dest).ok();
    }

    Ok(())
}

fn install_optional_extensions(paths: &PglitePaths) -> Result<()> {
    let dir = assets_dir().join("extensions");
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if !path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|name| name.ends_with(".tar.gz"))
            .unwrap_or(false)
        {
            continue;
        }

        let ext_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|name| name.strip_suffix(".tar.gz"))
            .unwrap_or("");

        let control_path = paths
            .pgroot
            .join("pglite/share/extension")
            .join(format!("{}.control", ext_name));
        if control_path.exists() {
            continue;
        }

        install_extension_archive(paths, &path)?;
    }

    Ok(())
}

pub fn install_extension_archive(paths: &PglitePaths, archive_path: &Path) -> Result<()> {
    let file = fs::File::open(archive_path)
        .with_context(|| format!("open extension archive {}", archive_path.display()))?;
    install_extension_reader(paths, file)
}

pub fn install_extension_bytes(paths: &PglitePaths, bytes: &[u8]) -> Result<()> {
    install_extension_reader(paths, Cursor::new(bytes))
}

fn install_extension_reader<R: Read>(paths: &PglitePaths, reader: R) -> Result<()> {
    let gz = GzDecoder::new(reader);
    let mut ar = Archive::new(gz);
    let target = paths.pgroot.join("pglite");
    fs::create_dir_all(&target)?;
    ar.unpack(&target)
        .with_context(|| format!("unpack extension into {}", target.display()))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PglitePaths {
    pub pgroot: PathBuf,
    pub pgdata: PathBuf,
}

impl PglitePaths {
    pub fn new(app_qual: (&str, &str, &str)) -> Result<Self> {
        let pd = ProjectDirs::from(app_qual.0, app_qual.1, app_qual.2)
            .context("could not resolve app data dir")?;
        let app_dir = pd.data_dir().to_path_buf();
        let pgroot = app_dir.join("pglite");
        let pgdata = app_dir.join("db");
        Ok(Self { pgroot, pgdata })
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        let pgroot = root.into();
        let pgdata = pgroot.join("pglite").join("base");
        Self { pgroot, pgdata }
    }

    pub fn with_paths(pgroot: impl Into<PathBuf>, pgdata: impl Into<PathBuf>) -> Self {
        Self {
            pgroot: pgroot.into(),
            pgdata: pgdata.into(),
        }
    }

    /// Detect the legacy/local mount layouts that the Python helper supports.
    pub fn detect_existing_mounts() -> Option<Self> {
        for raw in ["tmp", "/tmp"] {
            let base = PathBuf::from(raw);
            let pgdata = base.join("pglite").join("base");
            if pgdata.join("PG_VERSION").exists() {
                return Some(Self {
                    pgroot: base,
                    pgdata,
                });
            }
        }
        None
    }

    pub fn mount_root(&self) -> &Path {
        &self.pgroot
    }

    fn marker_runtime(&self) -> PathBuf {
        self.pgroot.join(".runtime_ready")
    }
    fn marker_cluster(&self) -> PathBuf {
        self.pgdata.join("PG_VERSION")
    }
}

fn promote_nested_runtime(paths: &PglitePaths) -> Result<()> {
    let nested = paths.pgroot.join("tmp").join("pglite");
    let nested_bin = nested.join("bin");
    if nested_bin.join("pglite.wasi").exists() {
        for entry in std::fs::read_dir(&nested).context("read nested pglite dir")? {
            let entry = entry?;
            let name = entry.file_name();
            let src = entry.path();
            let dst = paths.pgroot.join(name);
            let metadata = match std::fs::symlink_metadata(&dst) {
                Ok(metadata) => Some(metadata),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(err).with_context(|| format!("inspect {}", dst.display()));
                }
            };
            if let Some(metadata) = metadata {
                if metadata.file_type().is_dir() {
                    std::fs::remove_dir_all(&dst)
                        .with_context(|| format!("remove dir {}", dst.display()))?;
                } else {
                    std::fs::remove_file(&dst)
                        .with_context(|| format!("remove file {}", dst.display()))?;
                }
            }
            std::fs::rename(&src, &dst)
                .with_context(|| format!("promote {} -> {}", src.display(), dst.display()))?;
        }
        let _ = std::fs::remove_dir_all(paths.pgroot.join("tmp"));
    }
    Ok(())
}

fn ensure_pglite_layout(paths: &PglitePaths) -> Result<()> {
    let pglite_dir = paths.pgroot.join("pglite");
    if !pglite_dir.exists() {
        fs::create_dir_all(&pglite_dir)?;
    }

    for name in ["bin", "share", "lib", "password"] {
        let src = paths.pgroot.join(name);
        if src.exists() {
            let dst = pglite_dir.join(name);
            let moved = std::fs::rename(&src, &dst).is_ok();
            if !moved {
                if src.is_dir() {
                    std::fs::create_dir_all(&dst)?;
                    copy_dir_all(&src, &dst).with_context(|| {
                        format!("copy dir {} -> {}", src.display(), dst.display())
                    })?;
                    std::fs::remove_dir_all(&src)?;
                } else {
                    std::fs::copy(&src, &dst).with_context(|| {
                        format!("copy file {} -> {}", src.display(), dst.display())
                    })?;
                    std::fs::remove_file(&src)?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn locate_runtime_module(paths: &PglitePaths) -> Option<(PathBuf, PathBuf)> {
    let pglite_dir = paths.pgroot.join("pglite");
    if !pglite_dir.exists() {
        return None;
    }
    let pglite_bin_dir = pglite_dir.join("bin");
    let module = if pglite_bin_dir.join("pglite.wasi").exists() {
        pglite_bin_dir.join("pglite.wasi")
    } else {
        return None;
    };

    let share = pglite_dir.join("share").join("postgresql");
    if !share.exists() || !share.is_dir() {
        return None;
    }
    if !share.join("postgres.bki").exists() {
        return None;
    }
    Some((module, pglite_bin_dir))
}

fn finalize_runtime_setup(
    paths: &PglitePaths,
    module_path: &Path,
    pglite_bin_dir: &Path,
) -> Result<()> {
    ensure_shim(module_path, &pglite_bin_dir.join("initdb"))?;
    ensure_shim(module_path, &pglite_bin_dir.join("postgres"))?;
    fs::write(paths.marker_runtime(), b"ok")?;
    Ok(())
}

pub fn ensure_runtime(paths: &PglitePaths) -> Result<()> {
    if let Some((module_path, bin_dir)) = locate_runtime_module(paths) {
        install_optional_pg_dump(paths)?;
        install_optional_extensions(paths)?;
        finalize_runtime_setup(paths, &module_path, &bin_dir)?;
        return Ok(());
    }

    if paths.marker_runtime().exists() {
        let _ = fs::remove_file(paths.marker_runtime());
    }

    fs::create_dir_all(&paths.pgroot).context("create pgroot dir")?;
    promote_nested_runtime(paths)?;
    ensure_pglite_layout(paths)?;
    install_optional_pg_dump(paths)?;
    install_optional_extensions(paths)?;

    if let Some((module_path, bin_dir)) = locate_runtime_module(paths) {
        finalize_runtime_setup(paths, &module_path, &bin_dir)?;
        return Ok(());
    }

    if let Ok(override_path) = std::env::var("PGLITE_OXIDE_TAR_XZ") {
        let file = std::fs::File::open(&override_path)
            .with_context(|| format!("open override tar.xz: {}", override_path))?;
        let mut decoder = XzDecoder::new(file);
        let mut ar = Archive::new(&mut decoder);
        ar.unpack(&paths.pgroot)
            .with_context(|| format!("unpack override tar.xz from {}", override_path))?;
    } else {
        let mut decoder = XzDecoder::new(EMBEDDED_TAR_XZ);
        let mut ar = Archive::new(&mut decoder);
        ar.unpack(&paths.pgroot)
            .context("unpack embedded pglite-wasi.tar.xz")?;
    }

    promote_nested_runtime(paths)?;
    ensure_pglite_layout(paths)?;
    install_optional_pg_dump(paths)?;
    install_optional_extensions(paths)?;

    let (module_path, bin_dir) = locate_runtime_module(paths).ok_or_else(|| {
        anyhow!(
            "runtime missing: could not locate module under {} after install",
            paths.pgroot.display()
        )
    })?;

    finalize_runtime_setup(paths, &module_path, &bin_dir)
}

#[allow(clippy::const_is_empty)]
pub fn embedded_runtime_present() -> bool {
    !EMBEDDED_TAR_XZ.is_empty()
}

pub fn ensure_cluster(paths: &PglitePaths) -> Result<()> {
    if paths.marker_cluster().exists() {
        return Ok(());
    }

    ensure_runtime(paths)?;
    fs::create_dir_all(&paths.pgdata).context("create pgdata dir")?;

    // Password file expected at /password (relative to PREFIX)
    let pw_path = paths.pgroot.join("pglite").join("password");
    if !pw_path.exists() {
        fs::write(&pw_path, "localdevpassword\n").context("write password file")?;
    }

    let mut cfg = wasmtime::Config::new();
    cfg.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
    let engine = Engine::new(&cfg)?;

    let pglite_bin_dir = paths.pgroot.join("pglite").join("bin");
    let module_path = pglite_bin_dir.join("pglite.wasi");
    let module = Module::from_file(&engine, &module_path)
        .with_context(|| format!("load module at {}", module_path.display()))?;

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    add_to_linker_sync(&mut linker, |cx: &mut WasiP1Ctx| cx)?;

    // Ensure cluster dir is empty for clean init
    if paths.pgdata.exists() {
        for entry in std::fs::read_dir(&paths.pgdata)? {
            let entry = entry?;
            if entry.file_name() != "PG_VERSION" {
                let path = entry.path();
                if path.is_dir() {
                    std::fs::remove_dir_all(&path)?;
                } else {
                    std::fs::remove_file(&path)?;
                }
            }
        }
    }

    // Build WASI ctx/instance
    let mut b = standard_wasi_builder(paths)?;

    // Boot argv mirrors: `/tmp/pglite/bin/postgres --single postgres`
    let wasi = b
        .args(&["/tmp/pglite/bin/postgres", "--single", "postgres"])
        .build();

    let mut store = Store::new(&engine, WasiP1Ctx::new(wasi));
    let instance = linker.instantiate(&mut store, &module)?;

    // 1) Embed setup first
    info!("[pglite_oxide] Starting embed setup...");
    if let Ok(start) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
        let _ = start.call(&mut store, ());
        info!("[pglite_oxide] Embed setup completed");
    } else {
        warn!("[pglite_oxide] No _start export found");
    }

    // 2) Run initdb on the SAME instance; it reads env (PGDATA, PGSHAREDIR, POSTGRES, PREFIX)
    debug!("[pglite_oxide] Looking for initdb export...");
    let initdb = instance.get_typed_func::<(), i32>(&mut store, "pgl_initdb")?;

    info!("[pglite_oxide] Calling initdb...");
    let rc = initdb.call(&mut store, ())?;
    info!("[pglite_oxide] initdb returned: {}", rc);
    // Some pglite builds return non-zero even on success; trust the marker.
    if !paths.marker_cluster().exists() {
        anyhow::bail!("pgl_initdb rc={rc} but PG_VERSION not created");
    }

    // Best-effort graceful shutdown if exposed
    if let Ok(shutdown) = instance.get_typed_func::<(), ()>(&mut store, "pgl_shutdown") {
        let _ = shutdown.call(&mut store, ());
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct InstallOptions {
    pub ensure_cluster: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            ensure_cluster: true,
        }
    }
}

pub fn install_and_init(app_qual: (&str, &str, &str)) -> Result<PglitePaths> {
    if let Some(existing) = PglitePaths::detect_existing_mounts() {
        info!(
            "[pglite_oxide] Reusing existing runtime at {}",
            existing.pgroot.display()
        );
        return install_with_options(existing, InstallOptions::default());
    }

    let paths = PglitePaths::new(app_qual)?;
    install_with_options(paths, InstallOptions::default())
}

pub fn install_and_init_with_paths(paths: PglitePaths) -> Result<PglitePaths> {
    install_with_options(paths, InstallOptions::default())
}

pub fn install_and_init_in(root: impl Into<PathBuf>) -> Result<PglitePaths> {
    let paths = PglitePaths::with_root(root);
    install_with_options(paths, InstallOptions::default())
}

pub fn install_with_options(paths: PglitePaths, options: InstallOptions) -> Result<PglitePaths> {
    ensure_runtime(&paths)?;
    if options.ensure_cluster {
        ensure_cluster(&paths)?;
    }
    Ok(paths)
}

#[derive(Debug, Clone)]
pub struct MountInfo {
    mount: PathBuf,
    io_socket: PathBuf,
    paths: PglitePaths,
    reused_existing: bool,
}

impl MountInfo {
    pub fn into_paths(self) -> PglitePaths {
        self.paths
    }

    pub fn mount(&self) -> &Path {
        &self.mount
    }

    pub fn io_socket(&self) -> &Path {
        &self.io_socket
    }

    pub fn paths(&self) -> &PglitePaths {
        &self.paths
    }

    pub fn reused_existing(&self) -> bool {
        self.reused_existing
    }
}

pub fn prepare_default_mount() -> Result<MountInfo> {
    if let Some(existing) = PglitePaths::detect_existing_mounts() {
        let reused_existing = true;
        ensure_runtime(&existing)?;
        if !existing.marker_cluster().exists() {
            ensure_cluster(&existing)?;
        }
        let io_socket = resolve_io_socket(&existing);
        return Ok(MountInfo {
            mount: existing.pgroot.clone(),
            io_socket,
            paths: existing,
            reused_existing,
        });
    }

    let local_paths = PglitePaths::with_root(PathBuf::from("tmp"));
    install_with_options(
        local_paths.clone(),
        InstallOptions {
            ensure_cluster: false,
        },
    )?;
    if !local_paths.marker_cluster().exists() {
        ensure_cluster(&local_paths)?;
    }
    let io_socket = resolve_io_socket(&local_paths);
    Ok(MountInfo {
        mount: local_paths.pgroot.clone(),
        io_socket,
        paths: local_paths,
        reused_existing: false,
    })
}

fn resolve_io_socket(paths: &PglitePaths) -> PathBuf {
    let mount = &paths.pgroot;
    let io = paths.pgdata.join(".s.PGSQL.5432");
    if mount.is_absolute() {
        io
    } else {
        Path::new(".").join(io)
    }
}
