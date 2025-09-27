use std::fs;
use std::path::{Component, Path};

use anyhow::Result;
use serial_test::serial;
use tempfile::TempDir;

use pglite_oxide::interactive::{
    exec_interactive, pg_dump_path, poke, run_pg_dump, wasm_import, InteractiveRuntime, PokeInput,
};
use pglite_oxide::{
    ensure_cluster, ensure_runtime, install_and_init, install_and_init_in, install_with_options,
    prepare_default_mount, InstallOptions, PglitePaths,
};

fn temp_paths() -> (TempDir, PglitePaths) {
    let td = tempfile::tempdir().expect("tmpdir");
    let base = td.path().to_path_buf();
    let paths = PglitePaths {
        pgroot: base.join("pglite"),
        pgdata: base.join("db"),
    };
    (td, paths)
}

fn collect_message_tags(buf: &[u8]) -> Result<Vec<u8>> {
    let mut tags = Vec::new();
    let mut index = 0usize;
    while index < buf.len() {
        if buf.len() - index < 5 {
            anyhow::bail!("incomplete message");
        }
        let tag = buf[index];
        let len = u32::from_be_bytes(buf[index + 1..index + 5].try_into().unwrap()) as usize;
        if len < 4 {
            anyhow::bail!("invalid message length");
        }
        let total = 1 + len;
        if index + total > buf.len() {
            anyhow::bail!("message overruns buffer");
        }
        tags.push(tag);
        index += total;
    }
    Ok(tags)
}

#[test]
#[serial]
fn unpack_runtime_once() -> Result<()> {
    let (_td, paths) = temp_paths();

    ensure_runtime(&paths)?;
    assert!(paths
        .pgroot
        .join("pglite")
        .join("bin")
        .join("pglite.wasi")
        .exists());
    assert!(paths.pgroot.join("pglite").join("share").exists());
    assert!(paths.pgroot.join("pglite").join("lib").exists());
    Ok(())
}

#[test]
#[serial]
fn unpack_runtime_is_idempotent() -> Result<()> {
    let (_td, paths) = temp_paths();
    ensure_runtime(&paths)?;
    ensure_runtime(&paths)?;
    assert!(paths
        .pgroot
        .join("pglite")
        .join("bin")
        .join("pglite.wasi")
        .exists());
    Ok(())
}

#[test]
#[serial]
fn init_cluster_creates_pgdata() -> Result<()> {
    let (_td, paths) = temp_paths();
    ensure_runtime(&paths)?;
    assert!(paths
        .pgroot
        .join("pglite")
        .join("bin")
        .join("pglite.wasi")
        .exists());
    ensure_cluster(&paths)?;
    assert!(paths.pgdata.join("PG_VERSION").exists());
    assert!(paths.pgdata.join("global").join("pg_control").exists());
    Ok(())
}

#[test]
#[serial]
fn init_cluster_is_idempotent() -> Result<()> {
    let (_td, paths) = temp_paths();
    ensure_runtime(&paths)?;
    assert!(paths
        .pgroot
        .join("pglite")
        .join("bin")
        .join("pglite.wasi")
        .exists());
    ensure_cluster(&paths)?;
    ensure_cluster(&paths)?;
    assert!(paths.pgdata.join("PG_VERSION").exists());
    Ok(())
}

#[test]
#[serial]
fn end_to_end_install_and_init() -> Result<()> {
    let (_td, mut paths) = temp_paths();
    paths = {
        ensure_runtime(&paths)?;
        assert!(paths
            .pgroot
            .join("pglite")
            .join("bin")
            .join("pglite.wasi")
            .exists());
        ensure_cluster(&paths)?;
        paths
    };
    assert!(paths
        .pgroot
        .join("pglite")
        .join("bin")
        .join("pglite.wasi")
        .exists());
    assert!(paths.pgdata.join("PG_VERSION").exists());
    Ok(())
}

#[test]
#[serial]
fn install_and_init_in_respects_root() -> Result<()> {
    let td = tempfile::tempdir()?;
    let root = td.path().join("custom_root");
    let paths = install_and_init_in(&root)?;

    assert_eq!(paths.pgroot, root);
    assert_eq!(paths.pgdata, root.join("pglite").join("base"));
    assert!(paths
        .pgroot
        .join("pglite")
        .join("bin")
        .join("pglite.wasi")
        .exists());
    assert!(paths.pgdata.join("PG_VERSION").exists());
    Ok(())
}

#[test]
#[serial]
fn install_and_init_detects_existing_tmp_mount() -> Result<()> {
    if Path::new("tmp").exists() {
        fs::remove_dir_all("tmp")?;
    }

    let initial = install_and_init_in("tmp")?;
    assert_eq!(initial.pgroot, Path::new("tmp"));
    assert!(initial.pgdata.join("PG_VERSION").exists());

    let reused = install_and_init(("com", "example", "reuse_tmp"))?;
    assert_eq!(reused.pgroot, Path::new("tmp"));
    assert!(reused.pgdata.join("PG_VERSION").exists());

    fs::remove_dir_all("tmp")?;
    Ok(())
}

#[test]
#[serial]
fn install_with_options_runtime_only() -> Result<()> {
    let (_td, paths) = temp_paths();
    let paths = install_with_options(
        paths,
        InstallOptions {
            ensure_cluster: false,
        },
    )?;

    assert!(paths
        .pgroot
        .join("pglite")
        .join("bin")
        .join("pglite.wasi")
        .exists());
    assert!(!paths.pgdata.join("PG_VERSION").exists());
    Ok(())
}

#[test]
#[serial]
fn prepare_default_mount_prefers_tmp() -> Result<()> {
    if Path::new("tmp").exists() {
        fs::remove_dir_all("tmp")?;
    }

    let mount = prepare_default_mount()?;
    assert_eq!(mount.mount(), Path::new("tmp"));
    assert!(matches!(
        mount.io_socket().components().next(),
        Some(Component::CurDir)
    ));
    assert!(mount.paths().pgdata.join("PG_VERSION").exists());
    assert!(!mount.reused_existing());

    let reused = prepare_default_mount()?;
    assert!(reused.reused_existing());

    fs::remove_dir_all("tmp")?;
    Ok(())
}

#[test]
#[serial]
fn interactive_helpers_align_with_runtime() -> Result<()> {
    if Path::new("tmp").exists() {
        fs::remove_dir_all("tmp")?;
    }

    let mut runtime = InteractiveRuntime::prepare_default()?;
    let wasm_path = runtime.module_path("postgres", None)?;
    assert!(wasm_path.exists());

    if let Ok(dump_path) = runtime.pg_dump_path() {
        assert!(dump_path.exists());
    }

    // Ensure the default global cache also resolves modules.
    let default_path = wasm_import("postgres", None)?;
    assert!(default_path.exists());

    if let Ok(default_dump) = pg_dump_path() {
        assert!(default_dump.exists());
    }

    match run_pg_dump(&["pg_dump", "--version"], &[]) {
        Ok(Some(code)) => assert_eq!(code, 0),
        Ok(None) => (),
        Err(err) => {
            eprintln!("pg_dump --version failed: {err:#}");
        }
    }

    let (bytes, len) = poke(PokeInput::Str("select 1"))?;
    assert_eq!(bytes[len - 1], 0);
    assert_eq!(len, bytes.len());

    let response = exec_interactive(PokeInput::Str("select 1;"))?;
    let tags = collect_message_tags(&response)?;
    assert!(tags.contains(&b'Z'));

    fs::remove_dir_all("tmp")?;
    Ok(())
}
