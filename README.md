# pglite-oxide

pglite-oxide is the Rust companion to the [Electric SQL pglite](https://github.com/electric-sql/pglite) [WASM builds](https://github.com/electric-sql/pglite-build). It gives a consumer-level API for installing and running a self-contained PostgreSQL 17.x instance inside a WebAssembly guest, so you can embed "real Postgres" into CLI tools, desktop apps, server side functions, or tests without talking to a separate Postgres service. This document explains how to install the kit, the modes it supports, and the knobs you can turn to adapt it to your own runtime.

## Installation Patterns

The crate ships with a prebuilt pglite-wasi.tar.xz. You have three options for provisioning it:

### Default initialization (recommended)

```rust
let paths = pglite_oxide::install_and_init(("com", "example", "app"))?;
```

- Installs the WASM runtime into the operating system's data directory for that app ID (see directories::ProjectDirs).
- Runs pg_initdb inside the WASM guest.
- Returns PglitePaths { pgroot, pgdata } where pgroot holds the runtime and pgdata is the database cluster.

### Specify an explicit mount root

```rust
let paths = pglite_oxide::install_and_init_in("/custom/location")?;
```

Useful for portable binaries or integration tests where you want to keep the runtime under /tmp, inside your project tree, etc.

### Fine-grained control

```rust
let paths = pglite_oxide::install_with_options(
    PglitePaths::with_root("/opt/pglite"),
    InstallOptions { ensure_cluster: false },
)?;
```

- You can skip initdb if you only want the runtime binaries.
- Later call ensure_cluster(&paths) manually once you want a database.

All of the helpers detect existing installs: if tmp/pglite/base/PG_VERSION or /tmp/pglite/base/PG_VERSION already exists, the kit reuses them instead of unpacking another archive.

## Runtime API ("interactive" module)

Most consumers only need the top-level functions in pglite_oxide::interactive:

| Function | Purpose |
|----------|---------|
| `prepare_default_mount()` | Returns MountInfo with the auto-detected runtime + cluster, creating them on demand. The example binary uses this. |
| `wasm_import(alias, path)` | Ensures the default session is initialized and returns the path to the WASM module (you can use this if you need to spawn your own Wasmtime instance). |
| `exec_interactive(PokeInput)` | Sends bytes over the WASM-backed Postgres wire protocol and returns the raw response. This performs the full startup handshake the first time it runs. |
| `poke(PokeInput) + interactive_one()` | Lower-level helpers for REPL-style usage; poke flashes SQL into the shared buffer and interactive_one ticks the host once. |
| `run_pg_dump(argv, env)` | Invokes the optional pg_dump shim if it exists in the runtime. Returns Ok(None) when the archive didn't include that artifact. |
| `default_mount()` | Gives you the same MountInfo the global runtime uses (good for exposing the socket path or the installation root). |
| `start_proxy(use_tcp)` | Launches the full socket proxy to /tmp/.s.PGSQL.5432 (Unix) or 0.0.0.0:5432 (TCP). This allows external clients like psql to connect to the WASM backend. |

PokeInput accepts either &str (we append the null terminator) or raw bytes.

### Under the hood

The crate decides between two transports:

- **CMA channel available** – the WASM exports a shared-memory channel (get_channel() >= 0). The kit writes requests directly into the CMA buffer and issues interactive_write(len).
- **File-based fallback** – when the CMA channel is missing, the kit uses the .in/.out lock files (/tmp/pglite/base/.s.PGSQL.5432{.in,.out}). The run_tests_quick helper only runs when we're in file mode.

You normally don't need to reason about which transport is active; the helpers handle that automatically.

## Knobs & Environment

When we instantiate the WASI context (standard_wasi_builder), we pre-open three directories inside the guest:

- `/tmp` -> the runtime root (pgroot)
- `/tmp/pglite/base` -> the cluster data directory (pgdata)
- `/dev` -> a shim directory for things like urandom

We also set the environment variables Postgres expects:

| Environment variable | Default |
|---------------------|---------|
| `ENVIRONMENT` | wasm32_wasi_preview1 |
| `PREFIX` / `PGDATA` / `PGSYSCONFDIR` | /tmp/pglite / /tmp/pglite/base / /tmp/pglite |
| `PGUSER` / `PGDATABASE` | postgres / template1 |
| `MODE` / `REPL` | REACT / N |
| `PGCLIENTENCODING`, `LC_CTYPE`, `PG_COLOR`, `PATH`, `TZ`, `PGTZ` | Standard defaults |

Override them by modifying the WasiCtxBuilder before you call into interactive::wasm_import or interactive::exec_interactive. For advanced scenarios, grab the builder yourself:

```rust
let mut builder = pglite_oxide::standard_wasi_builder(&paths)?;
builder.env("PGDATABASE", "custom_db");
```

Similarly, you can provide different runtime modules by passing Some(path) into wasm_import, or by placing alternate .wasi files under paths.pgroot/pglite/bin/.

## Embedding Patterns

### Run ad-hoc SQL within Rust

```rust
let response = interactive::exec_interactive(PokeInput::Str("SELECT 42;"))?;
println!("{}", interactive::hexc(&response, "<-", Some(4)));
```

You get the raw Postgres wire response. For higher-level decoding plug in a Postgres wire parser (e.g. tokio-postgres's frame decoder) or reuse the CMA buffer via poke + interactive_one.

### Expose a real Postgres socket

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Start a Unix domain socket at /tmp/.s.PGSQL.5432
    interactive::start_proxy(false).await
}
```

This gives external tools access to the WASM backend. The proxy forwards raw startup packets, handles CMA/file transport, and recovers from interactive_one traps by clearing the channel.

### Ship pg_dump in your application

Call `run_pg_dump(&["pg_dump", "--schema-only"], &[("PGDATABASE", "mydb")])` to execute the embedded CLI. The helper returns Ok(None) if the asset isn't bundled.

### Custom runtimes (CI builds, development)

Place an alternate pglite.wasi somewhere and let `wasm_import("postgres", Some(custom_path))` resolve it. The crate's installer already honors tmp/pglite vs /tmp/pglite detection, so you can drop a development build into /tmp/pglite and the kit will reuse it.

## Managing the Data Directory

PglitePaths exposes pgroot and pgdata. The kit writes a marker file (PG_VERSION) after initdb. You can safely remove the pgroot directory between runs to force a clean install:

```rust
std::fs::remove_dir_all(paths.pgroot)?;
```

During testing, the smoke suite uses temporary directories (see tests/pglite_smoke.rs) and ensures we clean them up afterwards.

### Runtime layout

The unpacked runtime lives under `<mount>/pglite/` with familiar Postgres directories (`bin`, `lib`, `share`, `password`, `tmp`). Core extensions, including `plpgsql`, ship in `share/extension` so they are ready for immediate use inside the WASM guest.

## Example Binary (runtime_showcase)

Build and run:

```bash
cargo run -p pglite-oxide --example runtime_showcase
```

The example prints the mount root, socket path, whether it reused an existing install, then runs a simple SELECT 1; through exec_interactive and logs the hex-dump of the response. It finishes by invoking pg_dump --version.

## Proxy Example (psql-friendly)

Expose a Postgres-compatible socket for GUI tools or `psql` by running:

```bash
cargo run -p pglite-oxide --example proxy_showcase
```

By default the example binds the canonical Unix socket `/tmp/.s.PGSQL.5432`. GUI tools that support sockets usually expose it as a “socket directory” field—point them at `/tmp`, with user `postgres` and database `template1`. The libpq-style connection URI looks like:

```
postgresql://postgres@/template1?host=/tmp
```

Pass `--tcp` after the `--` delimiter to listen on `0.0.0.0:5432` instead:

```bash
cargo run -p pglite-oxide --example proxy_showcase -- --tcp
```

Clients can then use a standard URI such as `postgresql://postgres@127.0.0.1:5432/template1`. Use `--uds` to return to socket mode. Hit Ctrl+C when you want to tear the proxy down.

## Proxy Lifecycles and Error Handling

- The interactive session lazily performs the wire handshake on the first exec_interactive call. If you use poke + interactive_one without calling use_wire(true), it stays in the REPL (non-wire) mode.
- When interactive_one throws a WASM trap, the runtime recovers by: clear_error(), resets the CMA length (interactive_write(-1)), and can re-attempt the handshake.
- start_proxy runs run_tests_quick() only in file-transport mode. That helper feeds a handful of SQL statements via REPL to prove the backend responds before accepting real connections.

## Summary of Key Types

- **PglitePaths** – descriptive struct with pgroot and pgdata.
- **MountInfo** – wraps PglitePaths and tracks the mount root, socket path, and whether an existing install was reused.
- **InteractiveRuntime** – owns the Wasmtime engine, store, and exports. Normally you access it through the global with_default_runtime.
- **Transport enum** – internal, describes CMA vs file transport (automatic).
- **PokeInput<'a>** – either Str(&'a str) or Bytes(&'a [u8]).

## Putting It Together

A minimal "headless Postgres in WASM" flow looks like:

```rust
fn main() -> anyhow::Result<()> {
    // Ensure the runtime and cluster exist (or reuse an existing /tmp/pglite)
    let _mount = pglite_oxide::prepare_default_mount()?;

    // Run SQL inside the WASM backend
    let response = pglite_oxide::interactive::exec_interactive(
        pglite_oxide::interactive::PokeInput::Str("SELECT current_database();")
    )?;

    println!(
        "Postgres wire response:\n{}",
        pglite_oxide::interactive::hexc(&response, "<-", Some(6))
    );

    Ok(())
}
```
