use std::env;

use anyhow::{bail, Result};

use pglite_oxide::interactive;
use pglite_oxide::prepare_default_mount;
use tokio::runtime::Builder;

#[derive(Copy, Clone, Eq, PartialEq)]
enum ProxyMode {
    Unix,
    Tcp,
}

fn main() -> Result<()> {
    let mode = parse_mode()?;
    let mount = prepare_default_mount()?;

    println!("pglite mount root: {}", mount.mount().display());
    println!("cluster data dir: {}", mount.paths().pgdata.display());
    println!("postgres username: postgres");
    println!("postgres database: template1");
    println!("Press Ctrl+C to stop the proxy\n");

    interactive::with_default_runtime(|rt| rt.ensure_handshake())?;

    match mode {
        ProxyMode::Unix => {
            println!("listening on unix socket: /tmp/.s.PGSQL.5432");
            println!("Example connection string: postgresql://postgres@/template1?host=/tmp");
            println!("Most GUI tools call this the \"socket directory\" -> /tmp\n");
        }
        ProxyMode::Tcp => {
            println!("listening on tcp: 0.0.0.0:5432");
            println!("Example connection string: postgresql://postgres@127.0.0.1:5432/template1");
            println!("(Use your LAN/WAN address instead of 127.0.0.1 if needed)\n");
        }
    }

    let rt = Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async { interactive::start_proxy(mode == ProxyMode::Tcp).await })
}

fn parse_mode() -> Result<ProxyMode> {
    let mut mode = ProxyMode::Unix;

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--tcp" => mode = ProxyMode::Tcp,
            "--uds" => mode = ProxyMode::Unix,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                bail!("unknown argument: {other}");
            }
        }
    }

    Ok(mode)
}

fn print_usage() {
    eprintln!("Usage: proxy_showcase [--tcp | --uds]");
    eprintln!("  --tcp   Bind 0.0.0.0:5432 so TCP clients can connect");
    eprintln!("  --uds   Bind the default Unix socket (/tmp/.s.PGSQL.5432)");
    eprintln!("If no flag is provided, the Unix socket mode is used.");
}
