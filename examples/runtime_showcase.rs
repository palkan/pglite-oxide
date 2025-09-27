use anyhow::Result;

use pglite_oxide::interactive::{self, exec_interactive, PokeInput};
use pglite_oxide::prepare_default_mount;

fn main() -> Result<()> {
    let mount = prepare_default_mount()?;

    println!("pglite mount root: {}", mount.mount().display());
    println!("pglite socket path: {}", mount.io_socket().display());
    println!("reused existing install: {}", mount.reused_existing());

    let module_path = interactive::wasm_import("postgres", None)?;
    println!("postgres module located at: {}", module_path.display());

    match exec_interactive(PokeInput::Str("select 1;")) {
        Ok(response) => println!(
            "interactive response ({} bytes):\n{}",
            response.len(),
            interactive::hexc(&response, "<-", Some(4))
        ),
        Err(err) => println!("interactive exec failed: {err:#}"),
    }

    match interactive::run_pg_dump(&["pg_dump", "--version"], &[]) {
        Ok(Some(code)) => println!("pg_dump --version exited with status {code}"),
        Ok(None) => println!("pg_dump shim not included in this runtime"),
        Err(err) => println!("pg_dump failed: {err:#}"),
    }

    Ok(())
}
