//! The daemon under systemd (see `crate::platform`): nothing to hand the
//! process to, and SIGTERM is the stop.

use crate::paths::Instance;

/// `--service` is the Windows Service Control Manager's: systemd runs the
/// daemon itself.
pub fn run(_instance: &Instance, _tls: bool, _body: impl Fn() -> u32 + Send + Sync + 'static) -> i32 {
    eprintln!("error: `--service` is for Windows; under systemd, run the daemon itself");
    2
}

/// What stops the daemon: SIGTERM (systemd's stop) or Ctrl-C.
pub struct Shutdown {
    sigterm: tokio::signal::unix::Signal,
}

impl Shutdown {
    pub fn listen() -> std::io::Result<Self> {
        Ok(Self { sigterm: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())? })
    }

    pub async fn requested(&mut self) {
        tokio::select! { _ = self.sigterm.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
    }
}

/// Never: a process systemd stops gets SIGTERM, which keeps its default
/// effect wherever nothing listens for it ([`Shutdown`]).
pub async fn stop_requested() {
    std::future::pending::<()>().await;
}

/// After `leave`: nothing — the unit stays, and starts again only once the
/// node joins again.
#[allow(clippy::unnecessary_wraps)]
pub fn after_leave(_instance: &Instance) -> Result<(), String> {
    Ok(())
}
