// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use futures_util::StreamExt;
use zbus::{Connection, Proxy};

const PROGRAM: &str = "/run/current-system/sw/bin/ghaf-fortivpn";

pub async fn watch() {
    if !std::path::Path::new(PROGRAM).is_file() {
        return;
    }
    loop {
        if let Err(error) = listen().await {
            log::warn!("FortiVPN prompt subscription: {error}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn listen() -> zbus::Result<()> {
    let bus = Connection::system().await?;
    let proxy = Proxy::new(
        &bus,
        "org.ghaf.FortiVpn",
        "/org/ghaf/FortiVpn",
        "org.ghaf.FortiVpn1",
    )
    .await?;
    let mut pending = proxy.receive_signal("AuthenticationPending").await?;
    let mut owner = proxy.receive_owner_changed().await?;
    loop {
        // Check after subscribing as a prompt can predate login or proxy recovery.
        let prompt: zbus::Result<(String, String, String, bool)> =
            proxy.call("PendingAuthentication", &("",)).await;
        if prompt.is_ok_and(|p| !p.0.is_empty()) {
            let mut child = tokio::process::Command::new(PROGRAM);
            child.arg("--present-pending").kill_on_drop(true);
            if let Err(error) = child.status().await {
                log::warn!("Could not open FortiVPN prompt: {error}");
            }
        }
        tokio::select! {
            message = pending.next() => if message.is_none() { return Ok(()) },
            change = owner.next() => if change.is_none() { return Ok(()) },
        }
    }
}
