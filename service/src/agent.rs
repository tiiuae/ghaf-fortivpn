// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{NM_BUS_NAME, Setting, Settings, auth, profiles};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use zbus::{OwnedObjectPath, OwnedVariant, fdo, interface, message::Header};

pub const AGENT_NAME: &str = "org.ghaf.FortiVpn.Agent";
pub const BACKEND_NAME: &str = "org.ghaf.FortiVpn.Authentication";
pub const BACKEND_PATH: &str = "/org/ghaf/FortiVpnAuthentication";
const BACKEND_INTERFACE: &str = "org.ghaf.FortiVpn.Authentication1";
const AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";

pub async fn owner(connection: &zbus::Connection, name: &str) -> zbus::Result<String> {
    Ok(fdo::DBusProxy::new(connection)
        .await?
        .get_name_owner(name.try_into()?)
        .await?
        .to_string())
}

async fn authorize(
    connection: &zbus::Connection,
    header: &Header<'_>,
    name: &str,
) -> fdo::Result<()> {
    let expected = owner(connection, name)
        .await
        .map_err(|_| fdo::Error::AccessDenied("The caller is not authorized".into()))?;
    if header.sender().map(|s| s.as_str()) != Some(expected.as_str()) {
        return Err(fdo::Error::AccessDenied(
            "The caller is not authorized".into(),
        ));
    }
    Ok(())
}

pub struct Backend {
    pub state_root: PathBuf,
    pub authentication: Arc<auth::Authentication>,
}

#[interface(name = "org.ghaf.FortiVpn.Authentication1")]
impl Backend {
    async fn authenticate(
        &self,
        path: OwnedObjectPath,
        flags: u32,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<HashMap<String, String>> {
        authorize(connection, &header, AGENT_NAME).await?;
        self.authentication
            .run(
                path.as_str(),
                profiles::credentials(connection, &self.state_root, &path),
                flags & 1 != 0,
            )
            .await
            .map_err(|e| fdo::Error::Failed(e.0.into()))
    }

    async fn cancel(
        &self,
        path: OwnedObjectPath,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        authorize(connection, &header, AGENT_NAME).await?;
        self.authentication.cancel(path.as_str()).await;
        Ok(())
    }
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.SecretAgent")]
enum AgentError {
    NoSecrets(String),
    UserCanceled(String),
    PermissionDenied(String),
    Failed(String),
}

pub(crate) struct Agent;

async fn backend(connection: &zbus::Connection) -> zbus::Result<zbus::Proxy<'_>> {
    zbus::Proxy::new(connection, BACKEND_NAME, BACKEND_PATH, BACKEND_INTERFACE).await
}

async fn nm_caller(connection: &zbus::Connection, header: &Header<'_>) -> Result<(), AgentError> {
    authorize(connection, header, NM_BUS_NAME)
        .await
        .map_err(|_| AgentError::PermissionDenied("Only NetworkManager may request secrets".into()))
}

#[interface(name = "org.freedesktop.NetworkManager.SecretAgent")]
impl Agent {
    #[allow(clippy::too_many_arguments)]
    async fn get_secrets(
        &self,
        settings: Settings,
        path: OwnedObjectPath,
        setting_name: String,
        _hints: Vec<String>,
        flags: u32,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Settings, AgentError> {
        nm_caller(connection, &header).await?;
        if setting_name != "vpn" || !profiles::is_openconnect_fortinet(&settings) {
            return Err(AgentError::NoSecrets(
                "This agent handles only Ghaf Fortinet profiles".into(),
            ));
        }
        if flags & 1 == 0 {
            return Err(AgentError::NoSecrets(
                "A fresh VPN authentication is required".into(),
            ));
        }
        let proxy = backend(connection)
            .await
            .map_err(|_| AgentError::Failed("The Fortinet service is unavailable".into()))?;
        let secrets: HashMap<String, String> = proxy
            .call("Authenticate", &(path, flags))
            .await
            .map_err(|error| match error {
                zbus::Error::FDO(error) => match *error {
                    fdo::Error::Failed(message)
                        if message == "VPN authentication was cancelled" =>
                    {
                        AgentError::UserCanceled(message)
                    }
                    fdo::Error::Failed(message) => AgentError::NoSecrets(message),
                    _ => AgentError::Failed("VPN authentication failed".into()),
                },
                _ => AgentError::Failed("VPN authentication failed".into()),
            })?;
        Ok(HashMap::from([(
            "vpn".into(),
            Setting::from([("secrets".into(), OwnedVariant::from(secrets))]),
        )]))
    }

    async fn cancel_get_secrets(
        &self,
        path: OwnedObjectPath,
        setting_name: String,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), AgentError> {
        nm_caller(connection, &header).await?;
        if setting_name == "vpn"
            && let Ok(proxy) = backend(connection).await
        {
            let _: zbus::Result<()> = proxy.call("Cancel", &(path,)).await;
        }
        Ok(())
    }

    async fn save_secrets(
        &self,
        _settings: Settings,
        _path: OwnedObjectPath,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), AgentError> {
        nm_caller(connection, &header).await
    }

    async fn delete_secrets(
        &self,
        _settings: Settings,
        path: OwnedObjectPath,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), AgentError> {
        self.cancel_get_secrets(path, "vpn".into(), connection, header)
            .await
    }
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let connection = zbus::connection::Builder::system()
        .method_timeout(auth::AUTH_TIMEOUT + std::time::Duration::from_secs(10))
        .name(AGENT_NAME)
        .serve_at(AGENT_PATH, Agent)
        .build()
        .await?;
    let mut registered_owner = String::new();
    loop {
        if let Ok(current) = owner(&connection, NM_BUS_NAME).await {
            if current != registered_owner {
                let proxy = zbus::Proxy::new(
                    &connection,
                    NM_BUS_NAME,
                    "/org/freedesktop/NetworkManager/AgentManager",
                    "org.freedesktop.NetworkManager.AgentManager",
                )
                .await?;
                let registration: zbus::Result<()> = proxy
                    .call("RegisterWithCapabilities", &(AGENT_NAME, 1u32))
                    .await;
                if registration.is_ok() {
                    registered_owner = current;
                }
            }
        } else {
            registered_owner.clear();
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
