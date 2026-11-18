// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

const PATH: &str = "/org/freedesktop/NetworkManager/Settings/1";

struct Bus {
    daemon: Child,
    address: String,
}
impl Bus {
    fn new() -> Self {
        let mut daemon = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon is required for integration tests");
        let mut address = String::new();
        BufReader::new(daemon.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            daemon,
            address: address.trim().into(),
        }
    }
    async fn connection(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .build()
            .await
            .unwrap()
    }
}
impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn copy(settings: &Settings) -> Settings {
    settings
        .iter()
        .map(|(section, values)| {
            (
                section.clone(),
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), value.try_clone().unwrap()))
                    .collect(),
            )
        })
        .collect()
}

struct NmProfile {
    settings: Arc<Mutex<Settings>>,
}
#[interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl NmProfile {
    async fn get_settings(&self) -> Settings {
        let mut settings = copy(&*self.settings.lock().await);
        settings.get_mut("vpn").unwrap().remove("secrets");
        settings
    }
}

#[tokio::test]
async fn credentials_are_bound_to_the_managed_gateway() {
    let bus = Bus::new();
    let root = tempfile::tempdir().unwrap();
    let uuid = Uuid::new_v4().to_string();
    let stored = store_materials(
        root.path(),
        &uuid,
        &Materials {
            certificate: None,
            private_key: None,
            ca_certificate: None,
        },
        MAX_PROFILE_COUNT,
    )
    .unwrap();
    let parameters = ProfileParameters {
        name: "Test VPN",
        gateway: "vpn.example.com",
        port: 10443,
        realm: "Staff & VPN",
        username: "user",
        password: "saved-password",
        trusted_certificate: "",
    };
    let auth_path = root.path().join(&uuid).join("auth.json");
    auth::save(&auth_path, &profiles::config(&parameters, &stored).unwrap()).unwrap();
    let settings = Arc::new(Mutex::new(
        build_settings(&parameters, &uuid, &stored).unwrap(),
    ));
    let _nm = zbus::connection::Builder::address(bus.address.as_str())
        .name(NM_BUS_NAME)
        .serve_at(
            PATH,
            NmProfile {
                settings: settings.clone(),
            },
        )
        .build()
        .await
        .unwrap();
    let client = bus.connection().await;
    let path = PATH.try_into().unwrap();
    let (name, credentials, stored_path) = profiles::credentials(&client, root.path(), &path)
        .await
        .unwrap();
    assert_eq!(name, "Test VPN");
    assert_eq!(credentials.password, "saved-password");
    assert_eq!(
        credentials.gateway,
        "https://vpn.example.com:10443/remote/login?realm=Staff%20%26%20VPN"
    );
    assert_eq!(stored_path, auth_path);

    {
        let mut settings = settings.lock().await;
        let mut data = profiles::dictionary(&settings, "data").unwrap();
        data.insert("gateway".into(), "https://attacker.invalid".into());
        settings
            .get_mut("vpn")
            .unwrap()
            .insert("data".into(), OwnedVariant::from(data));
    }
    assert_eq!(
        profiles::credentials(&client, root.path(), &path)
            .await
            .err()
            .unwrap()
            .0,
        "The managed VPN authentication settings were changed"
    );
}

#[tokio::test]
async fn authentication_backend_rejects_callers_without_the_local_agent_identity() {
    let bus = Bus::new();
    let root = tempfile::tempdir().unwrap();
    let _server = zbus::connection::Builder::address(bus.address.as_str())
        .name(agent::BACKEND_NAME)
        .serve_at(
            agent::BACKEND_PATH,
            agent::Backend {
                state_root: root.path().into(),
                authentication: Arc::default(),
            },
        )
        .build()
        .await
        .unwrap();
    let client = bus.connection().await;
    let proxy = zbus::Proxy::new(
        &client,
        agent::BACKEND_NAME,
        agent::BACKEND_PATH,
        "org.ghaf.FortiVpn.Authentication1",
    )
    .await
    .unwrap();
    let response: zbus::Result<HashMap<String, String>> = proxy
        .call(
            "Authenticate",
            &(OwnedObjectPath::try_from(PATH).unwrap(), 1u32),
        )
        .await;
    assert!(
        matches!(response, Err(zbus::Error::FDO(error)) if matches!(*error, fdo::Error::AccessDenied(_)))
    );
}

#[tokio::test]
async fn secret_agent_rejects_other_callers_and_leaves_unrelated_connections_alone() {
    let bus = Bus::new();
    let agent = zbus::connection::Builder::address(bus.address.as_str())
        .name(agent::AGENT_NAME)
        .serve_at("/org/freedesktop/NetworkManager/SecretAgent", agent::Agent)
        .build()
        .await
        .unwrap();
    let manager = zbus::connection::Builder::address(bus.address.as_str())
        .name(NM_BUS_NAME)
        .build()
        .await
        .unwrap();
    let unrelated = bus.connection().await;
    for (caller, expected) in [(&unrelated, "PermissionDenied"), (&manager, "NoSecrets")] {
        let proxy = zbus::Proxy::new(
            caller,
            agent.unique_name().unwrap(),
            "/org/freedesktop/NetworkManager/SecretAgent",
            "org.freedesktop.NetworkManager.SecretAgent",
        )
        .await
        .unwrap();
        let response: zbus::Result<Settings> = proxy
            .call(
                "GetSecrets",
                &(
                    Settings::new(),
                    OwnedObjectPath::try_from(PATH).unwrap(),
                    "802-11-wireless-security",
                    Vec::<String>::new(),
                    1u32,
                ),
            )
            .await;
        assert!(
            matches!(response, Err(zbus::Error::MethodError(name, _, _)) if name.as_str().ends_with(expected))
        );
    }
}
