// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use crate::*;

pub const SERVICE_TYPE: &str = "org.freedesktop.NetworkManager.openconnect";

pub fn value<'a>(settings: &'a Settings, section: &str, key: &str) -> Option<&'a str> {
    settings
        .get(section)?
        .get(key)
        .and_then(|value| <&str>::try_from(value).ok())
}

pub fn dictionary(settings: &Settings, key: &str) -> ProfileResult<HashMap<String, String>> {
    settings
        .get("vpn")
        .and_then(|vpn| vpn.get(key))
        .ok_or(ProfileError("The VPN settings are incomplete"))?
        .try_clone()
        .ok()
        .and_then(|v| HashMap::try_from(v).ok())
        .ok_or(ProfileError("The VPN settings are invalid"))
}

pub fn is_openconnect_fortinet(settings: &Settings) -> bool {
    value(settings, "vpn", "service-type") == Some(SERVICE_TYPE)
        && dictionary(settings, "data")
            .is_ok_and(|data| data.get("protocol").map(String::as_str) == Some("fortinet"))
}

pub fn gateway(host: &str, port: u16, realm: &str) -> String {
    let host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.into()
    };
    let mut gateway = format!("https://{host}:{port}/");
    if !realm.is_empty() {
        gateway.push_str("remote/login?realm=");
        for byte in realm.bytes() {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                gateway.push(byte as char);
            } else {
                gateway.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    gateway
}

pub fn config(
    parameters: &ProfileParameters<'_>,
    stored: &StoredMaterials,
) -> ProfileResult<auth::Credentials> {
    Ok(auth::Credentials {
        gateway: gateway(
            parameters.gateway.trim(),
            parameters.port,
            parameters.realm.trim(),
        ),
        username: parameters.username.trim().into(),
        password: parameters.password.into(),
        fingerprint: normalize_fingerprint(parameters.trusted_certificate.trim())?
            .unwrap_or_default(),
        certificate: stored.certificate.clone().unwrap_or_default(),
        key: stored.private_key.clone().unwrap_or_default(),
        ca: stored.ca_certificate.clone().unwrap_or_default(),
    })
}

pub fn data(credentials: &auth::Credentials) -> HashMap<String, String> {
    let mut data = HashMap::from([
        ("gateway".into(), credentials.gateway.clone()),
        ("protocol".into(), "fortinet".into()),
    ]);
    for key in ["cookie", "gateway", "gwcert", "resolve"] {
        data.insert(format!("{key}-flags"), "2".into());
    }
    for (key, value) in [
        ("usercert", &credentials.certificate),
        ("userkey", &credentials.key),
        ("cacert", &credentials.ca),
    ] {
        if !value.is_empty() {
            data.insert(key.into(), value.clone());
        }
    }
    data
}

fn directory(state_root: &Path, settings: &Settings) -> ProfileResult<PathBuf> {
    let uuid =
        value(settings, "connection", "uuid").ok_or(ProfileError("The VPN profile has no UUID"))?;
    if Uuid::parse_str(uuid).is_err() {
        return Err(ProfileError("The VPN profile UUID is invalid"));
    }
    let directory = state_root.join(uuid);
    ensure_private_directory(state_root)?;
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() {
        return Err(ProfileError(
            "The VPN profile is not managed by Ghaf FortiVPN",
        ));
    }
    ensure_private_directory(&directory)?;
    Ok(directory)
}

async fn proxy<'a>(
    connection: &'a zbus::Connection,
    path: &'a OwnedObjectPath,
) -> ProfileResult<zbus::Proxy<'a>> {
    if !path
        .as_str()
        .starts_with("/org/freedesktop/NetworkManager/Settings/")
    {
        return Err(ProfileError("The VPN profile path is invalid"));
    }
    zbus::Proxy::new(connection, NM_BUS_NAME, path, NM_CONNECTION_INTERFACE)
        .await
        .map_err(|_| ProfileError("NetworkManager is unavailable"))
}

pub async fn credentials(
    connection: &zbus::Connection,
    state_root: &Path,
    path: &OwnedObjectPath,
) -> ProfileResult<(String, auth::Credentials, PathBuf)> {
    let proxy = proxy(connection, path).await?;
    let settings: Settings = proxy
        .call("GetSettings", &())
        .await
        .map_err(|_| ProfileError("The VPN profile is unavailable"))?;
    if !is_openconnect_fortinet(&settings) {
        return Err(ProfileError("This VPN profile is not a Fortinet profile"));
    }
    let directory = directory(state_root, &settings)?;
    let credentials = auth::load(&directory.join("auth.json"))?;
    let current = dictionary(&settings, "data")?;
    for (key, expected) in data(&credentials) {
        if current.get(&key) != Some(&expected) {
            return Err(ProfileError(
                "The managed VPN authentication settings were changed",
            ));
        }
    }
    for (path, name) in [
        (&credentials.certificate, "client-cert.pem"),
        (&credentials.key, "client-key.pem"),
        (&credentials.ca, "gateway-ca.pem"),
    ] {
        if !path.is_empty()
            && (Path::new(path) != directory.join(name) || !fs::symlink_metadata(path)?.is_file())
        {
            return Err(ProfileError("The VPN certificate path is invalid"));
        }
    }
    Ok((
        value(&settings, "connection", "id")
            .unwrap_or("Fortinet VPN")
            .into(),
        credentials,
        directory.join("auth.json"),
    ))
}
