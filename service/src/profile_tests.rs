// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
#[test]
fn credentials_are_bound_to_the_managed_gateway() {
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
    let mut settings = build_settings(&parameters, &uuid, &stored).unwrap();
    let (name, credentials, stored_path) = profiles::credentials(root.path(), &settings).unwrap();
    assert_eq!(name, "Test VPN");
    assert_eq!(credentials.password, "saved-password");
    assert_eq!(
        credentials.gateway,
        "https://vpn.example.com:10443/remote/login?realm=Staff%20%26%20VPN"
    );
    assert_eq!(stored_path, auth_path);

    {
        let mut data = profiles::dictionary(&settings, "data").unwrap();
        data.insert("gateway".into(), "https://attacker.invalid".into());
        settings
            .get_mut("vpn")
            .unwrap()
            .insert("data".into(), OwnedVariant::from(data));
    }
    assert_eq!(
        profiles::credentials(root.path(), &settings)
            .err()
            .unwrap()
            .0,
        "The managed VPN authentication settings were changed"
    );
}
