// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{MAX_PASSWORD_SIZE, ProfileError, ProfileResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, oneshot, watch};
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: usize = 65536;
pub const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(100);

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub gateway: String,
    pub username: String,
    pub password: String,
    pub fingerprint: String,
    pub certificate: String,
    pub key: String,
    pub ca: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "event")]
enum Event {
    Prompt {
        label: String,
        secret: bool,
    },
    Complete {
        secrets: HashMap<String, String>,
        password: Option<String>,
    },
}

pub type Prompt = (String, String, String, bool);

struct Pending {
    prompt: Prompt,
    answer: oneshot::Sender<Option<Zeroizing<String>>>,
}

#[derive(Default)]
pub struct Authentication {
    pending: Mutex<HashMap<String, Pending>>,
    active: Mutex<HashMap<String, watch::Sender<bool>>>,
}

impl Authentication {
    pub async fn prompt(&self, id: &str) -> Prompt {
        let pending = self.pending.lock().await;
        let prompt = if id.is_empty() {
            pending.values().next()
        } else {
            pending.get(id)
        };
        prompt.map(|p| p.prompt.clone()).unwrap_or_default()
    }

    pub async fn answer(&self, id: &str, answer: String, cancel: bool) -> ProfileResult<()> {
        let answer = Zeroizing::new(answer);
        if answer.len() > MAX_PASSWORD_SIZE || answer.contains('\0') {
            return Err(ProfileError("The authentication response is invalid"));
        }
        let pending = self
            .pending
            .lock()
            .await
            .remove(id)
            .ok_or(ProfileError("The authentication request has expired"))?;
        let _ = pending.answer.send((!cancel).then_some(answer));
        Ok(())
    }

    pub async fn cancel(&self, path: &str) {
        if let Some(cancel) = self.active.lock().await.get(path) {
            let _ = cancel.send(true);
        }
    }

    pub async fn run(
        &self,
        path: &str,
        state_root: &Path,
        settings: &crate::Settings,
        connection: &zbus::Connection,
        sender: &str,
    ) -> ProfileResult<HashMap<String, String>> {
        let (cancel, mut cancelled) = watch::channel(false);
        {
            let mut active = self.active.lock().await;
            if active.contains_key(path) || active.len() >= 4 {
                return Err(ProfileError("VPN authentication is already in progress"));
            }
            active.insert(path.to_owned(), cancel);
        }
        let request = uuid::Uuid::new_v4().to_string();
        let authentication = async {
            let (name, credentials, credentials_path) =
                crate::profiles::credentials(state_root, settings)?;
            self.worker(&request, &name, credentials, connection, &credentials_path)
                .await
        };
        let plugin_gone = async {
            let Ok(bus) = zbus::fdo::DBusProxy::new(connection).await else {
                return;
            };
            let Ok(name) = zbus::names::BusName::try_from(sender) else {
                return;
            };
            loop {
                if !bus.name_has_owner(name.clone()).await.unwrap_or(false) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        };
        let result = tokio::select! {
            result = tokio::time::timeout(AUTH_TIMEOUT, authentication) =>
                result.unwrap_or(Err(ProfileError("VPN authentication timed out"))),
            _ = plugin_gone => Err(ProfileError("VPN plugin disconnected")),
            _ = cancelled.changed() => Err(ProfileError("VPN authentication was cancelled")),
        };
        self.pending
            .lock()
            .await
            .retain(|id, _| !id.starts_with(&format!("{request}:")));
        self.active.lock().await.remove(path);
        result
    }

    async fn worker(
        &self,
        id: &str,
        name: &str,
        mut credentials: Credentials,
        connection: &zbus::Connection,
        credentials_path: &Path,
    ) -> ProfileResult<HashMap<String, String>> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--authenticate-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| ProfileError("VPN authentication could not start"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or(ProfileError("VPN authentication could not start"))?;
        let mut stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or(ProfileError("VPN authentication could not start"))?,
        );
        let mut config = Zeroizing::new(
            serde_json::to_vec(&credentials)
                .map_err(|_| ProfileError("Invalid authentication configuration"))?,
        );
        config.push(b'\n');
        stdin.write_all(&config).await?;
        drop(config);
        let mut prompts = 0;
        loop {
            let frame = read_frame(&mut stdout).await?;
            let event: Event = serde_json::from_slice(&frame)
                .map_err(|_| ProfileError("VPN authentication failed"))?;
            match event {
                Event::Prompt { label, secret } => {
                    prompts += 1;
                    if prompts > 16 {
                        return Err(ProfileError("VPN authentication requires user interaction"));
                    }
                    let prompt_id = format!("{id}:{prompts}");
                    let (send, receive) = oneshot::channel();
                    self.pending.lock().await.insert(
                        prompt_id.clone(),
                        Pending {
                            prompt: (prompt_id, name.into(), label, secret),
                            answer: send,
                        },
                    );
                    connection
                        .emit_signal(
                            None::<&str>,
                            crate::OBJECT_PATH,
                            "org.ghaf.FortiVpn1",
                            "AuthenticationPending",
                            &(),
                        )
                        .await
                        .map_err(|_| ProfileError("Could not notify the desktop"))?;
                    let answer = receive
                        .await
                        .ok()
                        .flatten()
                        .ok_or(ProfileError("VPN authentication was cancelled"))?;
                    let mut frame = Zeroizing::new(
                        serde_json::to_vec(answer.as_str())
                            .map_err(|_| ProfileError("Invalid authentication response"))?,
                    );
                    frame.push(b'\n');
                    stdin.write_all(&frame).await?;
                }
                Event::Complete { secrets, password } => {
                    if !child.wait().await?.success() {
                        return Err(ProfileError("VPN authentication failed"));
                    }
                    validate_result(&secrets)?;
                    if let Some(password) = password {
                        credentials.password.zeroize();
                        credentials.password = password;
                        let contents =
                            Zeroizing::new(serde_json::to_vec(&credentials).map_err(|_| {
                                ProfileError("VPN credentials could not be updated")
                            })?);
                        write_private_inner(credentials_path, &contents, true)?;
                    }
                    return Ok(secrets);
                }
            }
        }
    }
}

async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> ProfileResult<Zeroizing<Vec<u8>>> {
    let mut frame = Zeroizing::new(Vec::new());
    for _ in 0..MAX_FRAME {
        let byte = reader
            .read_u8()
            .await
            .map_err(|_| ProfileError("VPN authentication failed"))?;
        if byte == b'\n' {
            return Ok(frame);
        }
        frame.push(byte);
    }
    Err(ProfileError("The authentication response is too large"))
}

fn validate_result(secrets: &HashMap<String, String>) -> ProfileResult<()> {
    for key in ["cookie", "gateway", "gwcert"] {
        if secrets
            .get(key)
            .is_none_or(|s| s.is_empty() || s.contains(['\n', '\r', '\0']))
        {
            return Err(ProfileError(
                "VPN authentication returned an invalid session",
            ));
        }
    }
    if secrets
        .keys()
        .any(|k| !["cookie", "gateway", "gwcert", "resolve"].contains(&k.as_str()))
    {
        return Err(ProfileError(
            "VPN authentication returned an invalid session",
        ));
    }
    Ok(())
}

pub fn load(path: &Path) -> ProfileResult<Credentials> {
    let metadata = std::fs::symlink_metadata(path)?;
    use std::os::unix::fs::PermissionsExt;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_FRAME as u64
    {
        return Err(ProfileError("VPN credentials are not safely stored"));
    }
    let contents = Zeroizing::new(std::fs::read(path)?);
    serde_json::from_slice(&contents).map_err(|_| ProfileError("VPN credentials are invalid"))
}

pub fn save(path: &Path, credentials: &Credentials) -> ProfileResult<()> {
    let contents = Zeroizing::new(
        serde_json::to_vec(credentials)
            .map_err(|_| ProfileError("VPN credentials could not be stored"))?,
    );
    write_private(path, &contents)
}

fn write_private(path: &Path, contents: &[u8]) -> ProfileResult<()> {
    write_private_inner(path, contents, false)
}

fn write_private_inner(path: &Path, contents: &[u8], replace: bool) -> ProfileResult<()> {
    let parent = path
        .parent()
        .ok_or(ProfileError("Invalid credential storage path"))?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(contents)?;
    file.as_file().sync_all()?;
    let result = if replace {
        file.persist(path)
    } else {
        file.persist_noclobber(path)
    };
    result.map_err(|_| ProfileError("Private VPN storage failed"))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn input() -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut bytes = Zeroizing::new(Vec::new());
    let stdin = std::io::stdin();
    let mut reader = stdin.lock().take(MAX_FRAME as u64);
    use std::io::Read;
    reader.read_until(b'\n', &mut bytes).map_err(|_| ())?;
    if bytes.last() != Some(&b'\n') {
        return Err(());
    }
    Ok(bytes)
}

fn output(event: &Event) -> Result<(), ()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(event).map_err(|_| ())?);
    if bytes.len() >= MAX_FRAME - 1 {
        return Err(());
    }
    bytes.push(b'\n');
    std::io::stdout().lock().write_all(&bytes).map_err(|_| ())
}

struct Worker {
    credentials: Credentials,
    password_used: bool,
    password_changed: bool,
}

unsafe extern "C" {
    fn ghaf_openconnect(
        context: *mut c_void,
        gateway: *const c_char,
        certificate: *const c_char,
        key: *const c_char,
        ca: *const c_char,
    ) -> c_int;
}

fn cstring(value: &str) -> Result<CString, ()> {
    CString::new(value).map_err(|_| ())
}

unsafe fn text<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ghaf_check_certificate(
    context: *mut c_void,
    der: *const u8,
    length: c_int,
) -> c_int {
    let worker = unsafe { &*(context as *const Worker) };
    let digest = openssl::sha::sha256(unsafe { std::slice::from_raw_parts(der, length as usize) });
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if hex == worker.credentials.fingerprint {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ghaf_answer(
    context: *mut c_void,
    login: c_int,
    name: *const c_char,
    label: *const c_char,
    message: *const c_char,
    secret: c_int,
    buffer: *mut c_char,
    length: u32,
) -> c_int {
    let worker = unsafe { &mut *(context as *mut Worker) };
    let name = unsafe { text(name) };
    let answer = if login != 0 && name == "username" {
        Zeroizing::new(worker.credentials.username.clone())
    } else if login != 0 && name == "credential" && !worker.password_used {
        worker.password_used = true;
        Zeroizing::new(worker.credentials.password.clone())
    } else {
        let message: String = unsafe { text(message) }.chars().take(200).collect();
        let label: String = unsafe { text(label) }.chars().take(56).collect();
        let description = format!("{message} {label}");
        let label: String = description
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(256)
            .collect();
        if output(&Event::Prompt {
            label,
            secret: secret != 0,
        })
        .is_err()
        {
            return -1;
        }
        let Ok(bytes) = input() else {
            return -1;
        };
        let Ok(answer) = serde_json::from_slice::<String>(&bytes) else {
            return -1;
        };
        Zeroizing::new(answer)
    };
    if login != 0 && name == "credential" && *answer != worker.credentials.password {
        worker.credentials.password.zeroize();
        worker.credentials.password = answer.to_string();
        worker.password_changed = true;
    }
    if answer.len() >= length as usize || answer.contains('\0') {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(answer.as_ptr(), buffer.cast::<u8>(), answer.len());
        *buffer.add(answer.len()) = 0;
    }
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ghaf_result(
    context: *mut c_void,
    cookie: *const c_char,
    gateway: *const c_char,
    certificate: *const c_char,
    dnsname: *const c_char,
    address: *const c_char,
) -> c_int {
    let mut secrets = HashMap::from([
        ("cookie".into(), unsafe { text(cookie) }.to_owned()),
        ("gateway".into(), unsafe { text(gateway) }.to_owned()),
        ("gwcert".into(), unsafe { text(certificate) }.to_owned()),
    ]);
    let dnsname = unsafe { text(dnsname) };
    let address = unsafe { text(address) }.trim_matches(['[', ']']);
    if !dnsname.is_empty() && dnsname != address && address.parse::<std::net::IpAddr>().is_ok() {
        secrets.insert("resolve".into(), format!("{dnsname}:{address}"));
    }
    let worker = unsafe { &*(context as *const Worker) };
    let event = Event::Complete {
        secrets,
        password: worker
            .password_changed
            .then(|| worker.credentials.password.clone()),
    };
    let result = output(&event).map_or(-1, |()| 0);
    if let Event::Complete {
        mut secrets,
        mut password,
    } = event
    {
        if let Some(password) = password.as_mut() {
            password.zeroize();
        }
        for secret in secrets.values_mut() {
            secret.zeroize();
        }
    }
    result
}

pub fn worker() -> Result<(), ()> {
    let bytes = input()?;
    let credentials: Credentials = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let gateway = cstring(&credentials.gateway)?;
    let certificate = cstring(&credentials.certificate)?;
    let key = cstring(&credentials.key)?;
    let ca = cstring(&credentials.ca)?;
    let mut worker = Worker {
        credentials,
        password_used: false,
        password_changed: false,
    };
    // The C adapter borrows this context and all strings only for this synchronous call.
    let result = unsafe {
        ghaf_openconnect(
            (&mut worker as *mut Worker).cast(),
            gateway.as_ptr(),
            certificate.as_ptr(),
            key.as_ptr(),
            ca.as_ptr(),
        )
    };
    if result == 0 { Ok(()) } else { Err(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn answers_are_private_to_a_prompt_and_cannot_be_replayed() {
        let auth = Authentication::default();
        let (send, receive) = oneshot::channel();
        auth.pending.lock().await.insert(
            "request-a:1".into(),
            Pending {
                prompt: ("request-a:1".into(), "VPN A".into(), "Code".into(), true),
                answer: send,
            },
        );
        assert!(
            auth.answer("request-b:1", "wrong".into(), false)
                .await
                .is_err()
        );
        assert_eq!(auth.prompt("request-b:1").await.0, "");
        auth.answer("request-a:1", "123456".into(), false)
            .await
            .unwrap();
        assert_eq!(receive.await.unwrap().unwrap().as_str(), "123456");
        assert!(
            auth.answer("request-a:1", "replay".into(), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cancellation_is_scoped_to_the_requested_connection() {
        let auth = Authentication::default();
        let (cancel_a, mut a) = watch::channel(false);
        let (cancel_b, b) = watch::channel(false);
        auth.active
            .lock()
            .await
            .extend([("a".into(), cancel_a), ("b".into(), cancel_b)]);
        auth.cancel("a").await;
        a.changed().await.unwrap();
        assert!(*a.borrow());
        assert!(!*b.borrow());
    }

    #[tokio::test]
    async fn rejects_oversized_and_incomplete_worker_responses() {
        assert!(read_frame(&mut &b"incomplete"[..]).await.is_err());
        let oversized = vec![b'x'; MAX_FRAME];
        assert!(read_frame(&mut oversized.as_slice()).await.is_err());
        assert_eq!(
            read_frame(&mut &b"valid\n"[..]).await.unwrap().as_slice(),
            b"valid"
        );
    }

    #[test]
    fn credentials_reject_public_files_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("auth.json");
        let credentials = Credentials {
            gateway: "https://vpn.example.com:443/".into(),
            username: "user".into(),
            password: "test-password".into(),
            fingerprint: String::new(),
            certificate: String::new(),
            key: String::new(),
            ca: String::new(),
        };
        save(&path, &credentials).unwrap();
        assert_eq!(load(&path).unwrap().password, "test-password");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&path).is_ok());
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(load(&link).is_err());
        assert!(write_private(&path, b"replacement").is_err());
        assert_eq!(load(&path).unwrap().password, "test-password");
    }
}
