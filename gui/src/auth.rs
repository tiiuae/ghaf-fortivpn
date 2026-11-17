// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use cosmic::app::{Core, Settings};
use cosmic::iced::Size;
use cosmic::{Application, Element, executor, widget};
use std::process::{Child, Command};
use zbus::blocking::{Connection, Proxy};
use zeroize::Zeroizing;

pub type Prompt = (String, String, String, bool);

fn proxy(connection: &Connection) -> zbus::Result<Proxy<'_>> {
    Proxy::new(
        connection,
        super::BUS_NAME,
        super::OBJECT_PATH,
        super::INTERFACE_NAME,
    )
}

fn pending(id: &str) -> zbus::Result<Prompt> {
    let connection = Connection::system()?;
    proxy(&connection)?.call("PendingAuthentication", &(id,))
}

fn answer(id: &str, value: &str, cancel: bool) -> zbus::Result<()> {
    let connection = Connection::system()?;
    proxy(&connection)?.call("AnswerAuthentication", &(id, value, cancel))
}

pub fn agent() -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let mut active: Option<(String, Child)> = None;
    loop {
        if let Some((id, child)) = active.as_mut() {
            if child.try_wait()?.is_some() {
                let _ = answer(id, "", true);
                active = None;
            } else if pending(id).is_ok_and(|prompt| prompt.0.is_empty()) {
                let _ = child.kill();
                let _ = child.wait();
                active = None;
            }
        } else if let Ok(prompt) = pending("")
            && !prompt.0.is_empty()
        {
            let child = Command::new(&executable)
                .arg("--auth-prompt")
                .arg(&prompt.0)
                .spawn()?;
            active = Some((prompt.0, child));
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[derive(Clone, Debug)]
enum Message {
    Answer(String),
    Submit,
    Cancel,
    Finished(Result<(), String>),
}

struct AuthApp {
    core: Core,
    prompt: Prompt,
    answer: Zeroizing<String>,
    busy: bool,
    error: Option<String>,
}

impl Application for AuthApp {
    type Executor = executor::Default;
    type Flags = Prompt;
    type Message = Message;
    const APP_ID: &'static str = "org.ghaf.FortiVpn.Authentication";

    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, prompt: Prompt) -> (Self, cosmic::Task<cosmic::Action<Self::Message>>) {
        (
            Self {
                core,
                prompt,
                answer: Zeroizing::new(String::new()),
                busy: false,
                error: None,
            },
            cosmic::Task::none(),
        )
    }

    fn update(&mut self, message: Message) -> cosmic::Task<cosmic::Action<Message>> {
        match message {
            Message::Answer(value) => self.answer = Zeroizing::new(value),
            Message::Submit | Message::Cancel => {
                if self.busy {
                    return cosmic::Task::none();
                }
                self.busy = true;
                let cancel = matches!(message, Message::Cancel);
                let id = self.prompt.0.clone();
                let value = Zeroizing::new(std::mem::take(&mut *self.answer));
                return cosmic::Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            answer(&id, &value, cancel).map_err(|e| super::dbus_error(&e))
                        })
                        .await
                        .unwrap_or_else(|_| Err("VPN authentication stopped unexpectedly".into()))
                    },
                    |result| Message::Finished(result).into(),
                );
            }
            Message::Finished(Ok(())) => return cosmic::iced::exit(),
            Message::Finished(Err(error)) => {
                self.error = Some(error);
                self.busy = false;
            }
        }
        cosmic::Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let input = widget::text_input("Authentication response", self.answer.as_str())
            .on_input(Message::Answer)
            .on_submit(|_| Message::Submit);
        let input = if self.prompt.3 {
            input.password()
        } else {
            input
        };
        let mut column = widget::column([])
            .spacing(16)
            .padding(24)
            .push(widget::text::title3(&self.prompt.1))
            .push(widget::text(&self.prompt.2))
            .push(input);
        if let Some(error) = &self.error {
            column = column.push(widget::text(error));
        }
        column
            .push(
                widget::row([])
                    .spacing(12)
                    .push(widget::button::standard("Cancel").on_press(Message::Cancel))
                    .push(
                        widget::button::suggested("Continue")
                            .on_press_maybe((!self.busy).then_some(Message::Submit)),
                    ),
            )
            .into()
    }
}

pub fn prompt(id: &str) -> cosmic::iced::Result {
    let Ok(prompt) = pending(id) else {
        return Ok(());
    };
    if prompt.0.is_empty() {
        return Ok(());
    }
    cosmic::app::run::<AuthApp>(Settings::default().size(Size::new(480.0, 280.0)), prompt)
}
