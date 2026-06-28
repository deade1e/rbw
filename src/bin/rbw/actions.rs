use std::{io::Read as _, os::unix::ffi::OsStringExt as _};

use anyhow::Context as _;

pub fn register() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Register)
}

pub fn login() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Login)
}

pub fn unlock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Unlock)
}

pub fn unlocked() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::CheckLock,
            ))?;

            let res = sock.recv()?;
            match res {
                rbw::protocol::Response::Ack => Ok(()),
                rbw::protocol::Response::Error { error } => Err(anyhow::anyhow!("{error}")),
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) {
                anyhow::bail!("agent not running");
            }
            Err(e.into())
        }
    }
}

pub fn sync() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Sync)
}

pub fn lock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Lock)
}

pub fn quit() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let pidfile = rbw::dirs::pid_file()?;
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let Some(pid) = rustix::process::Pid::from_raw(pid.trim_end().parse()?) else {
                anyhow::bail!("failed to read pid from pidfile");
            };
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::Quit,
            ))?;
            wait_for_exit(pid);
            Ok(())
        }
        Err(e) => match e.kind() {
            // if the socket doesn't exist, or the socket exists but nothing
            // is listening on it, the agent must already be not running
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

pub fn get(find: rbw::protocol::FindArgs) -> anyhow::Result<rbw::protocol::Response> {
    complex_action(rbw::protocol::Action::Get(find))
}

pub fn search(term: String, folder: Option<String>) -> anyhow::Result<rbw::protocol::Response> {
    complex_action(rbw::protocol::Action::Search { term, folder })
}

pub fn code(find: rbw::protocol::FindArgs) -> anyhow::Result<rbw::protocol::Response> {
    complex_action(rbw::protocol::Action::Code(find))
}

pub fn add(
    name: String,
    username: Option<String>,
    uris: Vec<(String, Option<rbw::api::UriMatchType>)>,
    folder: Option<String>,
    password: Option<String>,
    notes: Option<String>,
) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Add(rbw::protocol::AddEntry {
        name,
        username,
        uris,
        folder,
        password,
        notes,
    }))
}

pub fn edit(
    find: rbw::protocol::FindArgs,
    password: Option<String>,
    notes: Option<String>,
) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Edit {
        find,
        password,
        notes,
    })
}

pub fn remove(find: rbw::protocol::FindArgs) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Remove(find))
}

pub fn history(find: rbw::protocol::FindArgs) -> anyhow::Result<rbw::protocol::Response> {
    complex_action(rbw::protocol::Action::History(find))
}

pub fn clipboard_store(text: &str) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ClipboardStore {
        text: text.to_string(),
    })
}

pub fn version() -> anyhow::Result<u32> {
    let res = complex_action(rbw::protocol::Action::Version)?;

    match res {
        rbw::protocol::Response::Version { version } => Ok(version),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to get version: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn complex_action(action: rbw::protocol::Action) -> anyhow::Result<rbw::protocol::Response> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request::new(get_environment(), action))?;
    sock.recv()
}

fn simple_action(action: rbw::protocol::Action) -> anyhow::Result<()> {
    let res = complex_action(action)?;

    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error } => Err(anyhow::anyhow!("{error}")),
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn connect() -> anyhow::Result<crate::sock::Sock> {
    crate::sock::Sock::connect().with_context(|| {
        let log = rbw::dirs::agent_stderr_file();
        format!(
            "failed to connect to rbw-agent \
            (this often means that the agent failed to start; \
            check {} for agent logs)",
            log.map_or("<Data directory unavailable>".to_string(), |p| p
                .display()
                .to_string())
        )
    })
}

fn wait_for_exit(pid: rustix::process::Pid) {
    loop {
        if rustix::process::test_kill_process(pid).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn get_environment() -> rbw::protocol::Environment {
    let tty = std::env::var_os("RBW_TTY").or_else(|| {
        rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .map(|p| std::ffi::OsString::from_vec(p.as_bytes().to_vec()))
    });

    let env_vars = std::env::vars_os()
        .filter(|(var_name, _)| (*rbw::protocol::ENVIRONMENT_VARIABLES_OS).contains(var_name))
        .collect();
    rbw::protocol::Environment::new(tty, env_vars)
}
