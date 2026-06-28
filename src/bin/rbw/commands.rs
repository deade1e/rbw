use std::{io::Write as _, os::unix::ffi::OsStrExt as _, path::PathBuf};

use anyhow::Context as _;
use rbw::db::EntryData;

use crate::FindArgs;

// TODO: This could be a dup of FieldType?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListField {
    Id,
    Name,
    User,
    Folder,
    Uri,
    EntryType,
}

impl ListField {
    fn all() -> &'static [Self] {
        &[
            Self::Id,
            Self::Name,
            Self::User,
            Self::Folder,
            Self::Uri,
            Self::EntryType,
        ]
    }
}

impl TryFrom<&String> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> anyhow::Result<Self> {
        Ok(match s.as_str() {
            "name" => Self::Name,
            "id" => Self::Id,
            "user" => Self::User,
            "folder" => Self::Folder,
            "type" => Self::EntryType,
            _ => return Err(anyhow::anyhow!("unknown field {s}")),
        })
    }
}

pub fn config_show() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    serde_json::to_writer_pretty(std::io::stdout(), &config)
        .context("failed to write config to stdout")?;
    println!();

    Ok(())
}

// TODO: Make this a Config method
pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load().unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "sso_id" => config.sso_id = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "ui_url" => config.ui_url = Some(value.to_string()),
        "notifications_url" => {
            config.notifications_url = Some(value.to_string());
        }
        "client_cert_path" => {
            config.client_cert_path = Some(PathBuf::from(value.to_string()));
        }
        "lock_timeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for lock_timeout")?;
            if timeout == 0 {
                log::error!("lock_timeout must be greater than 0");
            } else {
                config.lock_timeout = timeout;
            }
        }
        "sync_interval" => {
            let interval = value
                .parse()
                .context("failed to parse value for sync_interval")?;
            config.sync_interval = interval;
        }
        "pinentry" => config.pinentry = value.to_string(),
        "confirm_ssh" => config.confirm_ssh = Some(value == "true"),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()
}

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load().unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = None,
        "sso_id" => config.sso_id = None,
        "base_url" => config.base_url = None,
        "identity_url" => config.identity_url = None,
        "ui_url" => config.ui_url = None,
        "notifications_url" => config.notifications_url = None,
        "client_cert_path" => config.client_cert_path = None,
        "lock_timeout" => {
            config.lock_timeout = rbw::config::default_lock_timeout();
        }
        "pinentry" => config.pinentry = rbw::config::default_pinentry(),
        "confirm_ssh" => config.confirm_ssh = rbw::config::default_confirm_ssh(),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()
}

fn clipboard_store(val: &str) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::clipboard_store(val)
}

pub fn register() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::register()
}

pub fn login() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()
}

pub fn unlock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::unlock()
}

pub fn unlocked() -> anyhow::Result<()> {
    // not ensure_agent, because we don't want `rbw unlocked` to start the
    // agent if it's not running
    let _ = check_agent_version();
    crate::actions::unlocked()
}

pub fn sync() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::sync()
}

pub fn display_entry_field(entry: &rbw::db::Entry, desc: &str, field: &str) {
    let fields = entry.get_field(&field.to_lowercase(), rbw::totp::generate_totp);
    if fields.is_empty() {
        // TODO: This is not 100% compatible text output with the project before refactor.
        eprintln!("entry for '{desc}' had no {field} field");
    } else {
        fields.iter().for_each(|f| {
            println!("{f}");
        });
    }
}

pub fn display_entry_short(entry: &rbw::db::Entry, desc: &str) -> bool {
    let short = entry.get_short();
    let Some(short) = short else {
        // Would be cool if self.data had a method named main_field_name :D
        eprintln!(
            "entry for '{desc}' had no {}",
            match entry.data {
                EntryData::Login { .. } => "password",
                EntryData::Card { .. } => "card number",
                EntryData::Identity { .. } => "name",
                EntryData::SecureNote => "notes",
                EntryData::SshKey { .. } => "public key",
            }
        );
        return false;
    };

    println!("{short}");
    true
}

pub async fn get(
    FindArgs {
        needle,
        user,
        folder,
        ignorecase,
    }: FindArgs,
    field: Option<&str>,
    full: bool,
    raw: bool,
    clipboard: bool,
    list_fields: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let desc = format!(
        "{}{}",
        user.as_ref().map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let res = crate::actions::get(rbw::protocol::FindArgs {
        needle: needle.to_string(),
        user,
        folder,
        ignorecase,
    })?;
    let entry = match res {
        rbw::protocol::Response::Get { entry } => *entry,
        rbw::protocol::Response::Error { error } => {
            return Err(anyhow::anyhow!("{error}"));
        }
        _ => return Err(anyhow::anyhow!("unexpected message: {res:?}")),
    };

    if list_fields {
        entry
            .get_fields_list()
            .iter()
            .for_each(|field| println!("{field}"));
    } else if raw {
        serde_json::to_writer_pretty(std::io::stdout(), &entry)
            .context(format!("failed to write entry '{desc}' to stdout"))?;
        println!();
    } else {
        let short = entry.get_short();

        if clipboard {
            if let Some(field) = &field {
                let value = entry.get_field(field, rbw::totp::generate_totp);
                if let Err(e) = clipboard_store(&value.join(" ")) {
                    eprintln!("{e}");
                }
            } else if let Some(short) = &short {
                if let Err(e) = clipboard_store(short) {
                    eprintln!("{e}");
                }
            }
        }

        if full {
            // NOTE: In the previous version this printed "password", etc, the name of the "short"
            // field.
            if short.is_none() {
                eprintln!("entry for '{desc}' had no default field");
            }

            // NOTE: This printing is 99% backwards compatible, but the previous version was putting
            // EVERY field in the clipboard sequentially, leaving only the last at the end of course.
            // This behavior is unwanted, unnecessary and makes the code messy and for these reason
            // it has been removed. Now when specifying --clipboard, only the "short" field or the
            // --field value gets copied.
            print!("{entry}");
        } else if let Some(field) = field {
            display_entry_field(&entry, &desc, field);
        } else {
            display_entry_short(&entry, &desc);
        }
    }

    Ok(())
}

/// Used in "search" and "list"
fn print_entry_list(
    entries: &[rbw::search::SearchEntry],
    fields: &[ListField],
    raw: bool,
) -> anyhow::Result<()> {
    if raw {
        serde_json::to_writer_pretty(std::io::stdout(), &entries)
            .context("failed to write entries to stdout".to_string())?;
        println!();
    } else {
        for entry in entries {
            let values: Vec<&str> = fields
                .iter()
                .map(|field| match field {
                    ListField::Id => &entry.id,
                    ListField::Name => &entry.name,
                    ListField::User => entry.user.as_deref().unwrap_or(""),
                    ListField::Folder => entry.folder.as_deref().unwrap_or(""),
                    ListField::Uri => {
                        // "uri" is not listed in the TryFrom
                        // implementation, so there's no way to try to
                        // print it (and it's not clear what that would
                        // look like, since it's a list and not a single
                        // string)
                        unreachable!()
                    }
                    ListField::EntryType => &entry.entry_type,
                })
                .collect();

            // write to stdout but don't panic when pipe get's closed
            // this happens when piping stdout in a shell
            match writeln!(&mut std::io::stdout(), "{}", values.join("\t")) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                res => res,
            }?;
        }
    }

    Ok(())
}

pub async fn search(
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    raw: bool,
) -> anyhow::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all().to_vec()
    } else {
        fields
            .iter()
            .map(TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };

    unlock()?;

    let res = crate::actions::search(term.to_string(), folder.map(ToString::to_string))?;

    let mut entries = match res {
        rbw::protocol::Response::Search { entries } => entries,
        rbw::protocol::Response::Error { error } => {
            return Err(anyhow::anyhow!("{error}"));
        }
        _ => return Err(anyhow::anyhow!("unexpected message: {res:?}")),
    };

    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, raw)
}

pub async fn list(fields: &[String], raw: bool) -> anyhow::Result<()> {
    search("", fields, None, raw).await
}

pub async fn code(
    FindArgs {
        needle,
        user,
        folder,
        ignorecase,
    }: FindArgs,
    clipboard: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let res = crate::actions::code(rbw::protocol::FindArgs {
        needle: needle.to_string(),
        user,
        folder,
        ignorecase,
    })?;

    match res {
        rbw::protocol::Response::Code { code } => {
            if clipboard {
                if let Err(e) = clipboard_store(&code) {
                    eprintln!("{e}");
                }
            } else {
                println!("{code}");
            }
            Ok(())
        }
        rbw::protocol::Response::Error { error } => Err(anyhow::anyhow!("{error}")),
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn parse_editor(contents: &str) -> (Option<String>, Option<String>) {
    let mut lines = contents.lines();

    let password = lines.next().map(ToString::to_string);

    let mut notes: String = lines
        .skip_while(|line| line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    if notes.ends_with("\n") {
        notes.pop();
    }

    let notes = if notes.is_empty() { None } else { Some(notes) };

    (password, notes)
}

const HELP_PW: &str = r"
# The first line of this file will be the password, and the remainder of the
# file (after any blank lines after the password) will be stored as a note.
# Lines with leading # will be ignored.
";

const HELP_NOTES: &str = r"
# The content of this file will be stored as a note.
# Lines with leading # will be ignored.
";

pub async fn add(
    name: &str,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    unlock()?;

    let (password, notes) = match password {
        Some(password) => (Some(password.to_string()), None),
        None => {
            let contents = rbw::edit::edit("", HELP_PW)?;
            parse_editor(&contents)
        }
    };

    crate::actions::add(
        name.to_string(),
        username.map(ToString::to_string),
        uris.to_vec(),
        folder.map(ToString::to_string),
        password,
        notes,
    )
}

pub async fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{password}");

    match name {
        Some(name) => add(name, username, uris, folder, Some(&password)).await,
        None => Ok(()),
    }
}

pub async fn edit(
    FindArgs {
        needle,
        user,
        folder,
        ignorecase,
    }: FindArgs,
) -> anyhow::Result<()> {
    unlock()?;

    let res = crate::actions::get(rbw::protocol::FindArgs {
        needle: needle.to_string(),
        user: user.clone(),
        folder: folder.clone(),
        ignorecase,
    })?;
    let entry = match res {
        rbw::protocol::Response::Get { entry } => *entry,
        rbw::protocol::Response::Error { error } => {
            return Err(anyhow::anyhow!("{error}"));
        }
        _ => return Err(anyhow::anyhow!("unexpected message: {res:?}")),
    };

    let dec_notes = entry
        .notes
        .as_ref()
        .map_or_else(String::new, |n| format!("\n{n}\n"));

    // NOTE: Editing, previously, was limited to Login and SecureNote types. Now it's not limited
    // anymore. This behavior is not 100% backwards compatible, but it's hardly noticeable
    let (contents, help) = if let EntryData::Login { password, .. } = &entry.data {
        let dec_password = password.clone().unwrap_or_default();

        (format!("{dec_password}\n{dec_notes}"), HELP_PW)
    } else {
        (dec_notes, HELP_NOTES)
    };

    let (dec_password, dec_notes) = parse_editor(&rbw::edit::edit(&contents, help)?);

    let orig_password = match &entry.data {
        EntryData::Login { password, .. } => password.clone(),
        _ => None,
    };
    let password_changed = dec_password != orig_password;

    let orig_notes = entry.notes.clone();
    let notes_changed = dec_notes != orig_notes;

    crate::actions::edit(
        rbw::protocol::FindArgs {
            needle: needle.to_string(),
            user,
            folder,
            ignorecase,
        },
        if password_changed { dec_password } else { None },
        if notes_changed { dec_notes } else { None },
    )
}

pub async fn remove(
    FindArgs {
        needle,
        user,
        folder,
        ignorecase,
    }: FindArgs,
) -> anyhow::Result<()> {
    unlock()?;

    crate::actions::remove(rbw::protocol::FindArgs {
        needle: needle.to_string(),
        user,
        folder,
        ignorecase,
    })
}

pub async fn history(
    FindArgs {
        needle: name,
        user,
        folder,
        ignorecase,
    }: FindArgs,
) -> anyhow::Result<()> {
    unlock()?;

    let res = crate::actions::history(rbw::protocol::FindArgs {
        needle: name.to_string(),
        user,
        folder,
        ignorecase,
    })?;

    match res {
        rbw::protocol::Response::History { entries } => {
            for entry in entries {
                println!("{}: {}", entry.last_used_date, entry.password);
            }
            Ok(())
        }
        rbw::protocol::Response::Error { error } => Err(anyhow::anyhow!("{error}")),
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn lock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::lock()
}

pub fn purge() -> anyhow::Result<()> {
    stop_agent()?;

    let config = rbw::config::Config::load()?;

    let Some(email) = &config.email else {
        anyhow::bail!("failed to find email address in config");
    };

    rbw::db::Db::remove(&config.server_name(), email).map_err(anyhow::Error::new)
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()
}

fn ensure_agent() -> anyhow::Result<()> {
    check_config()?;
    if matches!(check_agent_version(), Ok(())) {
        return Ok(());
    }
    run_agent()?;
    check_agent_version()
}

fn run_agent() -> anyhow::Result<()> {
    let agent_path = std::env::var_os("RBW_AGENT");
    let agent_path = agent_path
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::from_bytes(b"rbw-agent"));
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!("failed to run rbw-agent: {status}"));
            }
        }
    }

    Ok(())
}

const MISSING_CONFIG_HELP: &str =
    "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        rbw config set base_url <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
        rbw config set identity_url <url>\n";

fn check_config() -> anyhow::Result<()> {
    rbw::config::Config::validate().map_err(|e| {
        log::error!("{MISSING_CONFIG_HELP}");
        anyhow::Error::new(e)
    })
}

fn check_agent_version() -> anyhow::Result<()> {
    let client_version = rbw::protocol::VERSION;
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        crate::actions::quit()?;
        anyhow::bail!(
            "client protocol version is {client_version} but agent protocol version is {agent_version}"
        );
    }
    Ok(())
}

fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().inspect_err(|_| {
        let _ = crate::actions::quit();
    })
}
