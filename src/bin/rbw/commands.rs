use std::{
    io::Write as _, os::unix::ffi::OsStrExt as _, path::PathBuf,
    time::SystemTime,
};

use anyhow::Context as _;
use rbw::{
    db::{Decrypted, Decrypter, Encrypted, Encrypter, EntryData},
    search::Needle,
};

use crate::FindArgs;

/// This Encrypter implementation will send the decrypted string to the agent and wait for it to
/// encrypt it.
struct RemoteEncrypter {}

impl<T> rbw::db::Encrypter<T> for RemoteEncrypter {
    fn encrypt_field(
        &mut self,
        entry: Option<&rbw::db::Entry<T>>,
        field: &str,
    ) -> rbw::error::Result<String> {
        crate::actions::encrypt(field, entry.and_then(|e| e.org_id.as_deref()))
            .map_err(|_e| rbw::error::Error::EncryptRemote)
    }
}

/// This Decrypter implementation will send the encrypted string to the agent and wait for it to
/// decrypt it.
struct RemoteDecrypter {}

impl<T> rbw::db::Decrypter<T> for RemoteDecrypter {
    fn decrypt_field(
        &mut self,
        entry: Option<&rbw::db::Entry<T>>,
        field: &str,
    ) -> rbw::error::Result<String> {
        crate::actions::decrypt(
            field,
            entry.and_then(|e| e.key.as_deref()),
            entry.and_then(|e| e.org_id.as_deref()),
        )
        .map_err(|_e| rbw::error::Error::DecryptRemote)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct SearchEntry {
    id: String,
    #[serde(rename = "type")]
    entry_type: String,
    folder: Option<String>,
    name: String,
    user: Option<String>,
    uris: Vec<(String, Option<rbw::api::UriMatchType>)>,
    fields: Vec<String>,
    notes: Option<String>,
}

impl SearchEntry {
    fn display_name(&self) -> String {
        self.user
            .as_ref()
            .map_or_else(|| self.name.clone(), |user| format!("{user}@{}", self.name))
    }

    #[allow(clippy::too_many_arguments)]
    fn matches(
        &self,
        needle: &Needle,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
        strict_username: bool,
        strict_folder: bool,
        exact: bool,
    ) -> bool {
        let match_str = match (ignore_case, exact) {
            (true, true) => {
                |field: &str, search_term: &str| field.to_lowercase() == search_term.to_lowercase()
            }
            (true, false) => |field: &str, search_term: &str| {
                field.to_lowercase().contains(&search_term.to_lowercase())
            },
            (false, true) => |field: &str, search_term: &str| field == search_term,
            (false, false) => |field: &str, search_term: &str| field.contains(search_term),
        };

        match (self.folder.as_deref(), folder) {
            (Some(folder), Some(given_folder)) => {
                if !match_str(folder, given_folder) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_folder {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match (&self.user, username) {
            (Some(username), Some(given_username)) => {
                if !match_str(username, given_username) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_username {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match needle {
            Needle::Uuid(uuid, s) => {
                if uuid::Uuid::parse_str(&self.id) != Ok(*uuid) && !match_str(&self.name, s) {
                    return false;
                }
            }
            Needle::Name(name) => {
                if !match_str(&self.name, name) {
                    return false;
                }
            }
            Needle::Uri(given_uri) => {
                if self
                    .uris
                    .iter()
                    .all(|(uri, match_type)| !matches_url(uri, *match_type, given_uri))
                {
                    return false;
                }
            }
        }

        true
    }

    fn search_match(&self, term: &str, folder: Option<&str>) -> bool {
        if folder.is_some() && self.folder.as_deref() != folder {
            return false;
        }

        let term = term.to_lowercase();

        [Some(&self.name), self.notes.as_ref(), self.user.as_ref()]
            .into_iter()
            .flatten()
            .chain(self.uris.iter().map(|(uri, _)| uri))
            .chain(self.fields.iter())
            .any(|f| f.to_lowercase().contains(&term))
    }
}

impl TryFrom<&rbw::db::Entry<Encrypted>> for SearchEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &rbw::db::Entry<Encrypted>) -> Result<Self, Self::Error> {
        let mut dec = RemoteDecrypter {};

        let user = match &entry.data {
            EntryData::Login { username, .. } => entry.decrypt_optstring(username, &mut dec)?,
            _ => None,
        };

        let name = entry.decrypt_string(&entry.name, &mut dec)?;
        let folder = entry.decrypt_optstring(&entry.folder, &mut dec)?;
        let notes = entry.decrypt_optstring(&entry.notes, &mut dec)?;

        let uris = entry
            .decrypt_uris(&mut dec)?
            .into_iter()
            .map(|u| (u.uri, u.match_type))
            .collect();

        let fields = entry
            .decrypt_custom_fields(&mut dec)?
            .into_iter()
            .filter_map(|f| {
                if f.ty == Some(rbw::api::FieldType::Hidden) {
                    None
                } else {
                    f.value
                }
            })
            .collect();

        let entry_type = (match &entry.data {
            rbw::db::EntryData::Login { .. } => "Login",
            rbw::db::EntryData::Identity { .. } => "Identity",
            rbw::db::EntryData::SshKey { .. } => "SSH Key",
            rbw::db::EntryData::SecureNote => "Note",
            rbw::db::EntryData::Card { .. } => "Card",
        })
        .to_string();

        Ok(SearchEntry {
            id: entry.id.clone(),
            entry_type,
            folder,
            name,
            user,
            uris,
            fields,
            notes,
        })
    }
}

fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port()
            .map_or_else(|| host.to_string(), |port| format!("{host}:{port}")),
    )
}

fn matches_url(
    url: &str,
    match_type: Option<rbw::api::UriMatchType>,
    given_url: &url::Url,
) -> bool {
    match match_type.unwrap_or(rbw::api::UriMatchType::Domain) {
        rbw::api::UriMatchType::Domain | rbw::api::UriMatchType::Host => {
            let is_domain = matches!(
                match_type.unwrap_or(rbw::api::UriMatchType::Domain),
                rbw::api::UriMatchType::Domain
            );
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && (self_host_port == given_host_port
                            || (is_domain
                                && given_host_port.ends_with(&format!(".{self_host_port}"))))
                    {
                        return true;
                    }
                }
            }
            url == given_host_port || (is_domain && given_host_port.ends_with(&format!(".{url}")))
        }
        rbw::api::UriMatchType::StartsWith => given_url.to_string().starts_with(url),
        rbw::api::UriMatchType::Exact => {
            given_url.to_string().trim_end_matches('/') == url.trim_end_matches('/')
        }
        rbw::api::UriMatchType::RegularExpression => {
            regex::Regex::new(url).is_ok_and(|rx| rx.is_match(given_url.as_ref()))
        }
        rbw::api::UriMatchType::Never => false,
    }
}

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

fn find_entry(
    db: &rbw::db::Db,
    mut needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<rbw::db::Entry<Encrypted>> {
    if let Needle::Uuid(uuid, s) = needle {
        for cipher in &db.entries {
            if uuid::Uuid::parse_str(&cipher.id) == Ok(uuid) {
                return Ok(cipher.clone());
            }
        }
        needle = Needle::Name(s);
    }

    let ciphers: Vec<(rbw::db::Entry<Encrypted>, SearchEntry)> = db
        .entries
        .iter()
        .map(|entry| entry.try_into().map(|decrypted| (entry.clone(), decrypted)))
        .collect::<anyhow::Result<_>>()?;

    let (entry, _) = find_entry_raw(&ciphers, &needle, username, folder, ignore_case)?;

    Ok(entry)
}

fn find_entry_raw(
    entries: &[(rbw::db::Entry<Encrypted>, SearchEntry)],
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry<Encrypted>, SearchEntry)> {
    let mut matches: Vec<(rbw::db::Entry<Encrypted>, SearchEntry)> = vec![];

    let find_matches = |strict_username, strict_folder, exact| {
        entries
            .iter()
            .filter(|&(_, decrypted_cipher)| {
                decrypted_cipher.matches(
                    needle,
                    username,
                    folder,
                    ignore_case,
                    strict_username,
                    strict_folder,
                    exact,
                )
            })
            .cloned()
            .collect()
    };

    for exact in [true, false] {
        matches = find_matches(true, true, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }

        let strict_folder_matches = find_matches(false, true, exact);
        let strict_username_matches = find_matches(true, false, exact);
        if strict_folder_matches.len() == 1 && strict_username_matches.len() != 1 {
            return Ok(strict_folder_matches[0].clone());
        } else if strict_folder_matches.len() != 1 && strict_username_matches.len() == 1 {
            return Ok(strict_username_matches[0].clone());
        }

        matches = find_matches(false, false, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }
    }

    if matches.is_empty() {
        Err(anyhow::anyhow!("no entry found"))
    } else {
        let entries: Vec<String> = matches
            .iter()
            .map(|(_, decrypted)| decrypted.display_name())
            .collect();
        let entries = entries.join(", ");
        Err(anyhow::anyhow!("multiple entries found: {entries}"))
    }
}

pub fn display_entry_field(entry: &rbw::db::Entry<Decrypted>, desc: &str, field: &str) {
    let fields = entry.get_field(&field.to_lowercase(), generate_totp);
    if fields.is_empty() {
        // TODO: This is not 100% compatible text output with the project before refactor.
        eprintln!("entry for '{desc}' had no {field} field");
    } else {
        fields.iter().for_each(|f| {
            println!("{f}");
        });
    }
}

pub fn display_entry_short(entry: &rbw::db::Entry<Decrypted>, desc: &str) -> bool {
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

    let db = load_db().await?;
    let mut dec = RemoteDecrypter {};

    let desc = format!(
        "{}{}",
        user.as_ref().map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let entry = find_entry(&db, needle, user.as_deref(), folder.as_deref(), ignorecase)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let decrypted = entry.decrypt(&mut dec)?;

    if list_fields {
        decrypted
            .get_fields_list()
            .iter()
            .for_each(|field| println!("{field}"));
    } else if raw {
        serde_json::to_writer_pretty(std::io::stdout(), &decrypted)
            .context(format!("failed to write entry '{desc}' to stdout"))?;
        println!();
    } else {
        let short = decrypted.get_short();

        if clipboard {
            if let Some(field) = &field {
                let value = decrypted.get_field(field, generate_totp);
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
            print!("{decrypted}");
        } else if let Some(field) = field {
            display_entry_field(&decrypted, &desc, field);
        } else {
            display_entry_short(&decrypted, &desc);
        }
    }

    Ok(())
}

/// Used in "search" and "list"
fn print_entry_list(
    entries: &[SearchEntry],
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

    let db = load_db().await?;

    let mut entries: Vec<SearchEntry> = db
        .entries
        .iter()
        .map(TryInto::try_into)
        .filter(|entry| {
            entry
                .as_ref()
                .map(|entry: &SearchEntry| entry.search_match(term, folder))
                .unwrap_or(true)
        })
        .collect::<Result<_, anyhow::Error>>()?;

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

    let db = load_db().await?;
    let mut dec = RemoteDecrypter {};

    let desc = format!(
        "{}{}",
        user.as_ref().map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let entry = find_entry(&db, needle, user.as_deref(), folder.as_deref(), ignorecase)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let EntryData::Login { totp, .. } = &entry.data {
        let totp = entry.decrypt_optstring(totp, &mut dec)?;

        if let Some(totp) = totp {
            let code = generate_totp(&totp)?;
            if clipboard {
                if let Err(e) = clipboard_store(&code) {
                    eprintln!("{e}");
                }
            } else {
                println!("{code}");
            }
        } else {
            return Err(anyhow::anyhow!("entry does not contain a totp secret"));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

async fn find_or_create_folder(db: &mut rbw::db::Db, folder: &str) -> anyhow::Result<String> {
    let enc: &mut dyn Encrypter<()> = &mut RemoteEncrypter {}; // fat ptr trick
    let dec: &mut dyn Decrypter<()> = &mut RemoteDecrypter {};

    let (new_access_token, new_refresh_token, folders) = rbw::actions::list_folders(
        db.access_token.as_ref().unwrap(),
        db.refresh_token.as_ref().unwrap(),
    )
    .await?;

    update_token(db, new_access_token, new_refresh_token).await?;

    let folders: Vec<(String, String)> = folders
        .into_iter()
        .map(|(id, name)| Ok((id, dec.decrypt_field(None, &name)?)))
        .collect::<anyhow::Result<_>>()?;

    let folder_id = folders
        .into_iter()
        .find_map(|(id, name)| if name == folder { Some(id) } else { None });

    let folder_id = if let Some(folder_id) = folder_id {
        folder_id
    } else {
        let (new_access_token, new_refresh_token, id) = rbw::actions::create_folder(
            db.access_token.as_ref().unwrap(),
            db.refresh_token.as_ref().unwrap(),
            &enc.encrypt_field(None, folder)?,
        )
        .await?;

        update_token(db, new_access_token, new_refresh_token).await?;

        id
    };

    Ok(folder_id)
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

async fn update_token(
    db: &mut rbw::db::Db,
    new_access_token: Option<String>,
    new_refresh_token: Option<String>,
) -> anyhow::Result<()> {
    let a = db.update_access_token(new_access_token);
    let b = db.update_refresh_token(new_refresh_token);
    if a || b {
        save_db(db).await?;
    }

    Ok(())
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
    let enc: &mut dyn Encrypter<()> = &mut RemoteEncrypter {}; // fat ptr trick

    unlock()?;

    let mut db = load_db().await?;
    // unwrap is safe here because the call to unlock above is guaranteed to
    // populate these or error

    let name = enc.encrypt_field(None, name)?;

    let username = username
        .map(|username| enc.encrypt_field(None, username))
        .transpose()?;

    let (password, notes) = match password {
        Some(password) => (Some(password.to_string()), None),
        None => {
            let contents = rbw::edit::edit("", HELP_PW)?;
            parse_editor(&contents)
        }
    };

    let password = password
        .map(|password| enc.encrypt_field(None, &password))
        .transpose()?;
    let notes = notes
        .map(|notes| enc.encrypt_field(None, &notes))
        .transpose()?;
    let uris: Vec<_> = uris
        .iter()
        .map(|uri| {
            Ok(rbw::db::Uri {
                uri: enc.encrypt_field(None, &uri.0)?,
                match_type: uri.1,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let folder_id = match folder {
        Some(folder) => Some(find_or_create_folder(&mut db, folder).await?),
        None => None,
    };

    let (new_token, new_refresh_token, ()) = rbw::actions::add(
        db.access_token.as_ref().unwrap(),
        db.refresh_token.as_ref().unwrap(),
        &name,
        &rbw::db::EntryData::Login {
            username,
            password,
            uris,
            totp: None,
        },
        notes.as_deref(),
        folder_id.as_deref(),
    )
    .await?;

    update_token(&mut db, new_token, new_refresh_token).await?;

    crate::actions::sync()
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

    let mut db = load_db().await?;

    let mut enc = RemoteEncrypter {};
    let mut dec = RemoteDecrypter {};

    let desc = format!(
        "{}{}",
        user.as_ref().map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let mut entry = find_entry(&db, needle, user.as_deref(), folder.as_deref(), ignorecase)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let dec_notes = entry
        .decrypt_optstring(&entry.notes, &mut dec)?
        .map_or_else(String::new, |n| format!("\n{n}\n"));

    // NOTE: Editing, previously, was limited to Login and SecureNote types. Now it's not limited
    // anymore. This behavior is not 100% backwards compatible, but it's hardly noticeable
    let (contents, help) = if let EntryData::Login { password, .. } = &entry.data {
        let dec_password = entry
            .decrypt_optstring(password, &mut dec)?
            .unwrap_or_else(String::new);

        (format!("{dec_password}\n{dec_notes}"), HELP_PW)
    } else {
        (dec_notes, HELP_NOTES)
    };

    let (dec_password, dec_notes) = parse_editor(&rbw::edit::edit(&contents, help)?);

    let new_enc_password = entry.encrypt_optstring(&dec_password, &mut enc)?;

    if let EntryData::Login { password, .. } = &mut entry.data {
        if let Some(prev_password) = password {
            entry.history.insert(
                0,
                rbw::db::HistoryEntry {
                    last_used_date: format!("{}", humantime::format_rfc3339(SystemTime::now())),
                    password: prev_password.clone(),
                },
            );
        }

        password.clone_from(&new_enc_password);
    }

    entry.notes = entry.encrypt_optstring(&dec_notes, &mut enc)?;

    let (new_token, new_refresh_token, ()) = rbw::actions::edit(
        db.access_token.as_ref().unwrap(),
        db.refresh_token.as_ref().unwrap(),
        &entry,
    )
    .await?;

    update_token(&mut db, new_token, new_refresh_token).await?;

    crate::actions::sync()
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

    let mut db = load_db().await?;

    let desc = format!(
        "{}{}",
        user.as_ref().map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let entry = find_entry(&db, needle, user.as_deref(), folder.as_deref(), ignorecase)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let (new_access_token, new_refresh_token, ()) = rbw::actions::remove(
        db.access_token.as_ref().unwrap(),
        db.refresh_token.as_ref().unwrap(),
        &entry.id,
    )
    .await?;

    update_token(&mut db, new_access_token, new_refresh_token).await?;

    crate::actions::sync()
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

    let db = load_db().await?;
    let mut dec = RemoteDecrypter {};

    let desc = format!(
        "{}{}",
        user.as_ref().map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let entry = find_entry(&db, name, user.as_deref(), folder.as_deref(), ignorecase)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    for history in entry.decrypt_history(&mut dec)? {
        println!("{}: {}", history.last_used_date, history.password);
    }

    Ok(())
}

pub fn lock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::lock()
}

pub fn purge() -> anyhow::Result<()> {
    stop_agent()?;

    remove_db()
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

async fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load()?;

    let Some(email) = &config.email else {
        anyhow::bail!("failed to find email address in config");
    };

    rbw::db::Db::load_async(&config.server_name(), email)
        .await
        .map_err(anyhow::Error::new)
}

async fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;

    let Some(email) = &config.email else {
        anyhow::bail!("failed to find email address in config");
    };

    db.save_async(&config.server_name(), email)
        .await
        .map_err(anyhow::Error::new)
}

fn remove_db() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;

    let Some(email) = &config.email else {
        anyhow::bail!("failed to find email address in config");
    };

    rbw::db::Db::remove(&config.server_name(), email).map_err(anyhow::Error::new)
}

fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let secret = secret.trim().replace(' ', "");
    let alphabets = [
        base32::Alphabet::Rfc4648 { padding: false },
        base32::Alphabet::Rfc4648 { padding: true },
        base32::Alphabet::Rfc4648Lower { padding: false },
        base32::Alphabet::Rfc4648Lower { padding: true },
    ];
    for alphabet in alphabets {
        if let Some(secret) = base32::decode(alphabet, &secret) {
            return Ok(secret);
        }
    }
    Err(anyhow::anyhow!("totp secret was not valid base32"))
}

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

fn generate_totp(secret: &str) -> anyhow::Result<String> {
    // Small hack that is not RFC compliant but helps with some services.
    // Most authenticators have this built-in, included official Bitwarden clients.
    let secret = secret.replace("algorithm=sha", "algorithm=SHA");

    let totp = match totp_rs::TOTP::from_url(&secret) {
        Ok(totp) => totp,
        Err(_e) => totp_rs::TOTP::new_unchecked(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            TOTP_DEFAULT_STEP,
            decode_totp_secret(&secret)?,
            None,
            "".to_string(),
        ),
    };

    Ok(totp.generate_current()?)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_find_entry() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry("gitter", Some("baz"), None, &[]),
            make_entry("git", Some("foo"), None, &[]),
            make_entry("bitwarden", None, None, &[]),
            make_entry("github", Some("foo"), Some("websites"), &[]),
            make_entry("github", Some("foo"), Some("ssh"), &[]),
            make_entry("github", Some("root"), Some("ssh"), &[]),
            make_entry("codeberg", Some("foo"), None, &[]),
            make_entry("codeberg", None, None, &[]),
            make_entry("1password", Some("foo"), None, &[]),
            make_entry("1password", None, Some("foo"), &[]),
        ];

        assert!(
            one_match(entries, "github", Some("foo"), None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), None, 0, true),
            "foo@GITHUB"
        );
        assert!(one_match(entries, "github", None, None, 0, false), "github");
        assert!(one_match(entries, "GITHUB", None, None, 0, true), "GITHUB");
        assert!(
            one_match(entries, "gitlab", Some("foo"), None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, "GITLAB", Some("foo"), None, 1, true),
            "foo@GITLAB"
        );
        assert!(
            one_match(entries, "git", Some("bar"), None, 2, false),
            "bar@git"
        );
        assert!(
            one_match(entries, "GIT", Some("bar"), None, 2, true),
            "bar@GIT"
        );
        assert!(
            one_match(entries, "gitter", Some("ba"), None, 3, false),
            "ba@gitter"
        );
        assert!(
            one_match(entries, "GITTER", Some("ba"), None, 3, true),
            "ba@GITTER"
        );
        assert!(
            one_match(entries, "git", Some("foo"), None, 4, false),
            "foo@git"
        );
        assert!(
            one_match(entries, "GIT", Some("foo"), None, 4, true),
            "foo@GIT"
        );
        assert!(one_match(entries, "git", None, None, 4, false), "git");
        assert!(one_match(entries, "GIT", None, None, 4, true), "GIT");
        assert!(
            one_match(entries, "bitwarden", None, None, 5, false),
            "bitwarden"
        );
        assert!(
            one_match(entries, "BITWARDEN", None, None, 5, true),
            "BITWARDEN"
        );
        assert!(
            one_match(entries, "github", Some("foo"), Some("websites"), 6, false),
            "websites/foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), Some("websites"), 6, true),
            "websites/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("foo"), Some("ssh"), 7, false),
            "ssh/foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), Some("ssh"), 7, true),
            "ssh/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("root"), None, 8, false),
            "ssh/root@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("root"), None, 8, true),
            "ssh/root@GITHUB"
        );

        assert!(
            no_matches(entries, "gitlab", Some("baz"), None, false),
            "baz@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("baz"), None, true),
            "baz@"
        );
        assert!(
            no_matches(entries, "bitbucket", Some("foo"), None, false),
            "foo@bitbucket"
        );
        assert!(
            no_matches(entries, "BITBUCKET", Some("foo"), None, true),
            "foo@BITBUCKET"
        );
        assert!(
            no_matches(entries, "github", Some("foo"), Some("bar"), false),
            "bar/foo@github"
        );
        assert!(
            no_matches(entries, "GITHUB", Some("foo"), Some("bar"), true),
            "bar/foo@"
        );
        assert!(
            no_matches(entries, "gitlab", Some("foo"), Some("bar"), false),
            "bar/foo@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("foo"), Some("bar"), true),
            "bar/foo@GITLAB"
        );

        assert!(many_matches(entries, "gitlab", None, None, false), "gitlab");
        assert!(many_matches(entries, "gitlab", None, None, true), "GITLAB");
        assert!(
            many_matches(entries, "gi", Some("foo"), None, false),
            "foo@gi"
        );
        assert!(
            many_matches(entries, "GI", Some("foo"), None, true),
            "foo@GI"
        );
        assert!(
            many_matches(entries, "git", Some("ba"), None, false),
            "ba@git"
        );
        assert!(
            many_matches(entries, "GIT", Some("ba"), None, true),
            "ba@GIT"
        );
        assert!(
            many_matches(entries, "github", Some("foo"), Some("s"), false),
            "s/foo@github"
        );
        assert!(
            many_matches(entries, "GITHUB", Some("foo"), Some("s"), true),
            "s/foo@GITHUB"
        );

        assert!(
            one_match(entries, "codeberg", Some("foo"), None, 9, false),
            "foo@codeberg"
        );
        assert!(
            one_match(entries, "codeberg", None, None, 10, false),
            "codeberg"
        );
        assert!(
            no_matches(entries, "codeberg", Some("bar"), None, false),
            "bar@codeberg"
        );

        assert!(
            many_matches(entries, "1password", None, None, false),
            "1password"
        );
    }

    #[test]
    fn test_find_by_uuid() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry("12345678-1234-1234-1234-1234567890ab", None, None, &[]),
            make_entry("12345678-1234-1234-1234-1234567890AC", None, None, &[]),
            make_entry("123456781234123412341234567890AD", None, None, &[]),
        ];

        assert!(
            one_match(entries, &entries[0].0.id, None, None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, &entries[1].0.id, None, None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, &entries[2].0.id, None, None, 2, false),
            "bar@gitlab"
        );

        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_uppercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );
        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_lowercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );

        assert!(one_match(entries, &entries[3].0.id, None, None, 3, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890ab",
            None,
            None,
            3,
            false
        ));
        assert!(no_matches(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            false
        ));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            3,
            true
        ));
        assert!(one_match(entries, &entries[4].0.id, None, None, 4, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AC",
            None,
            None,
            4,
            false
        ));
        assert!(one_match(entries, &entries[5].0.id, None, None, 5, false));
        assert!(one_match(
            entries,
            "123456781234123412341234567890AD",
            None,
            None,
            5,
            false
        ));
    }

    #[test]
    fn test_find_by_url_default() {
        let entries = &[
            make_entry("one", None, None, &[("https://one.com/", None)]),
            make_entry("two", None, None, &[("https://two.com/login", None)]),
            make_entry("three", None, None, &[("https://login.three.com/", None)]),
            make_entry("four", None, None, &[("four.com", None)]),
            make_entry("five", None, None, &[("https://five.com:8080/", None)]),
            make_entry("six", None, None, &[("six.com:8080", None)]),
            make_entry("seven", None, None, &[("192.168.0.128:8080", None)]),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://login.one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/other-page", None, None, 1, false),
            "two"
        );

        assert!(
            one_match(entries, "https://login.three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(entries, "https://five.com:8080/", None, None, 4, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(entries, "https://192.168.0.128:8080/", None, None, 6, false),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_domain() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[("192.168.0.128:8080", Some(rbw::api::UriMatchType::Domain))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://login.one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/other-page", None, None, 1, false),
            "two"
        );

        assert!(
            one_match(entries, "https://login.three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(entries, "https://five.com:8080/", None, None, 4, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(entries, "https://192.168.0.128:8080/", None, None, 6, false),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_host() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[("https://two.com/login", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[("https://five.com:8080/", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[("192.168.0.128:8080", Some(rbw::api::UriMatchType::Host))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/other-page", None, None, 1, false),
            "two"
        );

        assert!(
            one_match(entries, "https://login.three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(entries, "https://five.com:8080/", None, None, 4, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(entries, "https://192.168.0.128:8080/", None, None, 6, false),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_starts_with() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::StartsWith))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/login/sso", None, None, 1, false),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/other-page", None, None, false),
            "two"
        );

        assert!(
            one_match(entries, "https://login.three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_exact() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Exact))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[("https://two.com/login", Some(rbw::api::UriMatchType::Exact))],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("https://four.com", Some(rbw::api::UriMatchType::Exact))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com/foo", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/login/sso", None, None, false),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/other-page", None, None, false),
            "two"
        );

        assert!(
            one_match(entries, "https://login.three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );
        assert!(
            one_match(entries, "https://four.com", None, None, 3, false),
            "four"
        );
        assert!(
            no_matches(entries, "https://four.com/foo", None, None, false),
            "four"
        );
    }

    #[test]
    fn test_find_by_url_regex() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    r"^https://one\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    r"^https://two\.com/(login|start)",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    r"^https://(login\.)?three\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/start", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/login/sso", None, None, 1, false),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/other-page", None, None, false),
            "two"
        );

        assert!(
            one_match(entries, "https://login.three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            one_match(entries, "https://three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://www.three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_never() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[("https://two.com/login", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Never))],
            ),
        ];

        assert!(
            no_matches(entries, "https://one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com:443/", None, None, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/other-page", None, None, false),
            "two"
        );

        assert!(
            no_matches(entries, "https://login.three.com/", None, None, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            no_matches(entries, "https://four.com/", None, None, false),
            "four"
        );

        assert!(
            no_matches(entries, "https://five.com:8080/", None, None, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            no_matches(entries, "https://six.com:8080/", None, None, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
    }

    #[test]
    fn test_find_with_multiple_urls() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[
                    ("https://one.com/", Some(rbw::api::UriMatchType::Domain)),
                    ("https://two.com/", Some(rbw::api::UriMatchType::Domain)),
                ],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            no_matches(entries, "https://zero.com/", None, None, false),
            "zero"
        );
        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            many_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
    }

    #[test]
    fn test_decode_totp_secret() {
        let decoded = decode_totp_secret("NBSW Y3DP EB3W 64TM MQQQ").unwrap();
        let want = b"hello world!".to_vec();
        assert!(decoded == want, "strips spaces");
    }

    #[track_caller]
    fn one_match(
        entries: &[(rbw::db::Entry<Encrypted>, SearchEntry)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        idx: usize,
        ignore_case: bool,
    ) -> bool {
        entries_eq(
            &find_entry_raw(
                entries,
                &needle.parse().unwrap(),
                username,
                folder,
                ignore_case,
            )
            .unwrap(),
            &entries[idx],
        )
    }

    #[track_caller]
    fn no_matches(
        entries: &[(rbw::db::Entry<Encrypted>, SearchEntry)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &needle.parse().unwrap(),
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("no entry found")
        } else {
            false
        }
    }

    #[track_caller]
    fn many_matches(
        entries: &[(rbw::db::Entry<Encrypted>, SearchEntry)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &needle.parse().unwrap(),
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("multiple entries found")
        } else {
            false
        }
    }

    #[track_caller]
    fn entries_eq(
        a: &(rbw::db::Entry<Encrypted>, SearchEntry),
        b: &(rbw::db::Entry<Encrypted>, SearchEntry),
    ) -> bool {
        a.0 == b.0 && a.1 == b.1
    }

    fn make_entry(
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        uris: &[(&str, Option<rbw::api::UriMatchType>)],
    ) -> (rbw::db::Entry<Encrypted>, SearchEntry) {
        let id = uuid::Uuid::new_v4();
        (
            rbw::db::Entry::<Encrypted> {
                id: id.to_string(),
                org_id: None,
                folder: folder.map(|_| "encrypted folder name".to_string()),
                folder_id: None,
                name: "this is the encrypted name".to_string(),
                data: rbw::db::EntryData::Login {
                    username: username.map(|_| "this is the encrypted username".to_string()),
                    password: None,
                    uris: uris
                        .iter()
                        .map(|(_, match_type)| rbw::db::Uri {
                            uri: "this is the encrypted uri".to_string(),
                            match_type: *match_type,
                        })
                        .collect(),
                    totp: None,
                },
                fields: vec![],
                notes: None,
                history: vec![],
                key: None,
                master_password_reprompt: rbw::api::CipherRepromptType::None,
                _state: std::marker::PhantomData,
            },
            SearchEntry {
                id: id.to_string(),
                entry_type: "Login".to_string(),
                folder: folder.map(ToString::to_string),
                name: name.to_string(),
                user: username.map(ToString::to_string),
                uris: uris
                    .iter()
                    .map(|(uri, match_type)| ((*uri).to_string(), *match_type))
                    .collect(),
                fields: vec![],
                notes: None,
            },
        )
    }
}
