use std::{collections::HashMap, future::Future, sync::Arc};

use anyhow::Context as _;
use rbw::{
    actions::SessionParameters,
    db::{Db, Decrypter, Encrypter, EntryData},
    error::Error,
};

use crate::agent::Agent;

async fn with_retry<C, Fut, T>(c: C) -> anyhow::Result<T>
where
    C: Fn(Option<String>) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let mut err_msg = None;

    for i in 1..=3 {
        let err = err_msg.map(|msg| format!("{msg} (attempt {i}/3)"));

        match c(err).await {
            Ok(r) => {
                return Ok(r);
            }
            Err(e) => {
                if let Some(e) = e.downcast_ref::<rbw::error::Error>() {
                    match e {
                        rbw::error::Error::IncorrectPassword { message } if i < 3 => {
                            err_msg = Some(message.clone());
                            continue;
                        }
                        // TODO: Move this back where it was if possible
                        rbw::error::Error::TwoFactorRequired { .. } if i < 3 => {
                            err_msg = Some("TOTP code is not a number".to_string());
                            continue;
                        }
                        _ => {}
                    }
                }

                return Err(e);
            }
        }
    }

    unreachable!()
}

impl Agent {
    async fn getpin(
        &self,
        desc: &str,
        prompt: &str,
        err: &Option<String>,
        environment: &rbw::protocol::Environment,
        grab: bool,
    ) -> anyhow::Result<rbw::locked::Password> {
        Ok(rbw::pinentry::getpin(
            self.config_pinentry(),
            prompt,
            desc,
            err.as_deref(),
            environment,
            grab,
        )
        .await?)
    }

    async fn get_client_id_secret(
        &self,
        host: &str,
        err: &Option<String>,
        environment: &rbw::protocol::Environment,
    ) -> anyhow::Result<(rbw::locked::Password, rbw::locked::Password)> {
        let id = self
            .getpin(
                "API key client__id",
                &format!("Log in to {host}"),
                err,
                environment,
                false,
            )
            .await
            .context("failed to read client_id from pinentry")?;

        let secret = self
            .getpin(
                "API key client__secret",
                &format!("Log in to {host}"),
                err,
                environment,
                false,
            )
            .await
            .context("failed to read client_secret from pinentry")?;

        Ok((id, secret))
    }

    fn get_host(&self) -> anyhow::Result<String> {
        let url_str = self.base_url();
        let url = reqwest::Url::parse(&url_str).context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        Ok(host.to_string())
    }

    pub async fn register(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
    ) -> anyhow::Result<()> {
        if !self.inner.db.read().await.needs_login() {
            return respond_ack(sock).await;
        }

        let host = &self.get_host()?;

        let email = &self.email()?.to_string();

        with_retry(|e| async move {
            let (client_id, client_secret) =
                self.get_client_id_secret(host, &e, environment).await?;

            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);

            Ok(rbw::actions::register(email, apikey).await?)
        })
        .await
        .context("failed to log in to bitwarden instance")?;

        respond_ack(sock).await?;

        Ok(())
    }

    async fn get_code(
        &self,
        provider: rbw::api::TwoFactorProviderType,
        err: &Option<String>,
        environment: &rbw::protocol::Environment,
    ) -> anyhow::Result<rbw::locked::Password> {
        self.getpin(
            provider.header(),
            provider.message(),
            err,
            environment,
            provider.grab(),
        )
        .await
        .context("failed to read code from pinentry")
    }

    async fn two_factor(
        &self,
        environment: &rbw::protocol::Environment,
        password: &rbw::locked::Password,
        provider: rbw::api::TwoFactorProviderType,
    ) -> anyhow::Result<SessionParameters> {
        let email = self.email()?;

        with_retry(|err| async move {
            let code = self.get_code(provider, &err, environment).await?;
            let code = std::str::from_utf8(code.password()).context("code was not valid utf8")?;

            Ok(rbw::actions::login(email, password, Some(code), Some(provider)).await?)
        })
        .await
    }

    async fn two_factor_required(
        &self,
        password: &rbw::locked::Password,
        providers: Vec<rbw::api::TwoFactorProviderType>,
        sso_email_2fa_session_token: Option<String>,
        environment: &rbw::protocol::Environment,
    ) -> anyhow::Result<SessionParameters> {
        let supported_types = [
            rbw::api::TwoFactorProviderType::Authenticator,
            rbw::api::TwoFactorProviderType::Yubikey,
            rbw::api::TwoFactorProviderType::Email,
        ];

        let Some(provider) = supported_types.into_iter().find(|p| providers.contains(p)) else {
            return Err(anyhow::anyhow!(
                "unsupported two factor methods: {providers:?}"
            ));
        };

        let email = self.email()?;

        if provider == rbw::api::TwoFactorProviderType::Email {
            log::trace!("Two factor provider is email");
            if let Some(token) = sso_email_2fa_session_token {
                log::trace!("Sending 2FA email");
                rbw::actions::send_two_factor_email(email, &token).await?;
            }
        }

        log::trace!("Performing 2FA login");

        let creds = self.two_factor(environment, password, provider).await?;

        Ok(creds)
    }

    async fn get_password(
        &self,
        desc: &str,
        err: &Option<String>,
        environment: &rbw::protocol::Environment,
    ) -> anyhow::Result<rbw::locked::Password> {
        self.getpin("Master Password", desc, err, environment, true)
            .await
            .context("failed to read password from pinentry")
    }

    pub async fn login(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
    ) -> anyhow::Result<()> {
        if !self.inner.db.read().await.needs_login() {
            return respond_ack(sock).await;
        }

        let host = &self.get_host()?;

        let email = &self.email()?.to_string();

        let (creds, password) = with_retry(|err| async move {
            let password = self
                .get_password(&format!("Log in to {host}"), &err, environment)
                .await?;

            let r = match rbw::actions::login(email, &password, None, None).await {
                Err(Error::TwoFactorRequired {
                    providers,
                    sso_email_2fa_session_token,
                }) => {
                    log::trace!("Login requires 2FA, performing it.");

                    let ret = match self
                        .two_factor_required(
                            &password,
                            providers,
                            sso_email_2fa_session_token,
                            environment,
                        )
                        .await
                    {
                        Ok(creds) => Ok((creds, password)),
                        // Handling Err manually instead of letting with_retry handle it, because
                        // "e" might be "IncorrectPassword" if the user fails to input the TOTP.
                        Err(e) => Err(anyhow::anyhow!("2FA verification failed: {e}")),
                    }?;

                    Ok(ret)
                }
                Ok(creds) => Ok((creds, password)),
                Err(e) => Err(e),
            };

            Ok(r?)
        })
        .await
        .context("failed to log in to bitwarden instance")?;

        log::debug!("Login successful. Applying session parameters..");

        {
            let mut db = self.inner.db.write().await;

            db.apply_session_parameters(&creds);

            db.save_async(&self.server_name(), self.email()?).await?;
        }

        log::trace!("Session parameters set. Syncing..");
        self.sync(None).await?;

        log::trace!("Sync performed. Trying to unlock with the current password..");

        self.try_unlock(&password)
            .await
            .context("failed to unlock database")?;

        log::trace!("Login and unlock successful!");

        respond_ack(sock).await?;

        Ok(())
    }

    pub async fn unlock(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
    ) -> anyhow::Result<()> {
        self.unlock_state(environment).await?;

        respond_ack(sock).await?;

        Ok(())
    }

    pub async fn lock(&self, sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
        self.clear().await;

        respond_ack(sock).await?;

        Ok(())
    }

    pub async fn check_lock(&self, sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
        if self.needs_unlock().await {
            return Err(anyhow::anyhow!("agent is locked"));
        }

        respond_ack(sock).await?;

        Ok(())
    }

    pub async fn sync(&self, sock: Option<&mut crate::sock::Sock>) -> anyhow::Result<()> {
        // Sync is the only one that reads an updated copy of the db from disk
        let db = Db::load_async(&self.server_name(), self.email()?).await?;
        log::trace!("Read fresh db from disk");

        let Some(access_token) = &db.access_token else {
            anyhow::bail!("failed to find access token in db");
        };

        let Some(refresh_token) = &db.refresh_token else {
            anyhow::bail!("failed to find refresh token in db");
        };

        log::trace!("Obtained access and refresh tokens");

        let (access_token, (protected_key, protected_private_key, protected_org_keys, entries)) =
            rbw::actions::sync(access_token, refresh_token)
                .await
                .context("failed to sync database from server")?;

        log::trace!("Sync operation finished");

        // And then update the local cached copy of the db
        {
            let mut db = self.inner.db.write().await;

            log::trace!("Opened cached db for write operation");

            db.update_access_token(access_token);

            db.protected_key = Some(protected_key);
            db.protected_private_key = Some(protected_private_key);
            db.protected_org_keys = protected_org_keys;
            db.entries = entries;

            db.save_async(&self.server_name(), self.email()?).await?;
        }

        log::trace!("Updated disk db");

        // This is done on purpose, as the sync might happen while the db is locked, so we don't
        // care about errors here.
        if let Ok(()) = self.refresh_decrypted_entries().await {
            log::trace!("Refreshed decrypted entries cache");
        }

        if let Err(e) = self.subscribe_to_notifications().await {
            eprintln!("failed to subscribe to notifications: {e}");
        }

        if let Some(sock) = sock {
            respond_ack(sock).await?;
        }

        Ok(())
    }

    async fn maybe_reprompt_password(
        &self,
        environment: &rbw::protocol::Environment,
        entry: &rbw::db::Entry,
    ) -> anyhow::Result<()> {
        if entry.master_password_reprompt() {
            log::trace!("Requesting password reprompt for entry '{}'", entry.name);

            with_retry(|err| async move {
                let password = self
                    .get_password(
                        "Accessing this entry requires the master password",
                        &err,
                        environment,
                    )
                    .await?;

                self.try_unlock(&password).await
            })
            .await
            .context("failed to reprompt for master password")?;

            log::trace!("Password correct, reprompt successful");
        }

        Ok(())
    }

    async fn refresh_decrypted_entries(&self) -> anyhow::Result<()> {
        let db = self.inner.db.read().await;
        let mut dec = self.decrypter().await?;
        let mut decrypted = Vec::with_capacity(db.entries.len());

        for entry in &db.entries {
            decrypted.push(entry.decrypt_non_sensitive(&mut dec)?);
        }

        drop(db);

        let mut cache = self.inner.decrypted_entries.write().await;
        *cache = Some(decrypted);

        Ok(())
    }

    async fn get_decrypted_entries(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, Option<Vec<rbw::db::Entry>>> {
        self.inner.decrypted_entries.read().await
    }

    async fn decrypter(&self) -> anyhow::Result<LocalDecrypter> {
        let priv_key = self
            .inner
            .priv_key
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no personal keys"))?;
        let org_keys = self.inner.org_keys.read().await.clone().unwrap_or_default();
        Ok(LocalDecrypter { priv_key, org_keys })
    }

    async fn encrypter(&self) -> anyhow::Result<LocalEncrypter> {
        let priv_key = self
            .inner
            .priv_key
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no personal keys"))?;
        let org_keys = self.inner.org_keys.read().await.clone().unwrap_or_default();
        Ok(LocalEncrypter { priv_key, org_keys })
    }

    async fn update_token(&self, new_token: Option<String>) -> anyhow::Result<()> {
        if let Some(new_token) = new_token {
            let mut db = self.inner.db.write().await;
            if db.update_access_token(Some(new_token)) {
                db.save_async(&self.server_name(), self.email()?).await?;
            }
        }
        Ok(())
    }

    async fn find_or_create_folder(&self, folder: &str) -> anyhow::Result<String> {
        let db = self.inner.db.read().await;
        let access_token = db
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no access token"))?;
        let refresh_token = db
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no refresh token"))?;
        let (new_access_token, folders) =
            rbw::actions::list_folders(access_token, refresh_token).await?;
        drop(db);
        self.update_token(new_access_token).await?;

        let mut dec = self.decrypter().await?;

        let mut folder_id = None;
        for (id, name) in folders {
            let decrypted_name = dec.decrypt_field(None, &name)?;
            if decrypted_name == folder {
                folder_id = Some(id);
                break;
            }
        }

        if let Some(folder_id) = folder_id {
            Ok(folder_id)
        } else {
            let db = self.inner.db.read().await;
            let access_token = db
                .access_token
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no access token"))?;
            let refresh_token = db
                .refresh_token
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no refresh token"))?;
            let mut enc = self.encrypter().await?;
            let enc_folder = enc.encrypt_field(None, folder)?;
            let (new_access_token, id) =
                rbw::actions::create_folder(access_token, refresh_token, &enc_folder).await?;
            drop(db);
            self.update_token(new_access_token).await?;
            Ok(id)
        }
    }

    pub async fn get(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
        find: &rbw::protocol::FindArgs,
    ) -> anyhow::Result<()> {
        self.unlock_state(environment).await?;
        let partial_entry = {
            let guard = self.get_decrypted_entries().await;
            let decrypted_entries = guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("decrypted entries cache not initialized"))?;
            rbw::search::find_entry(decrypted_entries, find)?.clone()
        };
        self.maybe_reprompt_password(environment, &partial_entry)
            .await?;

        let mut entry = partial_entry.clone();
        let mut dec = self.decrypter().await?;
        entry
            .fill_sensitive_fields(&mut dec)
            .map_err(anyhow::Error::new)?;

        sock.send(&rbw::protocol::Response::Get {
            entry: Box::new(entry),
        })
        .await?;
        Ok(())
    }

    pub async fn search(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
        term: &str,
        folder: Option<&str>,
    ) -> anyhow::Result<()> {
        self.unlock_state(environment).await?;
        let guard = self.get_decrypted_entries().await;
        let decrypted_entries = guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("decrypted entries cache not initialized"))?;
        let mut entries: Vec<rbw::search::SearchEntry> = decrypted_entries
            .iter()
            .filter(|entry| {
                let search_entry: rbw::search::SearchEntry = (*entry).into();
                search_entry.search_match(term, folder)
            })
            .map(|entry| entry.into())
            .collect();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        sock.send(&rbw::protocol::Response::Search { entries })
            .await?;
        Ok(())
    }

    pub async fn code(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
        find: &rbw::protocol::FindArgs,
    ) -> anyhow::Result<()> {
        self.unlock_state(environment).await?;
        let partial_entry = {
            let guard = self.get_decrypted_entries().await;
            let decrypted_entries = guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("decrypted entries cache not initialized"))?;
            rbw::search::find_entry(decrypted_entries, find)?.clone()
        };
        self.maybe_reprompt_password(environment, &partial_entry)
            .await?;

        let EntryData::Login {
            totp: Some(totp_enc),
            ..
        } = &partial_entry.data
        else {
            return Err(anyhow::anyhow!("not a login entry or no totp secret"));
        };

        let mut dec = self.decrypter().await?;
        let totp = partial_entry
            .decrypt_string(totp_enc, &mut dec)
            .map_err(anyhow::Error::new)?;
        let code = rbw::totp::generate_totp(&totp)?;
        sock.send(&rbw::protocol::Response::Code { code }).await?;
        Ok(())
    }

    pub async fn add(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
        entry: &rbw::protocol::AddEntry,
    ) -> anyhow::Result<()> {
        self.unlock_state(environment).await?;

        let mut enc = self.encrypter().await?;
        let name = enc.encrypt_field(None, &entry.name)?;
        let username = entry
            .username
            .as_deref()
            .map(|username| enc.encrypt_field(None, username))
            .transpose()?;
        let password = entry
            .password
            .as_deref()
            .map(|password| enc.encrypt_field(None, password))
            .transpose()?;
        let notes = entry
            .notes
            .as_deref()
            .map(|notes| enc.encrypt_field(None, notes))
            .transpose()?;
        let uris: Vec<rbw::db::Uri> = entry
            .uris
            .iter()
            .map(|(uri, match_type)| {
                Ok(rbw::db::Uri {
                    uri: enc.encrypt_field(None, uri)?,
                    match_type: *match_type,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let folder_id = match &entry.folder {
            Some(folder) => Some(self.find_or_create_folder(folder).await?),
            None => None,
        };

        let db = self.inner.db.read().await;
        let access_token = db
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no access token"))?;
        let refresh_token = db
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no refresh token"))?;
        let (new_access_token, ()) = rbw::actions::add(
            access_token,
            refresh_token,
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
        drop(db);
        self.update_token(new_access_token).await?;
        self.sync(Some(sock)).await
    }

    pub async fn edit(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
        find: &rbw::protocol::FindArgs,
        password: Option<&str>,
        notes: Option<&str>,
    ) -> anyhow::Result<()> {
        self.unlock_state(environment).await?;

        let dec_entry = {
            let guard = self.get_decrypted_entries().await;
            let decrypted_entries = guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("decrypted entries cache not initialized"))?;
            rbw::search::find_entry(decrypted_entries, find)?.clone()
        };
        self.maybe_reprompt_password(environment, &dec_entry)
            .await?;
        let id = dec_entry.id;

        let db = self.inner.db.read().await;
        let entry = db
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("entry not found in database"))?;
        drop(db);

        let mut entry = entry;
        let mut enc = self.encrypter().await?;

        if let Some(password) = password {
            if let EntryData::Login { .. } = &entry.data {
                let encrypted = if password.is_empty() {
                    None
                } else {
                    Some(enc.encrypt_field(Some(&entry), password)?)
                };
                if let EntryData::Login {
                    password: cur_pw, ..
                } = &mut entry.data
                {
                    if let Some(prev) = cur_pw.take() {
                        if !prev.is_empty() {
                            entry.history.insert(
                                0,
                                rbw::db::HistoryEntry {
                                    last_used_date: format!(
                                        "{}",
                                        humantime::format_rfc3339(std::time::SystemTime::now())
                                    ),
                                    password: prev,
                                },
                            );
                        }
                    }
                    *cur_pw = encrypted;
                }
            }
        }

        if let Some(notes) = notes {
            if notes.is_empty() {
                entry.notes = None;
            } else {
                entry.notes = Some(enc.encrypt_field(Some(&entry), notes)?);
            }
        }

        let db = self.inner.db.read().await;
        let access_token = db
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no access token"))?;
        let refresh_token = db
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no refresh token"))?;
        let (new_access_token, ()) =
            rbw::actions::edit(access_token, refresh_token, &entry).await?;
        drop(db);
        self.update_token(new_access_token).await?;
        self.sync(Some(sock)).await
    }

    pub async fn remove(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
        find: &rbw::protocol::FindArgs,
    ) -> anyhow::Result<()> {
        self.unlock_state(environment).await?;
        let entry_id = {
            let guard = self.get_decrypted_entries().await;
            let decrypted_entries = guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("decrypted entries cache not initialized"))?;
            rbw::search::find_entry(decrypted_entries, find)?.id
        };

        let db = self.inner.db.read().await;
        let access_token = db
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no access token"))?;
        let refresh_token = db
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no refresh token"))?;
        let (new_access_token, ()) =
            rbw::actions::remove(access_token, refresh_token, &entry_id).await?;
        drop(db);
        self.update_token(new_access_token).await?;
        self.sync(Some(sock)).await
    }

    pub async fn history(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
        find: &rbw::protocol::FindArgs,
    ) -> anyhow::Result<()> {
        self.unlock_state(environment).await?;
        let partial_entry = {
            let guard = self.get_decrypted_entries().await;
            let decrypted_entries = guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("decrypted entries cache not initialized"))?;
            rbw::search::find_entry(decrypted_entries, find)?.clone()
        };
        self.maybe_reprompt_password(environment, &partial_entry)
            .await?;

        let mut dec = self.decrypter().await?;
        let history = partial_entry
            .decrypt_history(&mut dec)
            .map_err(anyhow::Error::new)?;

        sock.send(&rbw::protocol::Response::History { entries: history })
            .await?;
        Ok(())
    }

    #[cfg(feature = "clipboard")]
    pub async fn clipboard_store(
        &self,
        sock: &mut crate::sock::Sock,
        text: &str,
    ) -> anyhow::Result<()> {
        if let Some(clipboard) = &mut (*self.clipboard_mut().await) {
            clipboard
                .set_text(text)
                .map_err(|e| anyhow::anyhow!("couldn't store value to clipboard: {e}"))?;
        }

        respond_ack(sock).await?;

        Ok(())
    }

    #[cfg(not(feature = "clipboard"))]
    pub async fn clipboard_store(
        &self,
        sock: &mut crate::sock::Sock,
        _text: &str,
    ) -> anyhow::Result<()> {
        sock.send(&rbw::protocol::Response::Error {
            error: "clipboard not supported".to_string(),
        })
        .await?;

        Ok(())
    }

    async fn try_unlock(&self, password: &rbw::locked::Password) -> anyhow::Result<()> {
        let db = self.inner.db.read().await;

        let (protected_key, protected_private_key, protected_org_keys) =
            db.some_protected_keys()
                .ok_or(Error::UnavailableDbProtectedKeys)?;

        let (keys, org_keys) = rbw::actions::unlock(
            self.email()?,
            password,
            &db.get_crypto_parameters()?,
            protected_key,
            protected_private_key,
            protected_org_keys,
        )?;

        self.set_keys(keys, org_keys).await;

        drop(db);

        self.refresh_decrypted_entries().await?;

        Ok(())
    }

    async fn unlock_state(&self, environment: &rbw::protocol::Environment) -> anyhow::Result<()> {
        if self.needs_unlock().await {
            with_retry(|err| async move {
                let password = self
                    .get_password(
                        &format!("Unlock the local database for '{}'", rbw::dirs::profile()),
                        &err,
                        environment,
                    )
                    .await?;

                self.try_unlock(&password).await
            })
            .await
            .context("failed to unlock database")?;
        }

        Ok(())
    }

    pub async fn get_ssh_public_keys(&self) -> anyhow::Result<Vec<String>> {
        let environment = { self.last_environment().await.clone() };

        log::trace!("Resetting lock timeout due to get_ssh_public_keys");
        self.reset_lock_timeout().await;

        log::trace!("Trying to unlock state");
        self.unlock_state(&environment).await?;

        let db = self.inner.db.read().await;
        let ssh_entries: Vec<_> = db
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    &e.data,
                    EntryData::SshKey {
                        public_key: Some(_),
                        ..
                    }
                )
            })
            .cloned()
            .collect();
        drop(db);

        let mut pubkeys = vec![];

        for entry in ssh_entries {
            let mut dec = self.decrypter().await?;
            if let EntryData::SshKey {
                public_key: Some(pubkey),
                ..
            } = &entry.data
            {
                pubkeys.push(
                    entry
                        .decrypt_string(pubkey, &mut dec)
                        .map_err(anyhow::Error::new)?,
                );
            }
        }

        Ok(pubkeys)
    }

    pub async fn find_ssh_private_key(
        &self,
        request_public_key: ssh_agent_lib::ssh_key::PublicKey,
    ) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
        let environment = {
            let le = self.last_environment().await;
            self.reset_lock_timeout().await;
            le.clone()
        };

        self.unlock_state(&environment).await?;

        let request_bytes = request_public_key.to_bytes();

        let db = self.inner.db.read().await;
        let ssh_entries: Vec<_> = db
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    &e.data,
                    EntryData::SshKey {
                        public_key: Some(_),
                        private_key: Some(_),
                        ..
                    }
                )
            })
            .cloned()
            .collect();
        drop(db);

        for entry in ssh_entries {
            let mut dec = self.decrypter().await?;

            let pub_plain = if let EntryData::SshKey {
                public_key: Some(pubkey),
                ..
            } = &entry.data
            {
                entry
                    .decrypt_string(pubkey, &mut dec)
                    .map_err(anyhow::Error::new)?
            } else {
                continue;
            };

            let pub_bytes = ssh_agent_lib::ssh_key::PublicKey::from_openssh(&pub_plain)?.to_bytes();

            if pub_bytes != request_bytes {
                continue;
            }

            self.maybe_reprompt_password(&environment, &entry).await?;

            let priv_plain = if let EntryData::SshKey {
                private_key: Some(privkey),
                ..
            } = &entry.data
            {
                entry
                    .decrypt_string(privkey, &mut dec)
                    .map_err(anyhow::Error::new)?
            } else {
                continue;
            };

            return ssh_agent_lib::ssh_key::PrivateKey::from_openssh(&priv_plain)
                .map_err(anyhow::Error::new);
        }

        Err(anyhow::anyhow!("No matching private key found"))
    }

    pub async fn subscribe_to_notifications(&self) -> anyhow::Result<()> {
        if self.notifications_handler().await.is_connected() {
            return Ok(());
        }

        let notifications_url = self.notifications_url();

        let db = self.inner.db.read().await;

        let Some(access_token) = &db.access_token else {
            anyhow::bail!("Error getting access token");
        };

        let websocket_url = format!("{}/hub?access_token={}", notifications_url, access_token)
            .replace("https://", "wss://");

        drop(db);

        let mut nh = self.notifications_handler_mut().await;

        nh.connect(websocket_url)
            .await
            .err()
            .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
    }
}

struct LocalDecrypter {
    priv_key: Arc<rbw::locked::Keys>,
    org_keys: HashMap<String, Arc<rbw::locked::Keys>>,
}

impl rbw::db::Decrypter for LocalDecrypter {
    fn decrypt_field(
        &mut self,
        entry: Option<&rbw::db::Entry>,
        field: &str,
    ) -> rbw::error::Result<String> {
        let keys = match entry.and_then(|e| e.org_id.as_deref()) {
            Some(org_id) => self
                .org_keys
                .get(org_id)
                .ok_or_else(|| rbw::error::Error::UnavailableDbSessionParameters("org key"))?,
            None => &self.priv_key,
        };
        let entry_key = entry
            .and_then(|e| e.key.as_deref())
            .map(|ek| {
                let cs = rbw::cipherstring::CipherString::new(ek)?;
                Ok::<_, rbw::error::Error>(rbw::locked::Keys::new(
                    cs.decrypt_locked_symmetric(keys.as_ref())?,
                ))
            })
            .transpose()?;
        let cs = rbw::cipherstring::CipherString::new(field)?;
        let plaintext = cs.decrypt_symmetric(keys.as_ref(), entry_key.as_ref())?;
        String::from_utf8(plaintext).map_err(|e| rbw::error::Error::Utf8Error {
            source: e.utf8_error(),
        })
    }
}

struct LocalEncrypter {
    priv_key: Arc<rbw::locked::Keys>,
    org_keys: HashMap<String, Arc<rbw::locked::Keys>>,
}

impl rbw::db::Encrypter for LocalEncrypter {
    fn encrypt_field(
        &mut self,
        entry: Option<&rbw::db::Entry>,
        field: &str,
    ) -> rbw::error::Result<String> {
        let keys = match entry.and_then(|e| e.org_id.as_deref()) {
            Some(org_id) => self
                .org_keys
                .get(org_id)
                .ok_or_else(|| rbw::error::Error::UnavailableDbSessionParameters("org key"))?,
            None => &self.priv_key,
        };
        let cs =
            rbw::cipherstring::CipherString::encrypt_symmetric(keys.as_ref(), field.as_bytes())?;
        Ok(cs.to_string())
    }
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}
