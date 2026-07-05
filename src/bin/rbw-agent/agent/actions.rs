use std::future::Future;

use anyhow::Context as _;
use rbw::{
    actions::SessionParameters,
    db::{Db, EntryData},
    error::{Error, Result},
};
use sha2::Digest as _;

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

        let (
            access_token,
            refresh_token_new,
            (protected_key, protected_private_key, protected_org_keys, entries),
        ) = rbw::actions::sync(access_token, refresh_token)
            .await
            .context("failed to sync database from server")?;

        log::trace!("Sync operation finished");

        self.set_master_password_reprompt(&entries).await;

        log::trace!("Set master password reprompt");

        // And then update the local cached copy of the db
        {
            let mut db = self.inner.db.write().await;

            log::trace!("Opened cached db for write operation");

            db.update_access_token(access_token);
            db.update_refresh_token(refresh_token_new);

            db.protected_key = Some(protected_key);
            db.protected_private_key = Some(protected_private_key);
            db.protected_org_keys = protected_org_keys;
            db.entries = entries;

            db.save_async(&self.server_name(), self.email()?).await?;
        }

        log::trace!("Updated disk db");

        if let Err(e) = self.subscribe_to_notifications().await {
            eprintln!("failed to subscribe to notifications: {e}");
        }

        if let Some(sock) = sock {
            respond_ack(sock).await?;
        }

        Ok(())
    }

    async fn decrypt_cipher(
        &self,
        environment: &rbw::protocol::Environment,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        self.initialize_mpr().await;

        let Some(keys) = self.key(org_id).await else {
            return Err(anyhow::anyhow!(
                "failed to find decryption keys in in-memory state"
            ));
        };

        let entry_key = decrypt_entry_key(entry_key, keys.as_ref())?;

        self.maybe_reprompt_password(environment, cipherstring)
            .await?;

        let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
            .context("failed to parse encrypted secret")?;

        // BUG: This is sensible memory and should be handled more carefully (locked)
        let plaintext = String::from_utf8(
            cipherstring
                .decrypt_symmetric(keys.as_ref(), entry_key.as_ref())
                .context("failed to decrypt encrypted secret")?,
        )
        .context("failed to parse decrypted secret")?;

        Ok(plaintext)
    }

    pub async fn decrypt(
        &self,
        sock: &mut crate::sock::Sock,
        environment: &rbw::protocol::Environment,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let plaintext = self
            .decrypt_cipher(environment, cipherstring, entry_key, org_id)
            .await?;

        sock.send(&rbw::protocol::Response::Decrypt { plaintext })
            .await?;

        Ok(())
    }

    pub async fn encrypt(
        &self,
        sock: &mut crate::sock::Sock,
        plaintext: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let Some(keys) = self.key(org_id).await else {
            return Err(anyhow::anyhow!(
                "failed to find encryption keys in in-memory state"
            ));
        };

        let cipherstring =
            rbw::cipherstring::CipherString::encrypt_symmetric(keys.as_ref(), plaintext.as_bytes())
                .context("failed to encrypt plaintext secret")?;

        sock.send(&rbw::protocol::Response::Encrypt {
            cipherstring: cipherstring.to_string(),
        })
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

    async fn try_unlock(&self, password: &rbw::locked::Password) -> Result<()> {
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

                Ok(self.try_unlock(&password).await?)
            })
            .await
            .context("failed to unlock database")?;
        }

        Ok(())
    }

    async fn maybe_reprompt_password(
        &self,
        environment: &rbw::protocol::Environment,
        cipherstring: &str,
    ) -> anyhow::Result<()> {
        let mut sha256 = sha2::Sha256::new();
        sha256.update(cipherstring);
        let master_password_reprompt: [u8; 32] = sha256.finalize().into();

        if self
            .inner
            .master_password_reprompt
            .read()
            .await
            .contains(&master_password_reprompt)
        {
            log::trace!(
                "Requesting password reprompt for item {:#?}",
                master_password_reprompt
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );

            with_retry(|err| async move {
                let password = self
                    .get_password(
                        "Accessing this entry requires the master password",
                        &err,
                        environment,
                    )
                    .await?;

                Ok(self.try_unlock(&password).await?)
            })
            .await
            .context("failed to unlock database")?;

            log::trace!("Password correct, reprompt successful");
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

        let enc_pubkeys: Vec<(String, Option<String>, Option<String>)> = db
            .entries
            .iter()
            .filter_map(|e| {
                if let EntryData::SshKey {
                    public_key: Some(pubkey),
                    ..
                } = &e.data
                {
                    Some((pubkey.clone(), e.key.clone(), e.org_id.clone()))
                } else {
                    None
                }
            })
            .collect();

        drop(db);

        let mut pubkeys = vec![];

        for (e, entry_key, org_id) in enc_pubkeys {
            let pubkey = self
                .decrypt_cipher(&environment, &e, entry_key.as_deref(), org_id.as_deref())
                .await?;
            pubkeys.push(pubkey);
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

        // Collect all ssh keys that are Some()
        let keys: Vec<(&String, &String, &Option<String>, &Option<String>)> = db
            .entries
            .iter()
            .filter_map(|e| match &e.data {
                rbw::db::EntryData::SshKey {
                    private_key,
                    public_key,
                    ..
                } => match (public_key, private_key) {
                    (Some(public), Some(private)) => Some((public, private, &e.key, &e.org_id)),
                    _ => None,
                },
                _ => None,
            })
            .collect();

        for (public, private, key, org_id) in keys {
            let pub_plain = self
                .decrypt_cipher(&environment, public, key.as_deref(), org_id.as_deref())
                .await?;

            let pub_bytes = ssh_agent_lib::ssh_key::PublicKey::from_openssh(&pub_plain)?.to_bytes();

            if pub_bytes != request_bytes {
                continue;
            }

            let priv_plain = self
                .decrypt_cipher(&environment, private, key.as_deref(), org_id.as_deref())
                .await?;

            return ssh_agent_lib::ssh_key::PrivateKey::from_openssh(priv_plain)
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

fn decrypt_entry_key(
    entry_key: Option<&str>,
    keys: &rbw::locked::Keys,
) -> anyhow::Result<Option<rbw::locked::Keys>> {
    entry_key
        .map(|ek| {
            let cs = rbw::cipherstring::CipherString::new(ek)
                .context("failed to parse individual item encryption key")?;
            Ok(rbw::locked::Keys::new(
                cs.decrypt_locked_symmetric(keys)
                    .context("failed to decrypt individual item encryption key")?,
            ))
        })
        .transpose()
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}
