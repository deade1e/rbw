use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::Context as _;
use rbw::{
    db::Db,
    error::{Error, Result},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Mutex, Notify, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{sleep_until, Instant},
};

use crate::notifications::NotificationsHandler;

mod actions;
pub mod ssh_agent;

struct InnerAgent {
    priv_key: RwLock<Option<Arc<rbw::locked::Keys>>>,
    org_keys: RwLock<Option<HashMap<String, Arc<rbw::locked::Keys>>>>,
    notifications_handler: RwLock<NotificationsHandler>,
    pub lock_deadline: Mutex<Option<Instant>>,
    pub sync_deadline: Mutex<Option<Instant>>,
    pub run_notify: Notify,
    config: rbw::config::Config,
    pub db: RwLock<Db>,
    pub decrypted_entries: RwLock<Option<Vec<rbw::db::Entry>>>,

    // this is stored here specifically for the use of the ssh agent, because
    // requests made to the ssh agent don't include an environment, and so we
    // can't properly initialize the pinentry process. we work around this by
    // just reusing the last environment we saw being sent to the main agent
    // (there should be at least one in most cases because you need to start
    // the rbw agent in order to make it start serving on the ssh agent
    // socket, and that initial request should come with an environment).
    //
    // we should not use this for any requests on the main agent, those
    // should all send their own environment over.
    pub last_environment: RwLock<rbw::protocol::Environment>,

    #[cfg(feature = "clipboard")]
    pub clipboard: Mutex<Option<arboard::Clipboard>>,
}

#[derive(Clone)]
pub struct Agent {
    inner: Arc<InnerAgent>,
}

impl Agent {
    pub async fn new(config: rbw::config::Config) -> Self {
        let notifications_handler = crate::notifications::NotificationsHandler::new();

        // TODO: ugly
        let mut sync_deadline: Option<Instant> = None;
        let sync_timeout_duration = std::time::Duration::from_secs(config.sync_interval);

        if sync_timeout_duration > std::time::Duration::ZERO {
            sync_deadline = Some(Instant::now() + sync_timeout_duration);
        }

        let db = match &config.email {
            Some(email) => Db::load_async(&config.server_name(), email)
                .await
                .unwrap_or_else(|_| Db::new()),
            None => Db::new(),
        };

        let state = Self {
            inner: Arc::new(InnerAgent {
                priv_key: RwLock::new(None),
                org_keys: RwLock::new(None),
                notifications_handler: RwLock::new(notifications_handler),
                lock_deadline: Mutex::new(None),
                sync_deadline: Mutex::new(sync_deadline),
                run_notify: Notify::new(),
                config,
                db: RwLock::new(db),
                decrypted_entries: RwLock::new(None),
                last_environment: RwLock::new(rbw::protocol::Environment::default()),

                #[cfg(feature = "clipboard")]
                clipboard: Mutex::new(
                    arboard::Clipboard::new()
                        .inspect_err(|e| {
                            log::warn!("couldn't create clipboard context: {e}");
                        })
                        .ok(),
                ),
            }),
        };

        state
    }

    pub async fn set_keys(
        &self,
        priv_key: rbw::locked::Keys,
        org_keys: HashMap<String, rbw::locked::Keys>,
    ) {
        let mut priv_key_guard = self.inner.priv_key.write().await;
        let mut org_keys_guard = self.inner.org_keys.write().await;

        *priv_key_guard = Some(Arc::new(priv_key));

        let org_keys: HashMap<String, Arc<rbw::locked::Keys>> = org_keys
            .into_iter()
            .map(|(k, v)| (k, Arc::new(v)))
            .collect();

        *org_keys_guard = Some(org_keys);
    }

    pub async fn needs_unlock(&self) -> bool {
        self.inner.priv_key.read().await.is_none() || self.inner.org_keys.read().await.is_none()
    }

    pub async fn reset_lock_timeout(&self) {
        *self.inner.lock_deadline.lock().await =
            Some(Instant::now() + Duration::from_secs(self.inner.config.lock_timeout));
        self.inner.run_notify.notify_one();
    }

    pub async fn notifications_handler(&self) -> RwLockReadGuard<'_, NotificationsHandler> {
        self.inner.notifications_handler.read().await
    }

    pub async fn notifications_handler_mut(&self) -> RwLockWriteGuard<'_, NotificationsHandler> {
        self.inner.notifications_handler.write().await
    }

    pub async fn clear(&self) {
        {
            let mut priv_key_guard = self.inner.priv_key.write().await;
            let mut org_keys_guard = self.inner.org_keys.write().await;
            let mut decrypted_entries_guard = self.inner.decrypted_entries.write().await;

            *priv_key_guard = None;
            *org_keys_guard = None;
            *decrypted_entries_guard = None;
        }

        *self.inner.lock_deadline.lock().await = None;
    }

    pub async fn set_sync_timeout(&self) {
        *self.inner.sync_deadline.lock().await =
            Some(Instant::now() + Duration::from_secs(self.inner.config.sync_interval));
        // self.inner
        //     .sync_timeout
        //     .set(self.inner.sync_timeout_duration);
    }

    pub async fn last_environment(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, rbw::protocol::Environment> {
        self.inner.last_environment.read().await
    }

    pub async fn set_last_environment(&self, environment: rbw::protocol::Environment) {
        *self.inner.last_environment.write().await = environment;
    }

    pub fn email(&self) -> Result<&str> {
        self.inner
            .config
            .email
            .as_deref()
            .ok_or_else(|| Error::ConfigMissingEmail)
    }

    pub fn base_url(&self) -> String {
        self.inner.config.base_url()
    }

    pub fn config_pinentry(&self) -> &str {
        &self.inner.config.pinentry
    }

    pub fn notifications_url(&self) -> String {
        self.inner.config.notifications_url()
    }

    pub fn server_name(&self) -> String {
        self.inner.config.server_name()
    }

    #[cfg(feature = "clipboard")]
    pub async fn clipboard_mut(&self) -> tokio::sync::MutexGuard<'_, Option<arboard::Clipboard>> {
        self.inner.clipboard.lock().await
    }

    pub fn confirm_ssh(&self) -> bool {
        self.inner.config.confirm_ssh.is_some_and(|o| o)
    }
    async fn sleep_until_deadline(deadline: Option<Instant>) {
        match deadline {
            Some(d) => sleep_until(d).await,
            None => std::future::pending().await,
        }
    }

    async fn on_notification(&self, message: crate::notifications::Message) {
        match message {
            crate::notifications::Message::Logout => {
                log::debug!("Received Logout Message via notification channel");
                self.clear().await;
            }
            crate::notifications::Message::Sync => {
                log::debug!("Received Sync Message via notification channel");
                self.set_sync_timeout().await;

                if let Err(e) = self.sync(None).await {
                    eprintln!("failed to sync: {e:#}");
                }
            }
            crate::notifications::Message::Disconnected => {
                log::warn!("Notifications websocket disconnected");
            }
        }
    }

    async fn on_connection(&self, stream: UnixStream) {
        let mut sock = crate::sock::Sock::new(stream);

        let self_ref = self.clone();

        // TODO: Check if does it make sense to handle this in another task
        tokio::spawn(async move {
            let res = self_ref.handle_request(&mut sock).await;
            if let Err(e) = res {
                sock.send(&rbw::protocol::Response::Error {
                    error: format!("{e:#}"),
                })
                .await
                .expect("failed to send error response to client");
            }
        });
    }

    pub async fn run(self, listener: UnixListener) -> anyhow::Result<()> {
        let mut nchannel = self.notifications_handler().await.get_channel();

        match self.subscribe_to_notifications().await {
            Ok(_) => {
                log::debug!("Successfully subscribed to notifications");
            }
            Err(e) => {
                log::warn!("Failed to subscribe to notifications: {e}");
            }
        };

        loop {
            let lock_deadline = *self.inner.lock_deadline.lock().await;
            let sync_deadline = *self.inner.sync_deadline.lock().await;

            tokio::select! {
                message = nchannel.recv() => {
                    let message = message?;
                    self.on_notification(message).await;
                },
                // TODO: The client does like a hundred connections to do basic things. Maybe it
                // makes sense to create more comprehensive opcodes.
                res = listener.accept() => {
                    let res = res.context("failed to accept incoming connection")?;

                    self.on_connection(res.0).await;
                },
                _ = self.inner.run_notify.notified() => {
                    log::trace!("Waking run loop to re-evaluate deadlines");
                },
                _ = Self::sleep_until_deadline(lock_deadline) => {
                    log::trace!("Lock deadline reached. Locking the db");
                    self.clear().await;
                },
                _ = Self::sleep_until_deadline(sync_deadline) => {
                    //let state = self.state.clone();

                    log::trace!("Sync deadline reached. Syncing the db");
                    self.set_sync_timeout().await;

                    // this could fail if we aren't logged in, but we
                    // don't care about that
                    if let Err(e) = self.sync(None).await {
                        eprintln!("failed to sync: {e:#}");
                    }

                }
            }
        }
    }

    async fn handle_request(&self, sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
        let req = match sock.recv().await? {
            Ok(msg) => msg,
            Err(error) => {
                sock.send(&rbw::protocol::Response::Error { error }).await?;
                return Ok(());
            }
        };

        let (action, environment) = req.into_parts();

        log::trace!("Start of action: {:?}", &action);

        match &action {
            rbw::protocol::Action::Register => {
                self.register(sock, &environment).await?;
            }
            rbw::protocol::Action::Login => {
                self.login(sock, &environment).await?;
            }
            rbw::protocol::Action::Unlock => {
                self.unlock(sock, &environment).await?;
            }
            rbw::protocol::Action::CheckLock => {
                self.check_lock(sock).await?;
            }
            rbw::protocol::Action::Lock => {
                self.lock(sock).await?;
            }
            rbw::protocol::Action::Sync => {
                self.sync(Some(sock)).await?;
            }
            rbw::protocol::Action::Get(find) => {
                self.get(sock, &environment, find).await?;
            }
            rbw::protocol::Action::Search { term, folder } => {
                self.search(sock, &environment, term, folder.as_deref())
                    .await?;
            }
            rbw::protocol::Action::Code(find) => {
                self.code(sock, &environment, find).await?;
            }
            rbw::protocol::Action::Add(add) => {
                self.add(sock, &environment, add).await?;
            }
            rbw::protocol::Action::Edit {
                find,
                password,
                notes,
            } => {
                self.edit(
                    sock,
                    &environment,
                    find,
                    password.as_deref(),
                    notes.as_deref(),
                )
                .await?;
            }
            rbw::protocol::Action::Remove(find) => {
                self.remove(sock, &environment, find).await?;
            }
            rbw::protocol::Action::History(find) => {
                self.history(sock, &environment, find).await?;
            }
            rbw::protocol::Action::ClipboardStore { text } => {
                self.clipboard_store(sock, text).await?;
            }
            // TODO: It's better to handle the closing more gracefully
            rbw::protocol::Action::Quit => std::process::exit(0),
            rbw::protocol::Action::Version => {
                sock.send(&rbw::protocol::Response::Version {
                    version: rbw::protocol::VERSION,
                })
                .await?;
            }
        }

        log::trace!("End of action: {:?}", &action);

        self.set_last_environment(environment).await;

        // Reset lock timeout on these request types
        match &action {
            rbw::protocol::Action::Register
            | rbw::protocol::Action::Login
            | rbw::protocol::Action::Unlock
            | rbw::protocol::Action::Get(_)
            | rbw::protocol::Action::Search { .. }
            | rbw::protocol::Action::Code(_)
            | rbw::protocol::Action::Add(_)
            | rbw::protocol::Action::Edit { .. }
            | rbw::protocol::Action::Remove(_)
            | rbw::protocol::Action::History(_)
            | rbw::protocol::Action::ClipboardStore { .. } => self.reset_lock_timeout().await,
            _ => {}
        }

        Ok(())
    }
}
