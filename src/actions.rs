use crate::{db::Entry, prelude::*};

pub async fn register(email: &str, apikey: crate::locked::ApiKey) -> Result<()> {
    let (client, config) = api_client_async().await?;

    client
        .register(email, &crate::config::device_id(&config).await?, &apikey)
        .await?;

    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CryptoParameters {
    pub kdf: crate::api::KdfType,
    pub iterations: u32,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}

pub struct SessionParameters {
    pub access_token: String,
    pub refresh_token: String,
    pub crypto_params: CryptoParameters,
    pub protected_key: String,
}

pub async fn login(
    email: &str,
    password: &crate::locked::Password,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<crate::api::TwoFactorProviderType>,
) -> Result<SessionParameters> {
    let (client, config) = api_client_async().await?;
    let crypto_params = client.prelogin(email).await?;

    let identity = crate::identity::Identity::new(email, password, &crypto_params)?;
    let (access_token, refresh_token, protected_key) = client
        .login(
            email,
            config.sso_id.as_deref(),
            &crate::config::device_id(&config).await?,
            &identity.master_password_hash,
            two_factor_token,
            two_factor_provider,
        )
        .await?;

    Ok(SessionParameters {
        access_token,
        refresh_token,
        crypto_params,
        protected_key,
    })
}

pub async fn send_two_factor_email(email: &str, sso_email_2fa_session_token: &str) -> Result<()> {
    let (client, config) = api_client_async().await?;
    client
        .send_email_login(
            email,
            &crate::config::device_id(&config).await?,
            sso_email_2fa_session_token,
        )
        .await
}

pub fn unlock<S: std::hash::BuildHasher>(
    email: &str,
    password: &crate::locked::Password,
    crypto_params: &CryptoParameters,
    protected_key: &str,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let identity = crate::identity::Identity::new(email, password, crypto_params)?;

    let protected_key = crate::cipherstring::CipherString::new(protected_key)?;
    let key = match protected_key.decrypt_locked_symmetric(&identity.keys) {
        Ok(master_keys) => crate::locked::Keys::new(master_keys),
        Err(Error::InvalidMac) => {
            return Err(Error::IncorrectPassword {
                message: "Password is incorrect. Try again.".to_string(),
            })
        }
        Err(e) => return Err(e),
    };

    let protected_private_key = crate::cipherstring::CipherString::new(protected_private_key)?;
    let private_key = match protected_private_key.decrypt_locked_symmetric(&key) {
        Ok(private_key) => crate::locked::PrivateKey::new(private_key),
        Err(e) => return Err(e),
    };

    let mut org_keys = std::collections::HashMap::new();
    for (org_id, protected_org_key) in protected_org_keys {
        let protected_org_key = crate::cipherstring::CipherString::new(protected_org_key)?;
        let org_key = match protected_org_key.decrypt_locked_asymmetric(&private_key) {
            Ok(org_key) => crate::locked::Keys::new(org_key),
            Err(e) => return Err(e),
        };
        org_keys.insert(org_id.clone(), org_key);
    }

    Ok((key, org_keys))
}

// TODO: This return type could be a struct, like SyncCredentials?
pub async fn sync(
    access_token: &str,
    refresh_token: &str,
) -> Result<(
    Option<String>,
    (
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
    ),
)> {
    with_exchange_refresh_token_async(access_token, refresh_token, |token| async move {
        sync_once(&token).await
    })
    .await
}

async fn sync_once(
    access_token: &str,
) -> Result<(
    String,
    String,
    std::collections::HashMap<String, String>,
    Vec<crate::db::Entry>,
)> {
    let (client, _) = api_client_async().await?;
    client.sync(access_token).await
}

pub async fn add(
    access_token: &str,
    refresh_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token_async(access_token, refresh_token, |token| async move {
        add_once(&token, name, data, notes, folder_id).await
    })
    .await
}

async fn add_once(
    access_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<()> {
    let (client, _) = api_client_async().await?;
    client
        .add(access_token, name, data, notes, folder_id)
        .await?;
    Ok(())
}

async fn edit_once(access_token: &str, entry: &crate::db::Entry) -> Result<()> {
    let (client, _) = api_client_async().await?;
    client.edit(access_token, entry).await
}

pub async fn edit(
    access_token: &str,
    refresh_token: &str,
    entry: &Entry,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token_async(access_token, refresh_token, |token| async move {
        edit_once(&token, entry).await
    })
    .await
}

pub async fn remove(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token_async(access_token, refresh_token, |token| async move {
        remove_once(&token, id).await
    })
    .await
}

async fn remove_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client_async().await?;
    client.remove(access_token, id).await?;
    Ok(())
}

pub async fn list_folders(
    access_token: &str,
    refresh_token: &str,
) -> Result<(Option<String>, Vec<(String, String)>)> {
    with_exchange_refresh_token_async(access_token, refresh_token, |token| async move {
        list_folders_once(&token).await
    })
    .await
}

async fn list_folders_once(access_token: &str) -> Result<Vec<(String, String)>> {
    let (client, _) = api_client_async().await?;
    client.folders(access_token).await
}

pub async fn create_folder(
    access_token: &str,
    refresh_token: &str,
    name: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token_async(access_token, refresh_token, |token| async move {
        create_folder_once(&token, name).await
    })
    .await
}

async fn create_folder_once(access_token: &str, name: &str) -> Result<String> {
    let (client, _) = api_client_async().await?;
    client.create_folder(access_token, name).await
}

async fn with_exchange_refresh_token_async<F, Fut, T>(
    access_token: &str,
    refresh_token: &str,
    mut f: F,
) -> Result<(Option<String>, T)>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    match f(access_token.to_string()).await {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token = exchange_refresh_token_async(refresh_token).await?;
            let t = f(access_token.clone()).await?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

async fn exchange_refresh_token_async(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client_async().await?;
    client.exchange_refresh_token_async(refresh_token).await
}

async fn api_client_async() -> Result<(crate::api::client::Client, crate::config::Config)> {
    let config = crate::config::Config::load()?;
    let client = crate::api::client::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}
