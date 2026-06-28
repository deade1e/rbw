use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use rand::distr::SampleString as _;
use sha2::Digest as _;
use tokio::sync::mpsc::{channel, Sender};

use crate::{
    actions::CryptoParameters,
    api::{
        entry_data_type, CiphersPostReq, CiphersPutReq, ConnectErrorRes, ConnectRefreshTokenRes,
        ConnectTokenAuth, ConnectTokenReq, ConnectTokenRes, FoldersRes, FoldersResData,
        PreloginRes, SyncRes, TwoFactorProviderType,
    },
    db::{Entry, EntryData},
    error::{Error, Result},
    json::{DeserializeJsonWithPath as _, DeserializeJsonWithPathAsync as _},
};

// Used for the Bitwarden-Client-Name header. Accepted values:
// https://github.com/bitwarden/server/blob/main/src/Core/Enums/BitwardenClient.cs
const BITWARDEN_CLIENT: &str = "cli";

// DeviceType.LinuxDesktop, as per Bitwarden API device types.
const DEVICE_TYPE: u8 = 8;

enum ClientRequest<'a> {
    Prelogin(&'a str),
    ConnectToken(ConnectTokenReq<'a>),
    Login(ConnectTokenReq<'a>, &'a str),
    SendEmailLogin(&'a str, &'a str, &'a str),
    Sync(&'a str),
    ExchangeRefreshToken(&'a str),
    Add(&'a str, CiphersPostReq),
    Edit(&'a str, &'a str, CiphersPutReq),
    Remove(&'a str, &'a str),
    Folders(&'a str),
    CreateFolder(&'a str, &'a str),
}

impl<'a> ClientRequest<'a> {
    async fn req(self, client: &Client) -> Result<reqwest::Response> {
        let http_client = client.reqwest_client().await?;

        let rb = match self {
            Self::Prelogin(email) => http_client
                .post(client.identity_url("/accounts/prelogin"))
                .json(&serde_json::json!({"email": email})),
            Self::ConnectToken(r) => http_client
                .post(client.identity_url("/connect/token"))
                .form(&r),
            Self::Login(r, email) => http_client
                .post(client.identity_url("/connect/token"))
                .form(&r)
                .header("auth-email", crate::base64::encode_url_safe_no_pad(email)),
            Self::SendEmailLogin(email, device_identifier, sso_email_2fa_session_token) => {
                http_client
                    .post(client.api_url("/two-factor/send-email-login"))
                    .json(&serde_json::json!({
                        "email": email,
                        "DeviceIdentifier": device_identifier,
                        "SsoEmail2faSessionToken": sso_email_2fa_session_token
                    }))
                    .header("auth-email", crate::base64::encode_url_safe_no_pad(email))
            }
            Self::Sync(access_token) => http_client
                .get(client.api_url("/sync"))
                .header("Authorization", format!("Bearer {access_token}"))
                // This is necessary for vaultwarden to include the ssh keys in the response
                .header("Bitwarden-Client-Version", "2024.12.0"),
            Self::ExchangeRefreshToken(refresh_token) => http_client
                .post(client.identity_url("/connect/token"))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", "cli"),
                    ("refresh_token", refresh_token),
                ]),
            Self::Add(access_token, r) => http_client
                .post(client.api_url("/ciphers"))
                .header("Authorization", format!("Bearer {access_token}"))
                .json(&r),
            Self::Edit(access_token, id, r) => http_client
                .put(client.api_url(&format!("/ciphers/{id}")))
                .header("Authorization", format!("Bearer {access_token}"))
                .json(&r),
            Self::Remove(access_token, id) => http_client
                .delete(client.api_url(&format!("/ciphers/{id}")))
                .header("Authorization", format!("Bearer {access_token}")),
            Self::Folders(access_token) => http_client
                .get(client.api_url("/folders"))
                .header("Authorization", format!("Bearer {access_token}")),
            Self::CreateFolder(access_token, name) => http_client
                .post(client.api_url("/folders"))
                .header("Authorization", format!("Bearer {access_token}"))
                .json(&serde_json::json!({"name": name})),
        };

        Ok(rb.send().await?)
    }
}

async fn find_free_port(bottom: u16, top: u16) -> Result<u16> {
    for port in bottom..top {
        if tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }

    Err(Error::FailedToFindFreePort {
        range: format!("({bottom}..{top})"),
    })
}

#[derive(Clone)]
struct SSOHandlerState {
    state: String,
    sender: Sender<Result<String>>,
}

async fn start_sso_callback_server(
    listener: tokio::net::TcpListener,
    state: &str,
) -> Result<String> {
    let (shut_tx, mut shut_rx) = channel(1);
    let (tx, mut rx) = channel(1);

    let sso_handler_state = Arc::new(SSOHandlerState {
        state: state.to_string(),
        sender: shut_tx,
    });

    let app = axum::Router::new()
        .route("/", axum::routing::get(handle_sso_callback))
        .with_state(sso_handler_state);

    axum::serve(listener, app)
        .with_graceful_shutdown(
            async move { tx.send(shut_rx.recv().await.unwrap()).await.unwrap() },
        )
        .await
        .map_err(|e| Error::FailedToProcessSSOCallback { msg: e.to_string() })?;

    rx.recv().await.unwrap()
}

async fn handle_sso_callback(
    axum::extract::State(state): axum::extract::State<Arc<SSOHandlerState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> axum::http::Response<String> {
    match sso_query_code(&params, state.state.as_str()) {
        Ok(sso_code) => {
            state.sender.send(Ok(sso_code)).await.unwrap();

            axum::http::Response::builder()
                .status(axum::http::StatusCode::OK)
                .body(
                    "<html><head><title>Success | rbw</title></head><body> \
                  <h1>Successfully authenticated with rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>"
                        .to_string(),
                )
                .unwrap()
        }
        Err(e) => {
            state.sender.send(Err(e)).await.unwrap();

            axum::http::Response::builder()
                .status(axum::http::StatusCode::BAD_REQUEST)
                .body(
                    "<html><head><title>Failed | rbw</title></head><body> \
                  <h1>Something went wrong logging into the rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>"
                        .to_string(),
                )
                .unwrap()
        }
    }
}

fn sso_query_code(params: &HashMap<String, String>, state: &str) -> Result<String> {
    let sso_code = params
        .get("code")
        .ok_or(Error::FailedToProcessSSOCallback {
            msg: "Could not obtain code from the URL".to_string(),
        })?;

    let received_state = params
        .get("state")
        .ok_or(Error::FailedToProcessSSOCallback {
            msg: "Could not obtain state from the URL".to_string(),
        })?;

    if received_state.split("_identifier=").next().unwrap() != state {
        return Err(Error::FailedToProcessSSOCallback {
            msg: format!(
                "SSO callback states do not match, sent: {state}, received: {received_state}"
            ),
        });
    }

    Ok(sso_code.clone())
}

#[derive(Debug)]
pub struct Client {
    base_url: String,
    identity_url: String,
    ui_url: String,
    client_cert_path: Option<PathBuf>,
}

impl Client {
    pub fn new(
        base_url: &str,
        identity_url: &str,
        ui_url: &str,
        client_cert_path: Option<&Path>,
    ) -> Self {
        Self {
            base_url: base_url.to_string(),
            identity_url: identity_url.to_string(),
            ui_url: ui_url.to_string(),
            client_cert_path: client_cert_path.map(Path::to_path_buf),
        }
    }

    pub(super) async fn reqwest_client(&self) -> Result<reqwest::Client> {
        let mut default_headers = axum::http::HeaderMap::new();
        default_headers.insert(
            "Bitwarden-Client-Name",
            axum::http::HeaderValue::from_static(BITWARDEN_CLIENT),
        );
        default_headers.insert(
            "Bitwarden-Client-Version",
            axum::http::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        default_headers.append(
            "Device-Type",
            // unwrap is safe here because DEVICE_TYPE is a number and digits
            // are valid ASCII
            axum::http::HeaderValue::from_str(&DEVICE_TYPE.to_string()).unwrap(),
        );
        let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        if let Some(client_cert_path) = self.client_cert_path.as_ref() {
            let buf =
                tokio::fs::read(client_cert_path)
                    .await
                    .map_err(|e| Error::LoadClientCert {
                        source: e,
                        file: client_cert_path.clone(),
                    })?;
            let pem = reqwest::Identity::from_pem(&buf)
                .map_err(|e| Error::CreateReqwestClient { source: e })?;
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .identity(pem)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        } else {
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        }
    }

    pub async fn prelogin(&self, email: &str) -> Result<CryptoParameters> {
        let res: PreloginRes = ClientRequest::Prelogin(email)
            .req(self)
            .await?
            .json_with_path()
            .await?;

        Ok(CryptoParameters {
            kdf: res.kdf,
            iterations: res.kdf_iterations,
            memory: res.kdf_memory,
            parallelism: res.kdf_parallelism,
        })
    }

    async fn check_connect_token_res(res: reqwest::Response) -> Result<reqwest::Response> {
        match res.status() {
            reqwest::StatusCode::OK => Ok(res),
            status => match res.text().await {
                Ok(body) => match body.clone().json_with_path::<ConnectErrorRes>() {
                    Ok(err) => match err.try_into() {
                        Ok(e) => Err(e),
                        Err(err) => {
                            log::warn!("unexpected error received during login: {err:?}");
                            Err(Error::RequestFailed {
                                status: status.as_u16(),
                            })
                        }
                    },
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed {
                            status: status.as_u16(),
                        })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed {
                        status: status.as_u16(),
                    })
                }
            },
        }
    }

    pub async fn register(
        &self,
        email: &str,
        device_id: &str,
        apikey: &crate::locked::ApiKey,
    ) -> Result<()> {
        let connect_req = ConnectTokenReq {
            auth: ConnectTokenAuth::ClientCredentials {
                username: email,
                client_secret: std::str::from_utf8(apikey.client_secret()).unwrap(),
            },
            grant_type: "client_credentials",
            scope: "api",
            // XXX unwraps here are not necessarily safe
            client_id: std::str::from_utf8(apikey.client_id()).unwrap(),
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id,
            device_name: "rbw",
            device_push_token: "",
            two_factor_token: None,
            two_factor_provider: None,
        };

        let res = ClientRequest::ConnectToken(connect_req).req(self).await?;

        Self::check_connect_token_res(res).await?;

        Ok(())
    }

    pub async fn login(
        &self,
        email: &str,
        sso_id: Option<&str>,
        device_id: &str,
        password_hash: &crate::locked::PasswordHash,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<TwoFactorProviderType>,
    ) -> Result<(String, String, String)> {
        let (auth, grant_type, scope) = match sso_id {
            Some(sso_id) => {
                let (sso_code, sso_code_verifier, callback_url) =
                    self.obtain_sso_code(sso_id).await?;
                (
                    ConnectTokenAuth::AuthCode {
                        code: &sso_code.clone(),
                        code_verifier: &sso_code_verifier.clone(),
                        redirect_uri: &callback_url.clone(),
                    },
                    "authorization_code",
                    "api offline_access",
                )
            }
            None => (
                ConnectTokenAuth::Password {
                    username: email,
                    password: &crate::base64::encode(password_hash.hash()),
                },
                "password",
                "api offline_access",
            ),
        };

        let connect_req = ConnectTokenReq {
            auth,
            grant_type,
            scope,
            client_id: "cli",
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id,
            device_name: "rbw",
            device_push_token: "",
            two_factor_token,
            two_factor_provider: two_factor_provider.map(|ty| ty as u32),
        };

        let res = ClientRequest::Login(connect_req, email).req(self).await?;

        let res = Self::check_connect_token_res(res).await?;

        let connect_res: ConnectTokenRes = res.json_with_path().await?;

        Ok((
            connect_res.access_token,
            connect_res.refresh_token,
            connect_res.key,
        ))
    }

    pub async fn send_email_login(
        &self,
        email: &str,
        device_id: &str,
        sso_email_2fa_session_token: &str,
    ) -> Result<()> {
        let res = ClientRequest::SendEmailLogin(email, device_id, sso_email_2fa_session_token)
            .req(self)
            .await?;

        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            log::warn!("{code}: {:?}", res.text().await);
            Err(Error::RequestFailed { status: code })
        }
    }

    async fn obtain_sso_code(&self, sso_id: &str) -> Result<(String, String, String)> {
        let state = rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);
        let sso_code_verifier = rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);

        let mut hasher = sha2::Sha256::new();
        hasher.update(&sso_code_verifier);
        let code_challenge = crate::base64::encode_url_safe_no_pad(hasher.finalize());

        let port = find_free_port(8065, 8070).await?;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| Error::CreateSSOCallbackServer { err: e })?;

        let callback_server = start_sso_callback_server(listener, state.as_str());

        let callback_url = "http://localhost:".to_string() + port.to_string().as_str();

        open::that(
            self.ui_url.clone()
                + "/#/sso?clientId="
                + "cli"
                + "&redirectUri="
                + urlencoding::encode(callback_url.as_str())
                    .into_owned()
                    .as_str()
                + "&state="
                + state.as_str()
                + "&codeChallenge="
                + code_challenge.as_str()
                + "&identifier="
                + sso_id,
        )
        .map_err(|e| Error::FailedToOpenWebBrowser { err: e })?;
        // TODO: probably it'd be better to display the URL in the console if the automatic
        // open operation fails, instead of failing the whole process? E.g. docker container
        // case

        let sso_code = callback_server.await?;

        Ok((sso_code, sso_code_verifier, callback_url))
    }

    pub async fn sync(
        &self,
        access_token: &str,
    ) -> Result<(String, String, HashMap<String, String>, Vec<Entry>)> {
        let res = ClientRequest::Sync(access_token)
            .req(self)
            .await?
            .error_for_status()?;

        let sync_res: SyncRes = res.json_with_path().await?;

        let ciphers: Vec<Entry> = sync_res
            .ciphers
            .into_iter()
            .filter_map(|cipher| match cipher.into_entry(&sync_res.folders) {
                Ok(e) => Some(Ok(e)),
                Err(Error::DeletedEntry) => None, // If deleted entry, simply skip it
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>>>()?;

        let org_keys = sync_res
            .profile
            .organizations
            .iter()
            .map(|org| (org.id.clone(), org.key.clone()))
            .collect();

        Ok((
            sync_res.profile.key,
            sync_res.profile.private_key,
            org_keys,
            ciphers,
        ))
    }

    pub async fn add(
        &self,
        access_token: &str,
        name: &str,
        data: &EntryData,
        notes: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<()> {
        let req = CiphersPostReq {
            ty: entry_data_type(data),
            folder_id: folder_id.map(|f| f.to_string()),
            name: name.to_string(),
            notes: notes.map(|n| n.to_string()),
            data: data.clone().into(),
        };

        ClientRequest::Add(access_token, req)
            .req(self)
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn edit(&self, access_token: &str, entry: &Entry) -> Result<()> {
        let req: CiphersPutReq = entry.clone().into();

        ClientRequest::Edit(access_token, &entry.id, req)
            .req(self)
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn remove(&self, access_token: &str, id: &str) -> Result<()> {
        ClientRequest::Remove(access_token, id)
            .req(self)
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn folders(&self, access_token: &str) -> Result<Vec<(String, String)>> {
        let res = ClientRequest::Folders(access_token)
            .req(self)
            .await?
            .error_for_status()?;

        let folders_res: FoldersRes = res.json_with_path().await?;

        Ok(folders_res
            .data
            .iter()
            .map(|folder| (folder.id.clone(), folder.name.clone()))
            .collect())
    }

    pub async fn create_folder(&self, access_token: &str, name: &str) -> Result<String> {
        let res = ClientRequest::CreateFolder(access_token, name)
            .req(self)
            .await?
            .error_for_status()?;

        let folders_res: FoldersResData = res.json_with_path().await?;

        Ok(folders_res.id)
    }

    pub async fn exchange_refresh_token(&self, refresh_token: &str) -> Result<String> {
        let res = ClientRequest::ExchangeRefreshToken(refresh_token)
            .req(self)
            .await?;
        let connect_res: ConnectRefreshTokenRes = res.json_with_path().await?;
        Ok(connect_res.access_token)
    }

    pub async fn exchange_refresh_token_async(&self, refresh_token: &str) -> Result<String> {
        let res = ClientRequest::ExchangeRefreshToken(refresh_token)
            .req(self)
            .await?;
        let connect_res: ConnectRefreshTokenRes = res.json_with_path().await?;
        Ok(connect_res.access_token)
    }

    pub(super) fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub(super) fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}
