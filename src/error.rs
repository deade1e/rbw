use std::str::Utf8Error;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("email address not set")]
    ConfigMissingEmail,

    #[error("failed to create block mode decryptor")]
    CreateBlockMode { source: aes::cipher::InvalidLength },

    #[error("failed to create block mode decryptor")]
    CreateHmac { source: aes::cipher::InvalidLength },

    #[error("failed to create directory at {}", .file.display())]
    CreateDirectory {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to create reqwest client")]
    CreateReqwestClient { source: reqwest::Error },

    #[error("failed to create sso callback server: {err}")]
    CreateSSOCallbackServer { err: std::io::Error },

    #[error("failed to decrypt")]
    Decrypt { source: block_padding::UnpadError },

    #[error("failed to find data directory")]
    FailedToFindDataDirectory,

    #[error("failed to find free port in {range}")]
    FailedToFindFreePort { range: String },

    #[error("failed to parse pinentry output ({out:?})")]
    FailedToParsePinentry { out: String },

    #[error("failed to process sso callback ({msg})")]
    FailedToProcessSSOCallback { msg: String },

    #[error("failed to open web browser: {err}")]
    FailedToOpenWebBrowser { err: std::io::Error },

    #[error("failed to read from stdin: {err}")]
    FailedToReadFromStdin { err: std::io::Error },

    #[error(
        "failed to run editor {}: {err}",
        .editor.to_string_lossy(),
    )]
    FailedToFindEditor {
        editor: std::path::PathBuf,
        err: std::io::Error,
    },

    #[error(
        "failed to run editor {} {}: {res:?}",
        .editor.to_string_lossy(),
        .args.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ")
    )]
    FailedToRunEditor {
        editor: std::path::PathBuf,
        args: Vec<std::ffi::OsString>,
        res: std::process::ExitStatus,
    },

    #[error("failed to expand with hkdf")]
    HkdfExpand,

    #[error("incorrect api key")]
    IncorrectApiKey,

    #[error("{message}")]
    IncorrectPassword { message: String },

    #[error("invalid base64")]
    InvalidBase64 { source: base64::DecodeError },

    #[error("invalid cipherstring: {reason}")]
    InvalidCipherString { reason: String },

    #[error(
        "invalid value for ${var}: {}",
        .editor.to_string_lossy()
    )]
    InvalidEditor {
        var: String,
        editor: std::ffi::OsString,
    },

    #[error("invalid mac")]
    InvalidMac,

    #[error("invalid two factor provider type: {ty}")]
    InvalidTwoFactorProvider { ty: String },

    #[error("failed to parse JSON")]
    Json {
        source: serde_path_to_error::Error<serde_json::Error>,
    },

    #[error("failed to load config from {}", .file.display())]
    LoadConfig {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to load config from {}", .file.display())]
    LoadConfigJson {
        source: serde_json::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to load db from {}", .file.display())]
    LoadDb {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to load db from {}", .file.display())]
    LoadDbJson {
        source: serde_json::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to load device id from {}", .file.display())]
    LoadDeviceId {
        source: tokio::io::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to load client cert from {}", .file.display())]
    LoadClientCert {
        source: tokio::io::Error,
        file: std::path::PathBuf,
    },

    #[error("invalid padding")]
    Padding,

    #[error("failed to parse match type {s}")]
    ParseMatchType { s: String },

    #[error("pbkdf2 requires at least 1 iteration (got 0)")]
    Pbkdf2ZeroIterations,

    #[error("failed to run pbkdf2")]
    Pbkdf2,

    #[error("failed to run argon2")]
    Argon2,

    #[error("pinentry cancelled")]
    PinentryCancelled,

    #[error("pinentry error: {error}")]
    PinentryErrorMessage { error: String },

    #[error("error reading pinentry output")]
    PinentryReadOutput { source: tokio::io::Error },

    #[error("error waiting for pinentry to exit")]
    PinentryWait { source: tokio::io::Error },

    #[error("This device has not yet been registered with the Bitwarden server. Run `rbw register` first, and then try again.")]
    RegistrationRequired,

    #[error("failed to remove db at {}", .file.display())]
    RemoveDb {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[error("api request returned error: {status}")]
    RequestFailed { status: u16 },

    #[error("api request unauthorized")]
    RequestUnauthorized,

    #[error("error making api request")]
    Reqwest { source: reqwest::Error },

    #[error("failed to decrypt")]
    Rsa { source: rsa::errors::Error },

    #[error("failed to decrypt")]
    RsaPkcs8 { source: rsa::pkcs8::Error },

    #[error("failed to save config to {}", .file.display())]
    SaveConfig {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to save config to {}", .file.display())]
    SaveConfigJson {
        source: serde_json::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to save db to {}", .file.display())]
    SaveDb {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to save db to {}", .file.display())]
    SaveDbJson {
        source: serde_json::Error,
        file: std::path::PathBuf,
    },

    #[error("failed to find crypto parameters in db")]
    UnavailableDbCryptoParameters,

    #[error("failed to find {0} in db")]
    UnavailableDbSessionParameters(&'static str),

    #[error("failed to find protected keys in db")]
    UnavailableDbProtectedKeys,

    #[error("error spawning pinentry")]
    Spawn { source: tokio::io::Error },

    #[error("cipherstring type {ty} too old\n\nPlease rotate your account encryption key (https://bitwarden.com/help/article/account-encryption-key/) and try again.")]
    TooOldCipherStringType { ty: String },

    #[error("two factor required")]
    TwoFactorRequired {
        providers: Vec<crate::api::TwoFactorProviderType>,
        sso_email_2fa_session_token: Option<String>,
    },

    #[error("unimplemented cipherstring type: {ty}")]
    UnimplementedCipherStringType { ty: String },

    #[error("I/O Error: {source}")]
    GenericIo { source: std::io::Error },

    #[error("error writing to pinentry stdin")]
    WriteStdin { source: tokio::io::Error },

    #[error("invalid kdf type: {ty}")]
    InvalidKdfType { ty: String },

    #[error("Utf8 conversion error: {source}")]
    Utf8Error { source: Utf8Error },

    #[error("the remote has sent an empty cipher data")]
    EmptyCipherData,

    #[error("the entry has been deleted")]
    DeletedEntry,
}

impl From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Self {
        Self::Utf8Error { source: value }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::GenericIo { source: value }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        match err.status() {
            Some(status) => match status {
                reqwest::StatusCode::UNAUTHORIZED => Self::RequestUnauthorized,
                _ => Self::RequestFailed {
                    status: status.as_u16(),
                },
            },
            None => Self::Reqwest { source: err },
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
