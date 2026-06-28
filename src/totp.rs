pub fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
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

pub fn generate_totp(secret: &str) -> anyhow::Result<String> {
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
