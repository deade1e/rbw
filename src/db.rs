use crate::{
    actions::{CryptoParameters, SessionParameters},
    prelude::*,
};

use std::{collections::HashMap, fmt::Display};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FieldType {
    Notes,
    Username,
    Password,
    Totp,
    Uris,
    IdentityName,
    City,
    State,
    PostalCode,
    Country,
    Phone,
    Ssn,
    License,
    Passport,
    CardNumber,
    Expiration,
    ExpMonth,
    ExpYear,
    Cvv,
    Cardholder,
    Brand,
    Name,
    Email,
    Address,
    Address1,
    Address2,
    Address3,
    Fingerprint,
    PublicKey,
    PrivateKey,
    Title,
    FirstName,
    MiddleName,
    LastName,
    Custom(String),
}

impl From<&str> for FieldType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "notes" | "note" => Self::Notes,
            "username" | "user" => Self::Username,
            "password" => Self::Password,
            "totp" | "code" => Self::Totp,
            "uris" | "urls" | "sites" => Self::Uris,
            "identityname" => Self::IdentityName,
            "city" => Self::City,
            "state" => Self::State,
            "postcode" | "zipcode" | "zip" => Self::PostalCode,
            "country" => Self::Country,
            "phone" => Self::Phone,
            "ssn" => Self::Ssn,
            "license" => Self::License,
            "passport" => Self::Passport,
            "number" | "card" => Self::CardNumber,
            "exp" => Self::Expiration,
            "exp_month" | "month" => Self::ExpMonth,
            "exp_year" | "year" => Self::ExpYear,
            // the word "code" got preceeded by Totp
            "cvv" => Self::Cvv,
            "cardholder" | "cardholder_name" => Self::Cardholder,
            "brand" | "type" => Self::Brand,
            "name" => Self::Name,
            "email" => Self::Email,
            "address1" => Self::Address1,
            "address2" => Self::Address2,
            "address3" => Self::Address3,
            "address" => Self::Address,
            "fingerprint" => Self::Fingerprint,
            "public_key" => Self::PublicKey,
            "private_key" => Self::PrivateKey,
            "title" => Self::Title,
            "first_name" => Self::FirstName,
            "middle_name" => Self::MiddleName,
            "last_name" => Self::LastName,
            _ => Self::Custom(s.to_string()),
        }
    }
}

impl Display for FieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Notes => "notes",
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Uris => "uris",
            Self::IdentityName => "identityname",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postcode",
            Self::Country => "country",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::License => "license",
            Self::Passport => "passport",
            Self::CardNumber => "number",
            Self::Expiration => "exp",
            Self::ExpMonth => "exp_month",
            Self::ExpYear => "exp_year",
            Self::Cvv => "cvv",
            Self::Cardholder => "cardholder",
            Self::Brand => "brand",
            Self::Name => "name",
            Self::Email => "email",
            Self::Address1 => "address1",
            Self::Address2 => "address2",
            Self::Address3 => "address3",
            Self::Address => "address",
            Self::Fingerprint => "fingerprint",
            Self::PublicKey => "public_key",
            Self::PrivateKey => "private_key",
            Self::Title => "title",
            Self::FirstName => "first_name",
            Self::MiddleName => "middle_name",
            Self::LastName => "last_name",
            Self::Custom(name) => name,
        })
    }
}

/// Used to describe custom fields in the application.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct DynamicField {
    pub ty: Option<crate::api::FieldType>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub linked_id: Option<crate::api::LinkedIdType>,
}

#[allow(clippy::large_enum_variant)]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum EntryData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Vec<Uri>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct HistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Entry {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<DynamicField>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
}

// Most impl fn don't belong here. I am talking of display ones, but looking to relocate them
// later in the refactor process.
impl Entry {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }

    /// The "short" is the first field that comes to mind when speaking of a entry, like the
    /// password for the Login , the number for the Card, etc.
    pub fn get_short(&self) -> Option<String> {
        match &self.data {
            EntryData::Login { password, .. } => password.clone(),
            EntryData::Card { number, .. } => number.clone(),
            EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<String> = [title, first_name, middle_name, last_name]
                    .iter()
                    .copied()
                    .flatten()
                    .cloned()
                    .collect();

                if names.is_empty() {
                    None
                } else {
                    Some(names.join(" "))
                }
            }
            EntryData::SecureNote => self.notes.clone(),
            EntryData::SshKey { public_key, .. } => public_key.clone(),
        }
    }

    /// Ugly function. Its job could be handled semi-automatically by the type system.
    /// Doesn't need to be "Decrypted" to work.
    pub fn get_fields_list(&self) -> Vec<String> {
        let mut ret = vec![];

        for (k, _) in self.static_fields() {
            ret.push(k.to_string());
        }

        for (k, _) in self.custom_fields() {
            ret.push(k);
        }

        ret
    }

    /// Given a textual representation of a field, like "username", "password" or "card number",
    /// check which type of entry EntryData is and extract the "username" or "cardnumber" field if
    /// available from the "static" fields, else go check for the dynamic ones.
    /// For example, if the EntryData is of type EntryData::Login, try to extract the username from the
    /// static username field, but if the field param is not within the static fields, search for it through the dynamic ones.
    /// The dynamic fields are the user's added ones and labeled as "Custom field" in GUI apps.
    pub fn get_field(
        &self,
        field_key: &str,
        generate_totp: fn(&str) -> anyhow::Result<String>,
    ) -> Vec<String> {
        let mut ret = vec![];
        let ftype: FieldType = field_key.into();

        if let FieldType::Custom(field_key) = ftype {
            if let Some(value) = self.custom_fields().remove(&field_key) {
                value.into_iter().for_each(|i| ret.push(i));
            }
        } else {
            if let Some(value) = self.static_fields().remove(&ftype) {
                let value = if ftype == FieldType::Totp {
                    match generate_totp(&value) {
                        Ok(totp) => totp,
                        Err(e) => {
                            eprintln!("{e}");
                            String::new()
                        }
                    }
                } else {
                    value
                };

                ret.push(value);
            }
        }

        ret
    }

    pub fn static_fields(&self) -> HashMap<FieldType, String> {
        let mut map = HashMap::new();

        let mut ins = |k, v: &Option<String>| {
            if let Some(v) = v {
                map.insert(k, v.clone());
            }
        };

        match &self.data {
            EntryData::Login {
                username,
                password,
                totp,
                uris,
            } => {
                ins(FieldType::Username, username);
                ins(FieldType::Password, password);
                ins(FieldType::Totp, totp);
                if !uris.is_empty() {
                    ins(
                        FieldType::Uris,
                        &Some(
                            uris.iter()
                                .map(|u| u.uri.clone())
                                .collect::<Vec<_>>()
                                .join("\n"),
                        ),
                    );
                }
            }
            EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                ins(FieldType::CardNumber, number);
                ins(FieldType::Cvv, code);
                ins(FieldType::Cardholder, cardholder_name);
                ins(FieldType::Brand, brand);
                ins(FieldType::ExpMonth, exp_month);
                ins(FieldType::ExpYear, exp_year);
                if let (Some(m), Some(y)) = (exp_month, exp_year) {
                    ins(FieldType::Expiration, &Some(format!("{m}/{y}")));
                }
            }
            EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => {
                let name: Vec<String> = [title, first_name, middle_name, last_name]
                    .iter()
                    .copied()
                    .flatten()
                    .cloned()
                    .collect();
                if !name.is_empty() {
                    ins(FieldType::Name, &Some(name.join(" ")));
                }

                let address: Vec<String> = [address1, address2, address3]
                    .iter()
                    .copied()
                    .flatten()
                    .cloned()
                    .collect();
                if !address.is_empty() {
                    ins(FieldType::Address, &Some(address.join("\n")));
                }

                ins(FieldType::City, city);
                ins(FieldType::State, state);
                ins(FieldType::PostalCode, postal_code);
                ins(FieldType::Country, country);
                ins(FieldType::Phone, phone);
                ins(FieldType::Email, email);
                ins(FieldType::Ssn, ssn);
                ins(FieldType::License, license_number);
                ins(FieldType::Passport, passport_number);
                ins(FieldType::Username, username);
            }
            EntryData::SecureNote => {}
            EntryData::SshKey {
                private_key,
                public_key,
                fingerprint,
            } => {
                ins(FieldType::PrivateKey, private_key);
                ins(FieldType::PublicKey, public_key);
                ins(FieldType::Fingerprint, fingerprint);
            }
        }

        ins(FieldType::Notes, &self.notes);

        map
    }

    pub fn custom_fields(&self) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for f in &self.fields {
            if let (Some(name), Some(value)) = (&f.name, &f.value) {
                map.entry(name.clone()).or_default().push(value.clone());
            }
        }
        map
    }
}

pub trait Decrypter {
    fn decrypt_field(&mut self, entry: Option<&Entry>, field: &str) -> Result<String>;
    fn decrypt_optfield(
        &mut self,
        entry: Option<&Entry>,
        field: &Option<&str>,
    ) -> Result<Option<String>> {
        Ok(match field {
            Some(field) => Some(self.decrypt_field(entry, field)?),
            None => None,
        })
    }
}

pub trait Encrypter {
    fn encrypt_field(&mut self, entry: Option<&Entry>, field: &str) -> Result<String>;
    fn encrypt_optfield(
        &mut self,
        entry: Option<&Entry>,
        field: &Option<&str>,
    ) -> Result<Option<String>> {
        Ok(match field {
            Some(field) => Some(self.encrypt_field(entry, field)?),
            None => None,
        })
    }
}

impl Entry {
    pub fn encrypt_string(&self, s: &str, encrypter: &mut impl Encrypter) -> Result<String> {
        encrypter.encrypt_field(Some(self), s)
    }

    pub fn encrypt_optstring(
        &self,
        optstring: &Option<String>,
        encrypter: &mut impl Encrypter,
    ) -> Result<Option<String>> {
        encrypter.encrypt_optfield(Some(self), &optstring.as_deref())
    }

    pub fn decrypt_string(&self, s: &str, decrypter: &mut impl Decrypter) -> Result<String> {
        decrypter.decrypt_field(Some(self), s)
    }

    pub fn decrypt_optstring(
        &self,
        optstring: &Option<String>,
        decrypter: &mut impl Decrypter,
    ) -> Result<Option<String>> {
        decrypter.decrypt_optfield(Some(self), &optstring.as_deref())
    }

    pub fn decrypt_custom_fields(
        &self,
        decrypter: &mut impl Decrypter,
    ) -> Result<Vec<DynamicField>> {
        self.fields
            .iter()
            .map(|field| {
                Ok(DynamicField {
                    name: self.decrypt_optstring(&field.name, decrypter)?,
                    value: self.decrypt_optstring(&field.value, decrypter)?,
                    ty: field.ty,
                    linked_id: field.linked_id,
                })
            })
            .collect()
    }

    pub fn decrypt_uris(&self, decrypter: &mut impl Decrypter) -> Result<Vec<Uri>> {
        match &self.data {
            EntryData::Login { uris, .. } => Ok(uris
                .iter()
                .map(|u| -> Result<Uri> {
                    Ok(Uri {
                        uri: decrypter.decrypt_field(Some(self), &u.uri)?,
                        match_type: u.match_type,
                    })
                })
                .collect::<Result<Vec<Uri>>>()?),
            _ => Ok(vec![]),
        }
    }

    pub fn decrypt_history(&self, decrypter: &mut impl Decrypter) -> Result<Vec<HistoryEntry>> {
        self.history
            .iter()
            .map(|he| {
                Ok(HistoryEntry {
                    last_used_date: he.last_used_date.clone(),
                    password: decrypter.decrypt_field(Some(self), &he.password)?,
                })
            })
            .collect::<Result<_>>()
    }

    pub fn _decrypt(&self, decrypter: &mut impl Decrypter) -> Result<Entry> {
        // folder name should always be decrypted with the local key because
        // folders are local to a specific user's vault, not the organization
        let folder = self.decrypt_optstring(&self.folder, decrypter)?;

        let fields = self.decrypt_custom_fields(decrypter)?;

        let notes = self.decrypt_optstring(&self.notes, decrypter)?;

        let history = self.decrypt_history(decrypter)?;

        let mut df = |_ft, val: &Option<String>| self.decrypt_optstring(val, decrypter);

        let data = match &self.data {
            EntryData::Login {
                username,
                password,
                totp,
                uris,
            } => EntryData::Login {
                username: df(FieldType::Username, username)?,
                password: df(FieldType::Password, password)?,
                totp: df(FieldType::Totp, totp)?,
                uris: uris
                    .iter()
                    .map(|s| {
                        Ok(df(FieldType::Uris, &Some(s.uri.clone()))?.map(|uri| Uri {
                            uri,
                            match_type: s.match_type,
                        }))
                    })
                    .collect::<Result<Vec<Option<Uri>>>>()?
                    .into_iter()
                    .flatten()
                    .collect(),
            },
            EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => EntryData::Card {
                cardholder_name: df(FieldType::Cardholder, cardholder_name)?,
                number: df(FieldType::CardNumber, number)?,
                brand: df(FieldType::Brand, brand)?,
                exp_month: df(FieldType::ExpMonth, exp_month)?,
                exp_year: df(FieldType::ExpYear, exp_year)?,
                code: df(FieldType::Cvv, code)?,
            },
            EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => EntryData::Identity {
                title: df(FieldType::Title, title)?,
                first_name: df(FieldType::FirstName, first_name)?,
                middle_name: df(FieldType::MiddleName, middle_name)?,
                last_name: df(FieldType::LastName, last_name)?,
                address1: df(FieldType::Address1, address1)?,
                address2: df(FieldType::Address2, address2)?,
                address3: df(FieldType::Address3, address3)?,
                city: df(FieldType::City, city)?,
                state: df(FieldType::State, state)?,
                postal_code: df(FieldType::PostalCode, postal_code)?,
                country: df(FieldType::Country, country)?,
                phone: df(FieldType::Phone, phone)?,
                email: df(FieldType::Email, email)?,
                ssn: df(FieldType::Ssn, ssn)?,
                license_number: df(FieldType::License, license_number)?,
                passport_number: df(FieldType::Passport, passport_number)?,
                username: df(FieldType::Username, username)?,
            },
            EntryData::SecureNote => EntryData::SecureNote {},
            EntryData::SshKey {
                public_key,
                fingerprint,
                private_key,
            } => EntryData::SshKey {
                public_key: df(FieldType::PublicKey, public_key)?,
                fingerprint: df(FieldType::Fingerprint, fingerprint)?,
                private_key: df(FieldType::PrivateKey, private_key)?,
            },
        };

        Ok(Entry {
            id: self.id.clone(),
            folder,
            folder_id: self.folder_id.clone(),
            org_id: self.org_id.clone(),
            key: None,
            name: decrypter.decrypt_field(Some(self), &self.name)?,
            data,
            fields,
            notes,
            history,
            master_password_reprompt: self.master_password_reprompt,
        })
    }

    /// Decrypt only non-sensitive fields, leaving passwords, card numbers, TOTP
    /// secrets, SSH private keys, identity SSN/passport/license, and history
    /// as encrypted cipherstrings (not None).
    pub fn decrypt_non_sensitive(&self, decrypter: &mut impl Decrypter) -> Result<Entry> {
        let folder = self.decrypt_optstring(&self.folder, decrypter)?;
        let notes = self.decrypt_optstring(&self.notes, decrypter)?;

        let fields: Vec<DynamicField> = self
            .fields
            .iter()
            .map(|field| {
                Ok(DynamicField {
                    name: self.decrypt_optstring(&field.name, decrypter)?,
                    value: self.decrypt_optstring(&field.value, decrypter)?,
                    ty: field.ty,
                    linked_id: field.linked_id,
                })
            })
            .collect::<Result<_>>()?;

        let data = match &self.data {
            EntryData::Login {
                username,
                password,
                totp,
                uris,
            } => EntryData::Login {
                username: self.decrypt_optstring(username, decrypter)?,
                password: password.clone(),
                totp: totp.clone(),
                uris: uris
                    .iter()
                    .map(|s| {
                        Ok(Uri {
                            uri: decrypter.decrypt_field(Some(self), &s.uri)?,
                            match_type: s.match_type,
                        })
                    })
                    .collect::<Result<Vec<Uri>>>()?,
            },
            EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => EntryData::Card {
                cardholder_name: self.decrypt_optstring(cardholder_name, decrypter)?,
                number: number.clone(),
                brand: self.decrypt_optstring(brand, decrypter)?,
                exp_month: self.decrypt_optstring(exp_month, decrypter)?,
                exp_year: self.decrypt_optstring(exp_year, decrypter)?,
                code: code.clone(),
            },
            EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => EntryData::Identity {
                title: self.decrypt_optstring(title, decrypter)?,
                first_name: self.decrypt_optstring(first_name, decrypter)?,
                middle_name: self.decrypt_optstring(middle_name, decrypter)?,
                last_name: self.decrypt_optstring(last_name, decrypter)?,
                address1: self.decrypt_optstring(address1, decrypter)?,
                address2: self.decrypt_optstring(address2, decrypter)?,
                address3: self.decrypt_optstring(address3, decrypter)?,
                city: self.decrypt_optstring(city, decrypter)?,
                state: self.decrypt_optstring(state, decrypter)?,
                postal_code: self.decrypt_optstring(postal_code, decrypter)?,
                country: self.decrypt_optstring(country, decrypter)?,
                phone: self.decrypt_optstring(phone, decrypter)?,
                email: self.decrypt_optstring(email, decrypter)?,
                ssn: ssn.clone(),
                license_number: license_number.clone(),
                passport_number: passport_number.clone(),
                username: self.decrypt_optstring(username, decrypter)?,
            },
            EntryData::SecureNote => EntryData::SecureNote {},
            EntryData::SshKey {
                public_key,
                fingerprint,
                private_key,
            } => EntryData::SshKey {
                public_key: self.decrypt_optstring(public_key, decrypter)?,
                fingerprint: self.decrypt_optstring(fingerprint, decrypter)?,
                private_key: private_key.clone(),
            },
        };

        Ok(Entry {
            id: self.id.clone(),
            folder,
            folder_id: self.folder_id.clone(),
            org_id: self.org_id.clone(),
            key: self.key.clone(),
            name: decrypter.decrypt_field(Some(self), &self.name)?,
            data,
            fields,
            notes,
            history: self.history.clone(),
            master_password_reprompt: self.master_password_reprompt,
        })
    }

    /// Fill in the sensitive fields that are encrypted cipherstrings in this
    /// partially decrypted entry by decrypting them in-place. Also decrypts history.
    /// `self` should be a partially decrypted entry (from decrypt_non_sensitive),
    /// where sensitive fields are still encrypted cipherstrings.
    pub fn fill_sensitive_fields(&mut self, decrypter: &mut impl Decrypter) -> Result<()> {
        self.history = self.decrypt_history(decrypter)?;

        let encrypted_password = match &self.data {
            EntryData::Login { password, .. } => password.clone(),
            _ => None,
        };
        let encrypted_totp = match &self.data {
            EntryData::Login { totp, .. } => totp.clone(),
            _ => None,
        };
        let encrypted_number = match &self.data {
            EntryData::Card { number, .. } => number.clone(),
            _ => None,
        };
        let encrypted_code = match &self.data {
            EntryData::Card { code, .. } => code.clone(),
            _ => None,
        };
        let encrypted_ssn = match &self.data {
            EntryData::Identity { ssn, .. } => ssn.clone(),
            _ => None,
        };
        let encrypted_license = match &self.data {
            EntryData::Identity { license_number, .. } => license_number.clone(),
            _ => None,
        };
        let encrypted_passport = match &self.data {
            EntryData::Identity {
                passport_number, ..
            } => passport_number.clone(),
            _ => None,
        };
        let encrypted_private_key = match &self.data {
            EntryData::SshKey { private_key, .. } => private_key.clone(),
            _ => None,
        };

        let decrypted_password = self.decrypt_optstring(&encrypted_password, decrypter)?;
        let decrypted_totp = self.decrypt_optstring(&encrypted_totp, decrypter)?;
        let decrypted_number = self.decrypt_optstring(&encrypted_number, decrypter)?;
        let decrypted_code = self.decrypt_optstring(&encrypted_code, decrypter)?;
        let decrypted_ssn = self.decrypt_optstring(&encrypted_ssn, decrypter)?;
        let decrypted_license = self.decrypt_optstring(&encrypted_license, decrypter)?;
        let decrypted_passport = self.decrypt_optstring(&encrypted_passport, decrypter)?;
        let decrypted_private_key = self.decrypt_optstring(&encrypted_private_key, decrypter)?;

        match &mut self.data {
            EntryData::Login { password, totp, .. } => {
                *password = decrypted_password;
                *totp = decrypted_totp;
            }
            EntryData::Card { number, code, .. } => {
                *number = decrypted_number;
                *code = decrypted_code;
            }
            EntryData::Identity {
                ssn,
                license_number,
                passport_number,
                ..
            } => {
                *ssn = decrypted_ssn;
                *license_number = decrypted_license;
                *passport_number = decrypted_passport;
            }
            EntryData::SshKey { private_key, .. } => {
                *private_key = decrypted_private_key;
            }
            EntryData::SecureNote => {}
        }

        Ok(())
    }
}

fn writefield(
    f: &mut std::fmt::Formatter<'_>,
    label: &str,
    field: &Option<String>,
    displayed: &mut bool,
) -> std::fmt::Result {
    if let Some(field) = field {
        *displayed = true;
        writeln!(f, "{label}: {field}")
    } else {
        Ok(())
    }
}

/// Display impl is a bit messy as we need to support previous output format.
/// I would, for example, yank this displayed bool and always print Notes after ---.
/// I would avoid printing the "short" field this way too, but rather print it as a normal field.
impl Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(short) = self.get_short() {
            writeln!(f, "{short}")?;
        }

        let mut d = false;

        match &self.data {
            EntryData::Login {
                username,
                totp,
                uris,
                ..
            } => {
                writefield(f, "Username", username, &mut d)?;
                writefield(f, "TOTP Secret", totp, &mut d)?;

                for uri in uris {
                    d = true;
                    write!(f, "{uri}")?;
                }

                for field in &self.fields {
                    d = true;
                    writeln!(
                        f,
                        "{}: {}",
                        field.name.as_deref().unwrap_or("(null)"),
                        field.value.as_deref().unwrap_or("")
                    )?;
                }
            }
            EntryData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if let (Some(m), Some(y)) = (exp_month, exp_year) {
                    writefield(f, "Expiration", &Some(format!("{m}/{y}")), &mut d)?;
                }

                writefield(f, "CVV", code, &mut d)?;
                writefield(f, "Name", cardholder_name, &mut d)?;
                writefield(f, "Brand", brand, &mut d)?;
            }
            EntryData::Identity {
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
                ..
            } => {
                writefield(f, "Address", address1, &mut d)?;
                writefield(f, "Address", address2, &mut d)?;
                writefield(f, "Address", address3, &mut d)?;
                writefield(f, "City", city, &mut d)?;
                writefield(f, "State", state, &mut d)?;
                writefield(f, "Postcode", postal_code, &mut d)?;
                writefield(f, "Country", country, &mut d)?;
                writefield(f, "Phone", phone, &mut d)?;
                writefield(f, "Email", email, &mut d)?;
                writefield(f, "SSN", ssn, &mut d)?;
                writefield(f, "License", license_number, &mut d)?;
                writefield(f, "Passport", passport_number, &mut d)?;
                writefield(f, "Username", username, &mut d)?;
            }
            EntryData::SecureNote => {}
            EntryData::SshKey { fingerprint, .. } => {
                writefield(f, "Fingerprint", fingerprint, &mut d)?;

                for field in &self.fields {
                    d = true;
                    writeln!(
                        f,
                        "{}: {}",
                        field.name.as_deref().unwrap_or("(null)"),
                        field.value.as_deref().unwrap_or("")
                    )?;
                }
            }
        }

        if !matches!(self.data, EntryData::SecureNote) {
            if let Some(notes) = &self.notes {
                if d {
                    writeln!(f)?;
                }
                writeln!(f, "{notes}")?;
            }
        }

        Ok(())
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
}

impl Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "URI: {}", &self.uri)?;

        if let Some(ty) = self.match_type {
            writeln!(f, "Match type: {ty}")?;
        }

        Ok(())
    }
}

// backwards compatibility
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrUri;
        impl<'de> serde::de::Visitor<'de> for StringOrUri {
            type Value = Uri;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("uri")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Uri {
                    uri: value.to_string(),
                    match_type: None,
                })
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut uri = None;
                let mut match_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "uri" => {
                            if uri.is_some() {
                                return Err(serde::de::Error::duplicate_field("uri"));
                            }
                            uri = Some(map.next_value()?);
                        }
                        "match_type" => {
                            if match_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("match_type"));
                            }
                            match_type = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| Ok(Self::Value { uri, match_type }),
                )
            }
        }

        deserializer.deserialize_any(StringOrUri)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    // TODO: Flatten SessionParameters into these fields
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    #[serde(flatten)]
    pub crypto_params: Option<CryptoParameters>,

    pub protected_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_org_keys: HashMap<String, String>,

    // TODO: This could be a HashMap?
    pub entries: Vec<Entry>,
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn load_async(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email)?;
        let mut fh = tokio::fs::File::open(&file)
            .await
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .await
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let slf: Self =
            serde_json::from_str(&json).map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub fn update_access_token(&mut self, access_token: Option<String>) -> bool {
        if let Some(access_token) = access_token {
            self.access_token = Some(access_token);
            true
        } else {
            false
        }
    }

    pub fn apply_session_parameters(&mut self, params: &SessionParameters) {
        self.access_token = Some(params.access_token.clone());
        self.refresh_token = Some(params.refresh_token.clone());
        self.crypto_params = Some(params.crypto_params.clone());
        self.protected_key = Some(params.protected_key.clone());
    }

    // TODO: Return references if possible
    // NOTE: Previous error string were different. Not 100% compatible output.
    pub fn get_crypto_parameters(&self) -> Result<CryptoParameters> {
        self.crypto_params
            .clone()
            .ok_or(Error::UnavailableDbCryptoParameters)
    }

    // TODO: Return references if possible
    pub fn get_session_parameters(&self) -> Result<SessionParameters> {
        let Some(access_token) = self.access_token.clone() else {
            return Err(Error::UnavailableDbSessionParameters("access_token"));
        };

        let Some(refresh_token) = self.refresh_token.clone() else {
            return Err(Error::UnavailableDbSessionParameters("refresh_token"));
        };

        let Some(protected_key) = self.protected_key.clone() else {
            return Err(Error::UnavailableDbSessionParameters("protected key"));
        };

        Ok(SessionParameters {
            access_token,
            refresh_token,
            crypto_params: self.get_crypto_parameters()?,
            protected_key,
        })
    }

    // XXX need to make this atomic
    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email)?;
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        tokio::fs::create_dir_all(file.parent().unwrap())
            .await
            .map_err(|source| Error::SaveDb {
                source,
                file: file.clone(),
            })?;
        let mut fh = tokio::fs::File::create(&file)
            .await
            .map_err(|source| Error::SaveDb {
                source,
                file: file.clone(),
            })?;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveDbJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .await
        .map_err(|source| Error::SaveDb { source, file })?;
        Ok(())
    }

    pub fn remove(server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email)?;
        let res = std::fs::remove_file(&file);
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        res.map_err(|source| Error::RemoveDb { source, file })?;
        Ok(())
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || self.refresh_token.is_none()
            || self.crypto_params.is_none()
            || self.protected_key.is_none()
    }

    pub fn protected_keys(&self) -> (&Option<String>, &Option<String>, &HashMap<String, String>) {
        (
            &self.protected_key,
            &self.protected_private_key,
            &self.protected_org_keys,
        )
    }

    pub fn some_protected_keys(&self) -> Option<(&String, &String, &HashMap<String, String>)> {
        let keys = self.protected_keys();

        match keys {
            (Some(key), Some(priv_key), org_keys) => Some((key, priv_key, org_keys)),
            _ => None,
        }
    }
}
