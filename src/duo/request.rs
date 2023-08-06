use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{Client, Method, Request, Url};
use sha1::Sha1;

use crate::Error;

#[derive(Default)]
pub struct Parameters(BTreeMap<String, String>);

impl Parameters {
    pub fn set<K: Into<String>, V: Into<String>>(&mut self, k: K, v: V) {
        self.0.insert(k.into(), v.into());
    }

    pub fn serialize(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<String>>()
            .join("&")
            .into()
    }
}

impl From<Parameters> for BTreeMap<String, String> {
    fn from(value: Parameters) -> Self {
        value.0
    }
}

pub struct DuoRequest {
    url: Url,
    method: Method,
    path: String,
    date: DateTime<Utc>,
    parameters: Parameters,
}

impl DuoRequest {
    pub fn new(url: Url, method: Method, path: impl Into<String>, parameters: Parameters) -> Self {
        DuoRequest {
            url,
            method,
            path: path.into(),
            date: Utc::now(),
            parameters,
        }
    }

    pub fn build(&self, client: &Client, ikey: &str, skey: &str) -> Result<Request, Error> {
        let no_body = matches!(self.method, Method::GET | Method::HEAD);

        let parameters_str = self.parameters.serialize();
        let mut url = self.url.clone();
        url.set_path(&self.path);
        if no_body {
            url.set_query(Some(&parameters_str))
        }

        let signature = self.build_signature(skey, &parameters_str)?;
        let mut rb = client
            .request(self.method.clone(), url)
            .basic_auth(ikey.clone(), Some(signature))
            .header("Date", self.date.to_rfc2822())
            .header("User-Agent", "sss-x25519/0.0.1");

        if !no_body {
            rb = rb
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(parameters_str)
        }

        rb.build().map_err(|e| e.into())
    }

    fn build_signature(&self, skey: &str, parameters_str: &str) -> Result<String, Error> {
        let domain = self.url.host_str().unwrap().to_string();

        let payload = &[
            self.date.to_rfc2822(),
            self.method.to_string().to_uppercase(),
            domain,
            self.path.clone(),
            parameters_str.into(),
        ]
        .join("\n");

        let mut signer = Hmac::<Sha1>::new_from_slice(skey.as_bytes())?;
        signer.update(payload.as_bytes());

        let signature = hex::encode(signer.finalize().into_bytes());

        Ok(signature)
    }
}
