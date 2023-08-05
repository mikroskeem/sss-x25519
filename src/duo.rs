use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use anyhow::Context;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{Method, Response, StatusCode, Url};
use serde::Deserialize;
use sha1::Sha1;
use url::form_urlencoded::Serializer;

use crate::Error;

pub struct DuoClient(Arc<DuoClientInner>);

struct DuoClientInner {
    api_domain: String,
    ikey: String,
    skey: String,
    user_id: String,

    client: reqwest::Client,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct DuoResponse<T> {
    response: T,
    stat: String,

    code: Option<u64>,
    message: Option<String>,
}

impl DuoClient {
    pub fn new(api_domain: String, ikey: String, skey: String, user_id: String) -> DuoClient {
        let client = reqwest::Client::new();
        DuoClient(Arc::new(DuoClientInner {
            api_domain,
            ikey,
            skey,
            user_id,
            client,
        }))
    }

    pub fn request_auth(&self, share_n: usize) -> impl Future<Output = Result<bool, Error>> {
        let this = Arc::clone(&self.0);

        async move {
            let txid = DuoClient::send_auth_request(this.clone(), share_n).await?;
            let mut status: Option<bool>;

            loop {
                status = DuoClient::auth_request_status(this.clone(), &txid).await?;
                match status {
                    None => tokio::time::sleep(Duration::from_secs(2)).await,
                    Some(v) => return Ok(v),
                }
            }
        }
    }

    async fn send_request(
        this: Arc<DuoClientInner>,
        date: DateTime<Utc>,
        method: Method,
        base_url: Url,
        path: String,
        parameters: BTreeMap<String, String>,
    ) -> Result<Response, Error> {
        let no_body = matches!(method, Method::GET | Method::HEAD);

        let body_str = {
            let mut ser = Serializer::new(String::new());
            for (k, v) in parameters.iter() {
                ser.append_pair(k, v);
            }

            // XXX: Duo doesn't like "+" as replacement for space
            ser.finish().replace('+', "%20")
        };

        let mut url = base_url.clone();
        url.set_path(&path);
        if no_body {
            url.set_query(Some(&body_str.clone()));
        }

        let signature = {
            let domain = base_url
                .host_str()
                .to_owned()
                .context("no host in base url")?
                .to_string();

            let payload = &[
                date.to_rfc2822(),
                method.to_string().to_uppercase(),
                domain,
                path,
                body_str.clone(),
            ]
            .join("\n");

            let mut signer = Hmac::<Sha1>::new_from_slice(this.skey.as_bytes())?;
            signer.update(payload.as_bytes());

            hex::encode(signer.finalize().into_bytes())
        };

        let mut rb = this
            .client
            .request(method, url)
            .basic_auth(this.ikey.clone(), Some(signature))
            .header("Date", date.to_rfc2822())
            .header("User-Agent", "sss-x25519/0.0.1");

        if !no_body {
            rb = rb
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body_str)
        }

        Ok(rb.send().await?)
    }

    async fn send_auth_request(this: Arc<DuoClientInner>, share_n: usize) -> Result<String, Error> {
        let mut parameters = BTreeMap::new();
        parameters.insert("user_id".into(), this.user_id.clone());
        parameters.insert("factor".into(), "auto".into());
        parameters.insert("async".into(), "1".into());
        parameters.insert("type".into(), "Authorize share".into());
        parameters.insert("device".into(), "auto".into());
        parameters.insert("display_username".into(), format!("Share {}", share_n));

        let response = DuoClient::send_request(
            this.clone(),
            Utc::now(),
            Method::POST,
            Url::parse(format!("https://{}", this.api_domain).as_str())?,
            "/auth/v2/auth".into(),
            parameters,
        )
        .await?;

        if response.status() != StatusCode::OK {
            // TODO: handle error properly
            let status = response.status();
            let errbody: serde_json::Value = response.json().await?;
            println!("err body={:?}", errbody);
            return Err(Error::from(format!("status code={}", status)));
        }

        #[derive(Deserialize)]
        struct AuthResponse {
            txid: String,
        }

        let body: DuoResponse<AuthResponse> = response.json().await?;

        Ok(body.response.txid)
    }

    async fn auth_request_status(
        this: Arc<DuoClientInner>,
        txid: &str,
    ) -> Result<Option<bool>, Error> {
        let mut parameters = BTreeMap::new();
        parameters.insert("txid".into(), txid.into());

        let response = DuoClient::send_request(
            this.clone(),
            Utc::now(),
            Method::GET,
            Url::parse(format!("https://{}", this.api_domain).as_str())?,
            "/auth/v2/auth_status".into(),
            parameters,
        )
        .await?;

        if response.status() != StatusCode::OK {
            // TODO: handle error properly
            let status = response.status();
            let errbody: serde_json::Value = response.json().await?;
            println!("err body={:?}", errbody);
            return Err(Error::from(format!("status code={}", status)));
            //return Err(Error::from(format!("status code={}", response.status())));
        }

        #[derive(Deserialize)]
        struct AuthStatusResponse {
            result: String,
        }

        let body: DuoResponse<AuthStatusResponse> = response.json().await?;
        match body.response.result.as_str() {
            "waiting" => Ok(None),
            "allow" => Ok(Some(true)),
            "deny" => Ok(Some(false)),
            v => Err(Error::from(format!("unexpected result '{}'", v))),
        }
    }
}
