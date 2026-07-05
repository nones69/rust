use reqwest::blocking::Client;
use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

use crate::capability_schema::NetScope;
use crate::syscall_envelope::HttpMethod;

#[derive(Debug)]
pub struct NetGateway {
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetGatewayResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub resolved_ips: Vec<String>,
}

#[derive(Debug, Error)]
pub enum NetGatewayError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("scope denied for token {token_id}: {reason}")]
    ScopeDenied { token_id: Uuid, reason: String },
    #[error("dns resolve failed for {host}:{port}: {reason}")]
    DnsResolve {
        host: String,
        port: u16,
        reason: String,
    },
    #[error("invalid header name: {0}")]
    InvalidHeaderName(String),
    #[error("invalid header value for {name}: {reason}")]
    InvalidHeaderValue { name: String, reason: String },
    #[error("http request failed: {0}")]
    Http(String),
    #[error("response header value for {name} is not valid UTF-8")]
    ResponseHeaderEncoding { name: String },
}

impl NetGateway {
    pub fn new() -> Self {
        Self::new_with_timeout(Duration::from_secs(10))
    }

    pub fn new_with_timeout(timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .expect("net client build failed");
        Self { client }
    }

    pub fn net_request(
        &self,
        token_id: &Uuid,
        scope: &NetScope,
        method: HttpMethod,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<NetGatewayResponse, NetGatewayError> {
        let parsed =
            reqwest::Url::parse(url).map_err(|e| NetGatewayError::InvalidUrl(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| NetGatewayError::InvalidUrl("missing host".into()))?
            .to_ascii_lowercase();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| NetGatewayError::InvalidUrl("missing known port".into()))?;

        enforce_scope(token_id, scope, &method, &host)?;
        let resolved_ips = resolve_dns(&host, port)?;

        let reqwest_method = to_reqwest_method(&method);
        let mut req = self.client.request(reqwest_method, parsed);
        for (name, value) in headers {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| NetGatewayError::InvalidHeaderName(name.clone()))?;
            let header_value =
                HeaderValue::from_str(value).map_err(|e| NetGatewayError::InvalidHeaderValue {
                    name: name.clone(),
                    reason: e.to_string(),
                })?;
            req = req.header(header_name, header_value);
        }

        let resp = req
            .body(body.to_vec())
            .send()
            .map_err(|e| NetGatewayError::Http(e.to_string()))?;

        let status = resp.status().as_u16();
        let response_headers = resp
            .headers()
            .iter()
            .map(|(name, value)| -> Result<(String, String), NetGatewayError> {
                let value = value.to_str().map_err(|_| NetGatewayError::ResponseHeaderEncoding {
                    name: name.as_str().to_string(),
                })?;
                Ok((name.as_str().to_string(), value.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let body = resp
            .bytes()
            .map_err(|e| NetGatewayError::Http(e.to_string()))?
            .to_vec();

        Ok(NetGatewayResponse {
            status,
            headers: response_headers,
            body,
            resolved_ips,
        })
    }
}

fn enforce_scope(
    token_id: &Uuid,
    scope: &NetScope,
    method: &HttpMethod,
    host: &str,
) -> Result<(), NetGatewayError> {
    if !scope.methods.contains(method) {
        return Err(NetGatewayError::ScopeDenied {
            token_id: *token_id,
            reason: format!("method {method:?} not in token scope"),
        });
    }
    if !scope.hosts.iter().any(|allowed| host_matches(host, allowed)) {
        return Err(NetGatewayError::ScopeDenied {
            token_id: *token_id,
            reason: format!("host {host} not in token scope"),
        });
    }
    Ok(())
}

fn resolve_dns(host: &str, port: u16) -> Result<Vec<String>, NetGatewayError> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| NetGatewayError::DnsResolve {
            host: host.into(),
            port,
            reason: e.to_string(),
        })?;

    let mut ips = BTreeSet::new();
    for addr in addrs {
        ips.insert(addr.ip().to_string());
    }
    if ips.is_empty() {
        return Err(NetGatewayError::DnsResolve {
            host: host.into(),
            port,
            reason: "no resolved addresses".into(),
        });
    }
    Ok(ips.into_iter().collect())
}

fn to_reqwest_method(method: &HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::GET => reqwest::Method::GET,
        HttpMethod::POST => reqwest::Method::POST,
        HttpMethod::PUT => reqwest::Method::PUT,
        HttpMethod::DELETE => reqwest::Method::DELETE,
        HttpMethod::PATCH => reqwest::Method::PATCH,
    }
}

fn host_matches(host: &str, allowed: &str) -> bool {
    let allowed = allowed.trim().to_ascii_lowercase();
    if allowed.is_empty() {
        return false;
    }
    host == allowed
        || (host.len() > allowed.len()
            && host.as_bytes()[host.len() - allowed.len() - 1] == b'.'
            && host.ends_with(&allowed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_match_accepts_exact_and_subdomain_only() {
        assert!(host_matches("api.example.com", "example.com"));
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("malicious-example.com", "example.com"));
    }

    #[test]
    fn scope_check_blocks_missing_method() {
        let scope = NetScope {
            hosts: vec!["example.com".into()],
            methods: vec![HttpMethod::GET],
        };
        let err = enforce_scope(
            &Uuid::nil(),
            &scope,
            &HttpMethod::POST,
            "api.example.com",
        )
        .unwrap_err();
        assert!(matches!(err, NetGatewayError::ScopeDenied { .. }));
    }

    #[test]
    fn scope_check_blocks_outside_host() {
        let scope = NetScope {
            hosts: vec!["example.com".into()],
            methods: vec![HttpMethod::GET],
        };
        let err = enforce_scope(
            &Uuid::nil(),
            &scope,
            &HttpMethod::GET,
            "api.evil.com",
        )
        .unwrap_err();
        assert!(matches!(err, NetGatewayError::ScopeDenied { .. }));
    }
}
