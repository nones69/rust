//! Live LDAP / Active Directory lookup via `ldap3` (Phase 2).
//!
//! Activated when `INTENTOS_LDAP_URL` is set. Falls back to stub on connection
//! or bind failure.

use super::identity::{IdentityBackend, Principal};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::time::Duration;
use thiserror::Error;

const TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("ldap connect failed: {0}")]
    Connect(String),
    #[error("ldap bind failed: {0}")]
    Bind(String),
    #[error("ldap search failed: {0}")]
    Search(String),
    #[error("principal not found: {0}")]
    NotFound(String),
}

/// Live directory connection configuration from environment.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub url: String,
    pub base_dn: String,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub domain: String,
}

impl LdapConfig {
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("INTENTOS_LDAP_URL").ok()?;
        let base_dn = std::env::var("INTENTOS_LDAP_BASE_DN")
            .unwrap_or_else(|_| "dc=corp,dc=local".to_string());
        let domain = std::env::var("INTENTOS_AD_DOMAIN").unwrap_or_else(|_| "corp.local".to_string());
        let bind_dn = std::env::var("INTENTOS_LDAP_BIND_DN").ok();
        let bind_password = std::env::var("INTENTOS_LDAP_BIND_PW").ok();

        Some(Self {
            url,
            base_dn,
            bind_dn,
            bind_password,
            domain,
        })
    }
}

#[derive(Debug)]
pub struct LiveLdap {
    config: LdapConfig,
}

impl LiveLdap {
    pub fn try_connect() -> Result<Self, LdapError> {
        let config = LdapConfig::from_env().ok_or_else(|| {
            LdapError::Connect("INTENTOS_LDAP_URL not set".into())
        })?;
        // Validate connection + bind up front so IdentityBridge can fall back cleanly.
        let mut conn = Self::open_conn(&config)?;
        if let (Some(dn), Some(pw)) = (&config.bind_dn, &config.bind_password) {
            conn.simple_bind(dn, pw)
                .map_err(|e| LdapError::Bind(e.to_string()))?
                .success()
                .map_err(|e| LdapError::Bind(format!("{e:?}")))?;
        }
        drop(conn);
        Ok(Self { config })
    }

    pub fn lookup(&self, user: &str) -> Result<Principal, LdapError> {
        let local = user.split('@').next().unwrap_or(user).trim();
        let filter = std::env::var("INTENTOS_LDAP_USER_FILTER")
            .unwrap_or_else(|_| "(|(uid={user})(sAMAccountName={user})(userPrincipalName={user}@*))".into())
            .replace("{user}", local);

        let mut conn = Self::open_conn(&self.config)?;
        if let (Some(dn), Some(pw)) = (&self.config.bind_dn, &self.config.bind_password) {
            conn.simple_bind(dn, pw)
                .map_err(|e| LdapError::Bind(e.to_string()))?
                .success()
                .map_err(|e| LdapError::Bind(format!("{e:?}")))?;
        }

        let (entries, _) = conn
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                vec!["cn", "uid", "sAMAccountName", "userPrincipalName", "memberOf"],
            )
            .map_err(|e| LdapError::Search(e.to_string()))?
            .success()
            .map_err(|e| LdapError::Search(format!("{e:?}")))?;

        let entry = entries
            .into_iter()
            .next()
            .map(SearchEntry::construct)
            .ok_or_else(|| LdapError::NotFound(local.to_string()))?;

        let upn = attr_first(&entry.attrs, "userPrincipalName")
            .unwrap_or_else(|| format!("{local}@{}", self.config.domain));

        let display = attr_first(&entry.attrs, "cn")
            .or_else(|| attr_first(&entry.attrs, "sAMAccountName"))
            .or_else(|| attr_first(&entry.attrs, "uid"))
            .unwrap_or_else(|| local.to_string());

        let groups: Vec<String> = entry
            .attrs
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("memberOf"))
            .flat_map(|(_, vals)| vals.iter())
            .filter_map(|dn| dn.split(',').next().map(|cn| cn.trim_start_matches("CN=").to_string()))
            .collect();

        let actor_id = format!(
            "{}\\{}",
            self.config.domain.split('.').next().unwrap_or("CORP").to_uppercase(),
            display.replace(' ', "-")
        );

        Ok(Principal {
            backend: IdentityBackend::LdapLive,
            actor_id,
            upn,
            display_name: display,
            groups,
        })
    }

    fn open_conn(config: &LdapConfig) -> Result<LdapConn, LdapError> {
        let mut conn = LdapConn::new(&config.url)
            .map_err(|e| LdapError::Connect(e.to_string()))?;
        conn.with_timeout(Duration::from_secs(TIMEOUT_SECS));
        Ok(conn)
    }
}

fn attr_first(attrs: &std::collections::HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, vals)| vals.first())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_absent_without_url() {
        std::env::remove_var("INTENTOS_LDAP_URL");
        assert!(LdapConfig::from_env().is_none());
    }
}