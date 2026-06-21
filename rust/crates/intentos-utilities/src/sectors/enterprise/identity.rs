//! AD/LDAP identity federation — stub + optional live `ldap3` backend.

use super::ldap_live::LiveLdap;
use serde::{Deserialize, Serialize};

/// Directory backend in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityBackend {
    AdLdapStub,
    LdapLive,
    Local,
}

/// Resolved enterprise principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub backend: IdentityBackend,
    pub actor_id: String,
    pub upn: String,
    pub display_name: String,
    pub groups: Vec<String>,
}

/// Identity bridge — live LDAP when configured, else stub directory.
#[derive(Debug)]
pub struct IdentityBridge {
    domain: String,
    default_user: String,
    backend: IdentityBackend,
    live: Option<LiveLdap>,
}

impl IdentityBridge {
    const STUB_DIRECTORY: &'static [(&'static str, &'static str, &'static [&'static str])] = &[
        (
            "admin@corp.local",
            "CORP\\Domain Admins",
            &["Domain Admins", "Enterprise Admins"],
        ),
        (
            "operator@corp.local",
            "CORP\\Operators",
            &["Operators", "Helpdesk"],
        ),
        (
            "svc-intentos@corp.local",
            "CORP\\IntentOS-Svc",
            &["IntentOS-Service"],
        ),
    ];

    pub fn from_env() -> Self {
        let domain = std::env::var("INTENTOS_AD_DOMAIN").unwrap_or_else(|_| "corp.local".into());
        let default_user =
            std::env::var("INTENTOS_ACTOR").unwrap_or_else(|_| "operator@corp.local".into());

        if std::env::var("INTENTOS_IDENTITY_BACKEND")
            .map(|v| v.eq_ignore_ascii_case("local"))
            .unwrap_or(false)
        {
            return Self {
                domain,
                default_user,
                backend: IdentityBackend::Local,
                live: None,
            };
        }

        if let Ok(live) = LiveLdap::try_connect() {
            return Self {
                domain: domain.clone(),
                default_user,
                backend: IdentityBackend::LdapLive,
                live: Some(live),
            };
        }

        Self {
            domain,
            default_user,
            backend: IdentityBackend::AdLdapStub,
            live: None,
        }
    }

    pub fn backend(&self) -> IdentityBackend {
        self.backend
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn is_live_ldap(&self) -> bool {
        matches!(self.backend, IdentityBackend::LdapLive)
    }

    pub fn whoami(&self) -> Principal {
        self.lookup(&self.default_user).unwrap_or_else(|| Principal {
            backend: IdentityBackend::Local,
            actor_id: self.default_user.clone(),
            upn: format!("{}@{}", self.default_user, self.domain),
            display_name: self.default_user.clone(),
            groups: vec!["Users".into()],
        })
    }

    pub fn lookup(&self, user: &str) -> Option<Principal> {
        if let Some(ref live) = self.live {
            match live.lookup(user) {
                Ok(p) => return Some(p),
                Err(_) if matches!(self.backend, IdentityBackend::LdapLive) => return None,
                Err(_) => {}
            }
        }

        let candidate = if user.contains('@') {
            user.to_string()
        } else {
            format!("{user}@{}", self.domain)
        };
        Self::resolve_stub(&candidate, self.backend)
    }

    pub fn actor_id(&self, principal: &Principal) -> String {
        principal.actor_id.clone()
    }

    pub fn trust_hint(&self, principal: &Principal) -> &'static str {
        let elevated = principal.groups.iter().any(|g| g.contains("Admin"));
        match (elevated, principal.backend) {
            (true, IdentityBackend::LdapLive) => "elevated",
            (true, _) => "elevated-stub",
            (false, IdentityBackend::LdapLive) => "standard-live",
            (false, _) => "standard-stub",
        }
    }

    pub fn list_stub_principals() -> &'static [&'static str] {
        &[
            "admin@corp.local",
            "operator@corp.local",
            "svc-intentos@corp.local",
        ]
    }

    fn resolve_stub(key: &str, backend: IdentityBackend) -> Option<Principal> {
        let lower = key.trim().to_lowercase();
        let stub_backend = if matches!(backend, IdentityBackend::LdapLive) {
            IdentityBackend::AdLdapStub
        } else {
            backend
        };

        for (upn, display, groups) in Self::STUB_DIRECTORY {
            if lower == upn.to_lowercase() || lower == display.to_lowercase() {
                return Some(Principal {
                    backend: stub_backend,
                    actor_id: sanitize_actor(display),
                    upn: (*upn).into(),
                    display_name: (*display).into(),
                    groups: groups.iter().map(|g| (*g).into()).collect(),
                });
            }
        }

        if key.contains('@') {
            let local = key.split('@').next().unwrap_or(key);
            return Some(Principal {
                backend: stub_backend,
                actor_id: format!("CORP\\{local}"),
                upn: key.into(),
                display_name: key.into(),
                groups: vec!["Users".into()],
            });
        }

        None
    }
}

fn sanitize_actor(display: &str) -> String {
    display.replace(' ', "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoami_uses_default_operator() {
        std::env::remove_var("INTENTOS_LDAP_URL");
        let bridge = IdentityBridge::from_env();
        let p = bridge.whoami();
        assert!(!p.actor_id.is_empty());
        assert!(!p.upn.is_empty());
    }

    #[test]
    fn lookup_finds_admin_stub() {
        std::env::remove_var("INTENTOS_LDAP_URL");
        let bridge = IdentityBridge::from_env();
        let p = bridge.lookup("admin@corp.local").unwrap();
        assert_eq!(p.actor_id, "CORP\\Domain-Admins");
    }
}