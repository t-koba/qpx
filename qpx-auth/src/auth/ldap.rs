use anyhow::Result;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use qpx_core::config::LdapConfig;
use std::fmt::Write as _;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct LdapAuthenticator {
    config: LdapConfig,
    bind_password: String,
}

impl LdapAuthenticator {
    pub(super) fn new(config: LdapConfig, bind_password: String) -> Self {
        Self {
            config,
            bind_password,
        }
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<Vec<String>>> {
        let ldap_timeout = Duration::from_millis(self.config.timeout_ms.max(1));
        let settings = if self.config.require_starttls && self.config.url.starts_with("ldap://") {
            #[cfg(any(feature = "ldap-auth-rustls", feature = "ldap-auth-native"))]
            {
                LdapConnSettings::new().set_starttls(true)
            }
            #[cfg(not(any(feature = "ldap-auth-rustls", feature = "ldap-auth-native")))]
            {
                return Err(anyhow::anyhow!(
                    "ldap auth requires LDAP TLS support in this build"
                ));
            }
        } else {
            LdapConnSettings::new()
        };
        #[cfg(not(any(feature = "ldap-auth-rustls", feature = "ldap-auth-native")))]
        if self.config.url.starts_with("ldaps://") {
            return Err(anyhow::anyhow!(
                "ldap auth requires LDAP TLS support in this build"
            ));
        }
        let (conn, mut ldap) = timeout(
            ldap_timeout,
            LdapConnAsync::with_settings(settings, &self.config.url),
        )
        .await??;
        tokio::spawn(async move {
            if let Err(err) = conn.drive().await {
                tracing::warn!(error = ?err, "ldap connection error");
            }
        });

        timeout(
            ldap_timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.bind_password),
        )
        .await??
        .success()?;

        let escaped_username = ldap_escape_filter_value(username);
        let filter = self
            .config
            .user_filter
            .replace("{username}", escaped_username.as_str());
        let (results, _res) = timeout(
            ldap_timeout,
            ldap.search(
                &self.config.user_base_dn,
                Scope::Subtree,
                &filter,
                vec!["dn"],
            ),
        )
        .await??
        .success()?;

        let entry = match results.into_iter().next() {
            Some(entry) => SearchEntry::construct(entry),
            None => return Ok(None),
        };

        let user_dn = entry.dn;
        if user_dn.is_empty() {
            return Ok(None);
        }

        let bind = timeout(ldap_timeout, ldap.simple_bind(&user_dn, password)).await??;
        if bind.success().is_err() {
            return Ok(None);
        }

        timeout(
            ldap_timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.bind_password),
        )
        .await??
        .success()?;

        let escaped_user_dn = ldap_escape_filter_value(&user_dn);
        let escaped_username = ldap_escape_filter_value(username);
        let group_filter = self
            .config
            .group_filter
            .replace("{user_dn}", escaped_user_dn.as_str())
            .replace("{username}", escaped_username.as_str());
        let (groups, _res) = timeout(
            ldap_timeout,
            ldap.search(
                &self.config.group_base_dn,
                Scope::Subtree,
                &group_filter,
                vec![self.config.group_attr.as_str()],
            ),
        )
        .await??
        .success()?;

        let mut out = Vec::new();
        for entry in groups {
            let entry = SearchEntry::construct(entry);
            if let Some(values) = entry.attrs.get(&self.config.group_attr) {
                for v in values {
                    out.push(v.clone());
                }
            }
        }
        Ok(Some(out))
    }
}

pub(super) fn ldap_escape_filter_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ if ch.is_control() => {
                let mut buf = [0u8; 4];
                for byte in ch.encode_utf8(&mut buf).as_bytes() {
                    let _ = write!(&mut out, "\\{:02x}", byte);
                }
            }
            _ => out.push(ch),
        }
    }
    out
}
