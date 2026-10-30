//! One release edition for the authorization publication and delivery contracts.
//!
//! The edition does not number business generations, revocations, stable grant
//! identities, migration history, or third-party protocol algorithms.

macro_rules! authorization_edition {
    ($edition:literal) => {
        /// Edition deployed and rolled back as one authorization contract set.
        pub const AUTHORIZATION_EDITION: u16 = $edition;
        pub const AUTHORIZATION_EDITION_NAME: &str = concat!("V", stringify!($edition));
        pub const AUTHORIZATION_COMPILER_VERSION: &str =
            concat!("astral-authorization-v", stringify!($edition));
        pub const AUTHORIZATION_MANIFEST_DIGEST_DOMAIN: &[u8] =
            concat!("astral-auth-manifest-v", stringify!($edition)).as_bytes();
        pub const AUTHORIZATION_SEGMENT_SEMANTIC_DOMAIN: &[u8] = concat!(
            "astral-auth-segment-seal-v",
            stringify!($edition),
            "/semantic"
        )
        .as_bytes();
        pub const AUTHORIZATION_SEGMENT_DEPENDENCY_DOMAIN: &[u8] = concat!(
            "astral-auth-segment-seal-v",
            stringify!($edition),
            "/dependency"
        )
        .as_bytes();
        pub const AUTHORIZATION_ARCHIVE_DIGEST_DOMAIN: &[u8] =
            concat!("astral-auth-archive-proof-v", stringify!($edition)).as_bytes();
        pub const AUTHORIZATION_COMPLETION_AUDIT_DOMAIN: &[u8] =
            concat!("astral-owned-completion-audit-v", stringify!($edition)).as_bytes();
        pub const AUTHORIZATION_COMPLETION_ITEMS_DOMAIN: &str =
            concat!("astral-owned-completion-item-set-v", stringify!($edition));
        pub const AUTHORIZATION_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
            concat!("astral-auth-snapshot-v", stringify!($edition)).as_bytes();
        pub const AUTHORIZATION_SEGMENT_FORMAT: &str =
            concat!("authorization_grants_json_v", stringify!($edition));
        pub const AUTHORIZATION_ORG_COMPILER_VERSION: &str =
            concat!("astral-org-authorization-v", stringify!($edition));
        pub const AUTHORIZATION_ORG_DEPENDENCY_DOMAIN: &str =
            concat!("astral-org-dependencies-v", stringify!($edition));
        pub const AUTHORIZATION_ORG_SEGMENT_DOMAIN: &str =
            concat!("astral-org-segment-v", stringify!($edition));
        pub const AUTHORIZATION_ORG_MANIFEST_DOMAIN: &str =
            concat!("astral-org-publication-v", stringify!($edition));
    };
}

authorization_edition!(6);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edition_labels_and_domains_share_the_single_release_number() {
        let edition = AUTHORIZATION_EDITION;
        assert_eq!(AUTHORIZATION_EDITION_NAME, format!("V{edition}"));
        assert_eq!(
            AUTHORIZATION_COMPILER_VERSION,
            format!("astral-authorization-v{edition}")
        );
        for (domain, expected) in [
            (
                AUTHORIZATION_MANIFEST_DIGEST_DOMAIN,
                format!("astral-auth-manifest-v{edition}"),
            ),
            (
                AUTHORIZATION_SEGMENT_SEMANTIC_DOMAIN,
                format!("astral-auth-segment-seal-v{edition}/semantic"),
            ),
            (
                AUTHORIZATION_SEGMENT_DEPENDENCY_DOMAIN,
                format!("astral-auth-segment-seal-v{edition}/dependency"),
            ),
            (
                AUTHORIZATION_ARCHIVE_DIGEST_DOMAIN,
                format!("astral-auth-archive-proof-v{edition}"),
            ),
            (
                AUTHORIZATION_COMPLETION_AUDIT_DOMAIN,
                format!("astral-owned-completion-audit-v{edition}"),
            ),
            (
                AUTHORIZATION_SNAPSHOT_DIGEST_DOMAIN,
                format!("astral-auth-snapshot-v{edition}"),
            ),
        ] {
            assert_eq!(domain, expected.as_bytes());
        }
        assert_eq!(
            AUTHORIZATION_COMPLETION_ITEMS_DOMAIN,
            format!("astral-owned-completion-item-set-v{edition}")
        );
        for (value, expected) in [
            (
                AUTHORIZATION_SEGMENT_FORMAT,
                format!("authorization_grants_json_v{edition}"),
            ),
            (
                AUTHORIZATION_ORG_COMPILER_VERSION,
                format!("astral-org-authorization-v{edition}"),
            ),
            (
                AUTHORIZATION_ORG_DEPENDENCY_DOMAIN,
                format!("astral-org-dependencies-v{edition}"),
            ),
            (
                AUTHORIZATION_ORG_SEGMENT_DOMAIN,
                format!("astral-org-segment-v{edition}"),
            ),
            (
                AUTHORIZATION_ORG_MANIFEST_DOMAIN,
                format!("astral-org-publication-v{edition}"),
            ),
        ] {
            assert_eq!(value, expected);
        }
    }
}
