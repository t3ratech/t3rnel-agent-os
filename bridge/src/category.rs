//! Policy categories (`05-security-and-trust.md` §11): one filter for requests, connector submissions and listings.
//! Prohibited work is rejected automatically with reason codes; restricted work needs an admin's written authorisation
//! that expires and is tied to one version; everything else runs through the automated pipeline.
//!
//! Classification works on declared tags. A submission that declares none cannot be classified and is refused
//! (fail closed); deciding which tags a free-text request deserves is the AI review's job, and the tags it produces
//! come through here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tag {
    // prohibited
    PrescriptionWrite,
    VehicleControl,
    Weapons,
    CriticalInfrastructure,
    CryptoWallet,
    CovertMonitoring,
    CredentialHarvesting,
    CaptchaEvasion,
    BulkUnsolicitedMessaging,
    IdentityForgery,
    // restricted
    Banking,
    TradingTerminal,
    HealthcareRead,
    PayrollHr,
    GovernmentPortal,
    SocialPosting,
    // unrestricted
    Wavepay,
    Media,
    Editor,
    Ide,
    Office,
    Files,
    Browser,
    BusinessMessagingApi,
    Crm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Unrestricted,
    Restricted,
    Prohibited,
}

impl Tag {
    pub fn class(self) -> Class {
        use Tag::*;
        match self {
            PrescriptionWrite
            | VehicleControl
            | Weapons
            | CriticalInfrastructure
            | CryptoWallet
            | CovertMonitoring
            | CredentialHarvesting
            | CaptchaEvasion
            | BulkUnsolicitedMessaging
            | IdentityForgery => Class::Prohibited,
            Banking | TradingTerminal | HealthcareRead | PayrollHr | GovernmentPortal
            | SocialPosting => Class::Restricted,
            Wavepay | Media | Editor | Ide | Office | Files | Browser | BusinessMessagingApi
            | Crm => Class::Unrestricted,
        }
    }

    /// The stable reason code shown to the submitter and recorded in the audit.
    pub fn reason_code(self) -> &'static str {
        use Tag::*;
        match self {
            PrescriptionWrite => "PROHIBITED_PRESCRIPTION_WRITE",
            VehicleControl => "PROHIBITED_VEHICLE_CONTROL",
            Weapons => "PROHIBITED_WEAPONS",
            CriticalInfrastructure => "PROHIBITED_CRITICAL_INFRASTRUCTURE",
            CryptoWallet => "PROHIBITED_CRYPTO_WALLET",
            CovertMonitoring => "PROHIBITED_COVERT_MONITORING",
            CredentialHarvesting => "PROHIBITED_CREDENTIAL_HARVESTING",
            CaptchaEvasion => "PROHIBITED_CAPTCHA_EVASION",
            BulkUnsolicitedMessaging => "PROHIBITED_BULK_UNSOLICITED_MESSAGING",
            IdentityForgery => "PROHIBITED_IDENTITY_FORGERY",
            Banking => "RESTRICTED_BANKING",
            TradingTerminal => "RESTRICTED_TRADING_TERMINAL",
            HealthcareRead => "RESTRICTED_HEALTHCARE_READ",
            PayrollHr => "RESTRICTED_PAYROLL_HR",
            GovernmentPortal => "RESTRICTED_GOVERNMENT_PORTAL",
            SocialPosting => "RESTRICTED_SOCIAL_POSTING",
            Wavepay | Media | Editor | Ide | Office | Files | Browser | BusinessMessagingApi
            | Crm => "UNRESTRICTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub class: Class,
    /// Reason codes of every tag that is not unrestricted, in tag order. Empty for an unrestricted verdict.
    pub reasons: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CategoryError {
    #[error(
        "no tags declared: a submission that declares nothing cannot be classified and is refused"
    )]
    Unclassified,
}

/// The most severe tag decides. All reasons at that severity are reported, so the submitter sees every ground at once.
pub fn classify(tags: &[Tag]) -> Result<Verdict, CategoryError> {
    let class = tags
        .iter()
        .map(|t| t.class())
        .max()
        .ok_or(CategoryError::Unclassified)?;
    let mut reasons: Vec<&'static str> = Vec::new();
    let mut sorted: Vec<Tag> = tags.to_vec();
    sorted.sort();
    sorted.dedup();
    for tag in sorted {
        if tag.class() == class && class != Class::Unrestricted {
            reasons.push(tag.reason_code());
        }
    }
    Ok(Verdict { class, reasons })
}

/// An admin's written authorisation of a restricted connector or request, for one version and for a limited time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorisation {
    pub subject: String,
    pub version: String,
    pub granted_by: String,
    /// What the connector may and may not do. Must be written out; an empty list authorises nothing.
    pub conditions: Vec<String>,
    pub expires_at: u64,
}

impl Authorisation {
    /// Valid for exactly the reviewed version, while unexpired, and only with written conditions and a named admin.
    pub fn covers(&self, subject: &str, version: &str, now: u64) -> bool {
        self.subject == subject
            && self.version == version
            && self.expires_at > now
            && !self.granted_by.trim().is_empty()
            && self.conditions.iter().any(|c| !c.trim().is_empty())
    }
}

/// May this submission be built and listed now? Prohibited: never. Restricted: only with a covering authorisation.
pub fn may_list(
    verdict: &Verdict,
    authorisation: Option<&Authorisation>,
    subject: &str,
    version: &str,
    now: u64,
) -> bool {
    match verdict.class {
        Class::Unrestricted => true,
        Class::Restricted => authorisation.is_some_and(|a| a.covers(subject, version, now)),
        Class::Prohibited => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Tag::*;

    fn auth() -> Authorisation {
        Authorisation {
            subject: "org.t3rnel.mt5-bridge".into(),
            version: "1.0.0".into(),
            granted_by: "admin-1".into(),
            conditions: vec!["no deposits, withdrawals or transfers".into()],
            expires_at: 2_000,
        }
    }

    #[test]
    fn nothing_declared_is_refused_not_waved_through() {
        assert_eq!(classify(&[]), Err(CategoryError::Unclassified));
    }

    #[test]
    fn the_most_severe_tag_decides_and_all_grounds_at_that_level_are_reported() {
        let v = classify(&[Media, Banking, CryptoWallet, CredentialHarvesting]).unwrap();
        assert_eq!(v.class, Class::Prohibited);
        assert_eq!(
            v.reasons,
            vec![
                "PROHIBITED_CRYPTO_WALLET",
                "PROHIBITED_CREDENTIAL_HARVESTING"
            ]
        );
    }

    #[test]
    fn restricted_and_unrestricted_verdicts() {
        let restricted = classify(&[Editor, TradingTerminal]).unwrap();
        assert_eq!(
            (restricted.class, restricted.reasons),
            (Class::Restricted, vec!["RESTRICTED_TRADING_TERMINAL"])
        );
        let free = classify(&[Media, Files, Wavepay]).unwrap();
        assert_eq!((free.class, free.reasons), (Class::Unrestricted, vec![]));
    }

    #[test]
    fn duplicate_tags_do_not_duplicate_reasons() {
        assert_eq!(
            classify(&[Weapons, Weapons]).unwrap().reasons,
            vec!["PROHIBITED_WEAPONS"]
        );
    }

    #[test]
    fn every_tag_has_a_distinct_reason_code_matching_its_class() {
        let all = [
            PrescriptionWrite,
            VehicleControl,
            Weapons,
            CriticalInfrastructure,
            CryptoWallet,
            CovertMonitoring,
            CredentialHarvesting,
            CaptchaEvasion,
            BulkUnsolicitedMessaging,
            IdentityForgery,
            Banking,
            TradingTerminal,
            HealthcareRead,
            PayrollHr,
            GovernmentPortal,
            SocialPosting,
        ];
        let mut codes = std::collections::BTreeSet::new();
        for tag in all {
            assert!(
                codes.insert(tag.reason_code()),
                "{tag:?} reuses a reason code"
            );
            let prefix = if tag.class() == Class::Prohibited {
                "PROHIBITED_"
            } else {
                "RESTRICTED_"
            };
            assert!(tag.reason_code().starts_with(prefix), "{tag:?}");
        }
        assert_eq!(codes.len(), 16);
    }

    #[test]
    fn the_prohibited_list_matches_the_specification() {
        // Truth rule 1: the specification's prohibited examples are pinned to the tags that implement them.
        let doc = crate::spec_section("05-security-and-trust.md");
        let text = std::fs::read_to_string(doc).unwrap();
        let row = text
            .lines()
            .find(|l| l.starts_with("| **Prohibited**"))
            .expect("prohibited row");
        let documented = row.split('|').nth(2).unwrap().split(';').count();
        let coded = [
            PrescriptionWrite,
            VehicleControl,
            Weapons,
            CriticalInfrastructure,
            CryptoWallet,
            CovertMonitoring,
            CredentialHarvesting,
            CaptchaEvasion,
            BulkUnsolicitedMessaging,
            IdentityForgery,
        ]
        .iter()
        .filter(|t| t.class() == Class::Prohibited)
        .count();
        assert_eq!(
            coded, documented,
            "the document lists {documented} prohibited kinds, the code has {coded} tags"
        );
    }

    #[test]
    fn prohibited_is_never_listable_even_with_an_authorisation() {
        let v = classify(&[CryptoWallet]).unwrap();
        assert!(!may_list(
            &v,
            Some(&auth()),
            "org.t3rnel.mt5-bridge",
            "1.0.0",
            1_000
        ));
    }

    #[test]
    fn restricted_needs_a_covering_unexpired_authorisation_for_this_version() {
        let v = classify(&[TradingTerminal]).unwrap();
        let id = "org.t3rnel.mt5-bridge";
        assert!(!may_list(&v, None, id, "1.0.0", 1_000));
        assert!(may_list(&v, Some(&auth()), id, "1.0.0", 1_000));
        assert!(
            !may_list(&v, Some(&auth()), id, "1.0.1", 1_000),
            "every new version is re-reviewed"
        );
        assert!(!may_list(
            &v,
            Some(&auth()),
            "org.other.thing",
            "1.0.0",
            1_000
        ));
        assert!(!may_list(&v, Some(&auth()), id, "1.0.0", 2_000), "expired");
    }

    #[test]
    fn an_authorisation_without_written_conditions_or_a_named_admin_covers_nothing() {
        let v = classify(&[Banking]).unwrap();
        let id = "org.t3rnel.mt5-bridge";
        let no_conditions = Authorisation {
            conditions: vec![" ".into()],
            ..auth()
        };
        let none_at_all = Authorisation {
            conditions: vec![],
            ..auth()
        };
        let nameless = Authorisation {
            granted_by: "".into(),
            ..auth()
        };
        for a in [no_conditions, none_at_all, nameless] {
            assert!(!may_list(&v, Some(&a), id, "1.0.0", 1_000));
        }
    }

    #[test]
    fn unrestricted_work_lists_without_an_authorisation() {
        assert!(may_list(
            &classify(&[Media]).unwrap(),
            None,
            "x",
            "1.0.0",
            0
        ));
    }

    #[test]
    fn tags_round_trip_through_json_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&BulkUnsolicitedMessaging).unwrap(),
            "\"bulk_unsolicited_messaging\""
        );
        assert_eq!(
            serde_json::from_str::<Tag>("\"payroll_hr\"").unwrap(),
            PayrollHr
        );
        assert!(serde_json::from_str::<Tag>("\"nope\"").is_err());
    }
}
