use kmr_common::consts::{AID_APP_START, AID_ROOT, AID_SHELL, AID_USER_OFFSET};

use crate::config::FilterConfig;

#[derive(Debug, Clone)]
pub enum PackageResolution {
    Known(Vec<String>),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterReason {
    Disabled,
    Allowed,
    RejectedAndroidPackage,
    RejectedByDenylist,
    RejectedNotInScope,
    RejectedUnknownPackage,
}

#[derive(Debug, Clone)]
pub struct FilterDecision {
    pub allowed: bool,
    pub reason: FilterReason,
    pub packages: Vec<String>,
}

pub fn evaluate(
    scoop: &[String],
    config: &FilterConfig,
    uid: u32,
    resolution: PackageResolution,
) -> FilterDecision {
    if !config.enabled {
        return FilterDecision {
            allowed: true,
            reason: FilterReason::Disabled,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }

    // Explicit opt-in for the `shell` (2000) and `root` (0) UIDs, which have no
    // package identity of their own. Used by KeyAttestation's "Use Shizuku" mode,
    // `rish`, and `adb shell`; lets those testing paths reach OMK instead of the
    // real System keymint. Bypasses the Android-package block on purpose.
    if config.allow_shell_caller && (uid == AID_ROOT || uid == AID_SHELL) {
        return FilterDecision {
            allowed: true,
            reason: FilterReason::Allowed,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }

    if config.block_android_package && uid % AID_USER_OFFSET < AID_APP_START {
        return FilterDecision {
            allowed: false,
            reason: FilterReason::RejectedAndroidPackage,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }

    let packages = match resolution {
        PackageResolution::Known(packages) => packages,
        PackageResolution::Unknown => {
            let allowed = config.allow_unknown_package;
            return FilterDecision {
                allowed,
                reason: if allowed {
                    FilterReason::Allowed
                } else {
                    FilterReason::RejectedUnknownPackage
                },
                packages: Vec::new(),
            };
        }
    };

    let reason = if config.block_android_package
        && packages
            .iter()
            .any(|pkg| pkg == "android" || pkg.starts_with("android."))
    {
        FilterReason::RejectedAndroidPackage
    } else if packages
        .iter()
        .any(|pkg| config.deny_packages.contains(pkg))
    {
        FilterReason::RejectedByDenylist
    } else if !packages.iter().any(|pkg| scoop.contains(pkg)) {
        FilterReason::RejectedNotInScope
    } else {
        FilterReason::Allowed
    };

    FilterDecision {
        allowed: reason == FilterReason::Allowed,
        reason,
        packages,
    }
}

#[cfg(test)]
mod tests;
