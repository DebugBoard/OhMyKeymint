use kmr_common::consts::{AID_APP_START, AID_SHELL, AID_USER_OFFSET};

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

/// Whether `uid` is exactly the `shell` UID (2000) and `allow_shell_caller` is
/// enabled, i.e. it is admitted regardless of package identity.
///
/// Deliberately does NOT cover `root` (UID 0): that UID belongs to `vold`,
/// `init`, and other system daemons whose keystore traffic — CE-storage unlock
/// in particular — must reach the real System keystore, not OMK. Routing UID 0
/// to OMK leaves the device stuck at `RUNNING_LOCKED` after boot.
pub fn is_allowed_shell_caller(config: &FilterConfig, uid: u32) -> bool {
    config.allow_shell_caller && uid == AID_SHELL
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

    // Explicit opt-in for the `shell` UID (2000), which has no package identity
    // of its own. Used by `adb shell`, `rish`, and Shizuku started over ADB;
    // lets those testing paths reach OMK instead of the real System keymint.
    // Bypasses the Android-package block on purpose. `root` (UID 0) is NOT
    // covered — see `is_allowed_shell_caller`.
    if is_allowed_shell_caller(config, uid) {
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
