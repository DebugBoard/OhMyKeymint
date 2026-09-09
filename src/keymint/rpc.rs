//
// Copyright (C) 2022 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Emulated implementation of device traits for `IRemotelyProvisionedComponent`.

use core::cell::RefCell;
use kmr_common::crypto::{ec, ec::CoseKeyPurpose, Ec, KeyMaterial};
use kmr_common::{
    crypto, explicit, rpc_err, vec_try, vec_try_with_capacity, Error, FallibleAllocExt,
};
use kmr_crypto_boring::{ec::BoringEc, rng::BoringRng};
use kmr_ta::device::{
    CsrSigningAlgorithm, DiceInfo, PubDiceArtifacts, RetrieveRpcArtifacts, RpcV2Req,
};
use kmr_wire::coset::{iana, CoseKey, CoseSign1Builder, HeaderBuilder};
use kmr_wire::keymint::{Digest, EcCurve};
use kmr_wire::{cbor::value::Value, coset::AsCborValue, rpc, CborError};

/// Labels of the `DiceChainEntryPayload` fields, from RFC 8392 and the Open Profile for DICE.
const LABEL_ISSUER: i64 = 1;
const LABEL_SUBJECT: i64 = 2;
const LABEL_CODE_HASH: i64 = -4670545;
const LABEL_CONFIG_HASH: i64 = -4670547;
const LABEL_CONFIG_DESC: i64 = -4670548;
const LABEL_AUTHORITY_HASH: i64 = -4670549;
const LABEL_MODE: i64 = -4670551;
const LABEL_SUBJECT_PUBLIC_KEY: i64 = -4670552;
const LABEL_KEY_USAGE: i64 = -4670553;
const LABEL_PROFILE_NAME: i64 = -4670554;

/// Labels of the `ConfigurationDescriptor` fields, from the Android Profile for DICE.
const LABEL_COMPONENT_NAME: i64 = -70002;
const LABEL_COMPONENT_VERSION: i64 = -70003;
const LABEL_SECURITY_VERSION: i64 = -70005;

/// Key usage bits which correspond to `keyCertSign` as per RFC 5280 section 4.2.1.3, in the
/// little-endian byte order used by the DICE profile.
const KEY_USAGE_CERT_SIGN: u8 = 0x20;

/// DICE mode for a stage that booted with verified boot in its normal, locked state.
const MODE_NORMAL: u8 = 1;
/// DICE mode for a stage that booted with verification disabled or the bootloader unlocked.
const MODE_DEBUG: u8 = 2;

/// Length of a DICE certificate ID, which is hex encoded into the issuer and subject fields.
const DICE_ID_LEN: usize = 20;

/// Salt used when deriving DICE certificate IDs, from the Open Profile for DICE reference
/// implementation (`kIdSalt` in `open-dice/src/dice.c`).
const DICE_ID_SALT: [u8; 64] = [
    0xDB, 0xDB, 0xAE, 0xBC, 0x80, 0x20, 0xDA, 0x9F, 0xF0, 0xDD, 0x5A, 0x24, 0xC8, 0x3A, 0xA5, 0xA5,
    0x42, 0x86, 0xDF, 0xC2, 0x63, 0x03, 0x1E, 0x32, 0x9B, 0x4D, 0xA1, 0x48, 0x43, 0x06, 0x59, 0xFE,
    0x62, 0xCD, 0xB5, 0xB7, 0xE1, 0xE0, 0x0F, 0xC6, 0x80, 0x30, 0x67, 0x11, 0xEB, 0x44, 0x4A, 0xF7,
    0x72, 0x09, 0x35, 0x94, 0x96, 0xFC, 0xFF, 0x1D, 0xB9, 0x52, 0x0B, 0xA5, 0x1C, 0x7B, 0x29, 0xEA,
];

/// Trait to encapsulate deterministic derivation of secret data.
pub trait DeriveBytes {
    /// Derive `output_len` bytes of data from `context`, deterministically.
    fn derive_bytes(&self, context: &[u8], output_len: usize) -> Result<Vec<u8>, Error>;
}

/// Boot state that the DICE chain measures. The values are the ones the device also reports in
/// the attestation `RootOfTrust`, so the DICE chain and the attestation record agree with each
/// other.
#[derive(Clone, Debug, Default)]
pub struct DiceBootInfo {
    /// Verified boot key, as reported in `RootOfTrust.verifiedBootKey`.
    pub vb_key: [u8; 32],
    /// Verified boot hash (vbmeta digest), as reported in `RootOfTrust.verifiedBootHash`.
    pub vb_hash: [u8; 32],
    /// Boot patch level, in `YYYYMMDD` form.
    pub boot_patchlevel: u32,
    /// OS patch level, in `YYYYMM` form.
    pub os_patchlevel: u32,
    /// Android major version, e.g. 16.
    pub os_version: u32,
    /// Whether the bootloader is locked and verified boot is in the `Verified` state.
    pub locked: bool,
}

/// A boot stage measured into the DICE chain. Each stage contributes one `DiceChainEntry`; the
/// last stage holds `CDI_Leaf`, the key that signs certificate requests.
struct DiceStage {
    /// Component name, and the key derivation context for the stage key.
    name: &'static str,
    /// Component version.
    version: u64,
    /// Security version, which is machine comparable and monotonically increasing.
    security_version: u64,
    /// The stage's code hash, in the 64-byte field that the Open Profile for DICE uses.
    code_hash: Vec<u8>,
}

/// Length of derived key material, for use with the `ring` HKDF interface.
struct HkdfLen(usize);

impl ring::hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Common emulated implementation of RPC artifact retrieval.
pub struct Artifacts<T: DeriveBytes> {
    derive: T,
    sign_algo: CsrSigningAlgorithm,
    boot: DiceBootInfo,
    // Invariant once populated: `self.dice_info.signing_algorithm` == `self.sign_algo`
    dice_info: RefCell<Option<DiceInfo>>,
    // Invariant once populated: `self.bcc_signing_key` is a variant that matches `self.sign_algo`
    bcc_signing_key: RefCell<Option<ec::Key>>,
}

impl<T: DeriveBytes + Send> RetrieveRpcArtifacts for Artifacts<T> {
    fn derive_bytes_from_hbk(
        &self,
        _hkdf: &dyn crypto::Hkdf,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        self.derive.derive_bytes(context, output_len)
    }

    fn get_dice_info(&self, _test_mode: rpc::TestMode) -> Result<DiceInfo, Error> {
        if self.dice_info.borrow().is_none() {
            let (dice_info, priv_key) = self.generate_dice_artifacts(rpc::TestMode(false))?;
            *self.dice_info.borrow_mut() = Some(dice_info);
            *self.bcc_signing_key.borrow_mut() = Some(priv_key);
        }

        Ok(self
            .dice_info
            .borrow()
            .as_ref()
            .ok_or_else(|| rpc_err!(Failed, "DICE artifacts are not initialized."))?
            .clone())
    }

    fn sign_data(
        &self,
        ec: &dyn crypto::Ec,
        data: &[u8],
        _rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error> {
        // DICE artifacts should have been initialized via `get_dice_info()` by the time this
        // method is called.
        let private_key = self
            .bcc_signing_key
            .borrow()
            .as_ref()
            .ok_or_else(|| rpc_err!(Failed, "DICE artifacts are not initialized."))?
            .clone();

        let mut op = ec.begin_sign(private_key.into(), self.signing_digest())?;
        op.update(data)?;
        let sig = op.finish()?;
        crypto::ec::to_cose_signature(self.signing_curve(), sig)
    }
}

impl<T: DeriveBytes + Send> Artifacts<T> {
    /// Constructor.
    pub fn new(derive: T, sign_algo: CsrSigningAlgorithm, boot: DiceBootInfo) -> Self {
        Self {
            derive,
            sign_algo,
            boot,
            dice_info: RefCell::new(None),
            bcc_signing_key: RefCell::new(None),
        }
    }

    /// Indicate the curve used in signing.
    fn signing_curve(&self) -> EcCurve {
        match self.sign_algo {
            CsrSigningAlgorithm::ES256 => EcCurve::P256,
            CsrSigningAlgorithm::ES384 => EcCurve::P384,
            CsrSigningAlgorithm::EdDSA => EcCurve::Curve25519,
        }
    }

    /// Indicate the digest used in signing.
    fn signing_digest(&self) -> Digest {
        match self.sign_algo {
            CsrSigningAlgorithm::ES256 => Digest::Sha256,
            CsrSigningAlgorithm::ES384 => Digest::Sha384,
            CsrSigningAlgorithm::EdDSA => Digest::None,
        }
    }

    /// Indicate the COSE algorithm value associated with signing.
    fn signing_cose_algo(&self) -> iana::Algorithm {
        match self.sign_algo {
            CsrSigningAlgorithm::ES256 => iana::Algorithm::ES256,
            CsrSigningAlgorithm::ES384 => iana::Algorithm::ES384,
            CsrSigningAlgorithm::EdDSA => iana::Algorithm::EdDSA,
        }
    }

    /// Indicate the version of the Android Profile for DICE that the chain follows. Profile names
    /// were introduced with the profile that aligns with Android 14.
    fn profile_name(&self) -> Option<&'static str> {
        match self.boot.os_version {
            0..=13 => None,
            14 => Some("android.14"),
            15 => Some("android.15"),
            _ => Some("android.16"),
        }
    }

    /// Indicate the DICE mode of the boot stages.
    fn mode(&self) -> u8 {
        if self.boot.locked {
            MODE_NORMAL
        } else {
            MODE_DEBUG
        }
    }

    /// Describe the boot stages that the DICE chain measures, from the stage that the bootloader
    /// runs in, down to the KeyMint stage that owns `CDI_Leaf`. The stage names follow the ones
    /// Android boot stages use.
    fn boot_stages(&self) -> Vec<DiceStage> {
        let boot = &self.boot;
        let boot_patchlevel = u64::from(boot.boot_patchlevel);
        let os_patchlevel = u64::from(boot.os_patchlevel);
        let os_version = u64::from(boot.os_version);
        vec![
            // The Android bootloader, measured by the stage that owns the UDS and versioned by
            // the boot patch level.
            DiceStage {
                name: "ABL",
                version: boot_patchlevel,
                security_version: boot_patchlevel,
                code_hash: measurement(
                    &[
                        b"ABL".as_slice(),
                        &boot.vb_key,
                        &boot.boot_patchlevel.to_be_bytes(),
                    ]
                    .concat(),
                ),
            },
            // Android Verified Boot, whose measurement of the OS images is the verified boot hash
            // that the attestation `RootOfTrust` also reports.
            DiceStage {
                name: "AVB",
                version: os_version,
                security_version: os_patchlevel,
                code_hash: pad_measurement(&boot.vb_hash),
            },
            // The KeyMint stage holds `CDI_Leaf`, the key that signs certificate requests.
            DiceStage {
                name: "KeyMint",
                version: os_version,
                security_version: os_patchlevel,
                code_hash: measurement(
                    &[
                        b"KeyMint".as_slice(),
                        &boot.vb_key,
                        &boot.vb_hash,
                        &boot.os_patchlevel.to_be_bytes(),
                    ]
                    .concat(),
                ),
            },
        ]
    }

    /// Generate the key pair for a boot stage, returning its public `COSE_Key` together with the
    /// private key that certifies the next stage in the chain.
    fn stage_key(
        &self,
        ec: &BoringEc,
        context: &[u8],
    ) -> Result<(CoseKey, crypto::OpaqueOr<ec::Key>), Error> {
        let key_material = match self.sign_algo {
            CsrSigningAlgorithm::EdDSA => {
                let secret = self.derive.derive_bytes(context, 32)?;
                ec::import_raw_ed25519_key(&secret)
            }
            // TODO: generate the *same* key after reboot, by use of the TPM.
            CsrSigningAlgorithm::ES256 => {
                ec.generate_nist_key(&mut BoringRng, ec::NistCurve::P256, &[])
            }
            CsrSigningAlgorithm::ES384 => {
                ec.generate_nist_key(&mut BoringRng, ec::NistCurve::P384, &[])
            }
        }?;
        match key_material {
            KeyMaterial::Ec(curve, curve_type, key) => {
                let cose_key = key.public_cose_key(
                    ec,
                    curve,
                    curve_type,
                    CoseKeyPurpose::Sign,
                    None, /* no key ID */
                    rpc::TestMode(false),
                )?;
                Ok((cose_key, key))
            }
            _ => Err(rpc_err!(
                Failed,
                "expected the Ec variant of KeyMaterial for the cdi leaf key."
            )),
        }
    }

    /// Return the raw public key material that a DICE certificate ID is derived from: the
    /// coordinates of a NIST key, or the raw public key of an Ed25519 key.
    fn raw_public_key(
        &self,
        ec: &BoringEc,
        key: &crypto::OpaqueOr<ec::Key>,
    ) -> Result<Vec<u8>, Error> {
        let pub_key = ec.subject_public_key(key)?;
        match self.sign_algo {
            CsrSigningAlgorithm::EdDSA => Ok(pub_key),
            // NIST public keys are SEC-1 uncompressed points; drop the leading 0x04 tag so that
            // only the coordinates are hashed.
            _ => Ok(pub_key
                .strip_prefix(&[0x04])
                .unwrap_or(pub_key.as_slice())
                .to_vec()),
        }
    }

    /// Build the `DiceChainEntryPayload` for `stage`, certified by the holder of `issuer`.
    fn entry_payload(
        &self,
        issuer: &str,
        subject: &str,
        stage: &DiceStage,
        subject_key: &CoseKey,
    ) -> Result<Vec<u8>, Error> {
        let subject_key_cbor = subject_key
            .clone()
            .to_cbor_value()
            .map_err(CborError::from)?;
        let subject_key_data = kmr_ta::rkp::serialize_cbor(&subject_key_cbor)?;

        // Construct `ConfigurationDescriptor`, which the configuration hash covers.
        let config_desc = Value::Map(vec_try![
            (
                Value::Integer(LABEL_COMPONENT_NAME.into()),
                Value::Text(String::from(stage.name))
            ),
            (
                Value::Integer(LABEL_COMPONENT_VERSION.into()),
                Value::Integer(stage.version.into())
            ),
            (
                Value::Integer(LABEL_SECURITY_VERSION.into()),
                Value::Integer(stage.security_version.into())
            ),
        ]?);
        let config_desc_data = kmr_ta::rkp::serialize_cbor(&config_desc)?;

        // The authority for every stage is the verified boot key, which is the key that the
        // attestation `RootOfTrust` reports as having signed the boot chain.
        let authority_hash = measurement(&[b"authority".as_slice(), &self.boot.vb_key].concat());

        let mut payload: Vec<(Value, Value)> = vec_try_with_capacity!(10)?;
        payload.try_push((
            Value::Integer(LABEL_ISSUER.into()),
            Value::Text(String::from(issuer)),
        ))?;
        payload.try_push((
            Value::Integer(LABEL_SUBJECT.into()),
            Value::Text(String::from(subject)),
        ))?;
        payload.try_push((
            Value::Integer(LABEL_CODE_HASH.into()),
            Value::Bytes(stage.code_hash.clone()),
        ))?;
        payload.try_push((
            Value::Integer(LABEL_CONFIG_DESC.into()),
            Value::Bytes(config_desc_data.clone()),
        ))?;
        payload.try_push((
            Value::Integer(LABEL_CONFIG_HASH.into()),
            Value::Bytes(sha512(&config_desc_data)),
        ))?;
        payload.try_push((
            Value::Integer(LABEL_AUTHORITY_HASH.into()),
            Value::Bytes(authority_hash),
        ))?;
        payload.try_push((
            Value::Integer(LABEL_MODE.into()),
            Value::Bytes(vec_try![self.mode()]?),
        ))?;
        payload.try_push((
            Value::Integer(LABEL_SUBJECT_PUBLIC_KEY.into()),
            Value::Bytes(subject_key_data),
        ))?;
        payload.try_push((
            Value::Integer(LABEL_KEY_USAGE.into()),
            Value::Bytes(vec_try![KEY_USAGE_CERT_SIGN]?),
        ))?;
        if let Some(profile_name) = self.profile_name() {
            payload.try_push((
                Value::Integer(LABEL_PROFILE_NAME.into()),
                Value::Text(String::from(profile_name)),
            ))?;
        }

        kmr_ta::rkp::serialize_cbor(&Value::Map(payload))
    }

    /// Generate the DICE chain: `UDS_Pub` followed by one `DiceChainEntry` per boot stage, each
    /// signed by the key of the stage before it. The private key of the last stage is returned,
    /// as it is `CDI_Leaf` and signs certificate requests.
    fn generate_dice_artifacts(
        &self,
        _test_mode: rpc::TestMode,
    ) -> Result<(DiceInfo, ec::Key), Error> {
        let ec = BoringEc::default();
        let protected = HeaderBuilder::new()
            .algorithm(self.signing_cose_algo())
            .build();

        // `UDS_Pub` is the root of the chain and is not itself certified.
        let (uds_key, mut issuer_key) = self.stage_key(&ec, b"UDS Key Seed")?;
        let mut issuer_id = dice_id(&self.raw_public_key(&ec, &issuer_key)?)?;
        let uds_key_cbor = uds_key.to_cbor_value().map_err(CborError::from)?;
        let mut dice_cert_chain = vec_try![uds_key_cbor]?;

        let stages = self.boot_stages();
        let last = stages.len() - 1;
        for (idx, stage) in stages.iter().enumerate() {
            // The last stage keeps the key derivation context that earlier releases used for the
            // leaf key, so that `CDI_Leaf` is unchanged.
            let (subject_key, subject_priv_key) = if idx == last {
                self.stage_key(&ec, b"Device Key Seed")?
            } else {
                self.stage_key(&ec, format!("CDI Key Seed: {}", stage.name).as_bytes())?
            };
            let subject_id = dice_id(&self.raw_public_key(&ec, &subject_priv_key)?)?;

            let payload = self.entry_payload(&issuer_id, &subject_id, stage, &subject_key)?;
            let entry = CoseSign1Builder::new()
                .protected(protected.clone())
                .payload(payload)
                .try_create_signature(&[], |input| {
                    let mut op = ec.begin_sign(issuer_key.clone(), self.signing_digest())?;
                    op.update(input)?;
                    let sig = op.finish()?;
                    crypto::ec::to_cose_signature(self.signing_curve(), sig)
                })?
                .build();
            dice_cert_chain.try_push(entry.to_cbor_value().map_err(CborError::from)?)?;

            issuer_key = subject_priv_key;
            issuer_id = subject_id;
        }

        // Construct `DiceCertChain`
        let dice_cert_chain_data = kmr_ta::rkp::serialize_cbor(&Value::Array(dice_cert_chain))?;

        // Construct `UdsCerts` as an empty CBOR map
        let uds_certs_data = kmr_ta::rkp::serialize_cbor(&Value::Map(Vec::new()))?;

        let pub_dice_artifacts = PubDiceArtifacts {
            dice_cert_chain: dice_cert_chain_data,
            uds_certs: uds_certs_data,
        };

        let dice_info = DiceInfo {
            pub_dice_artifacts,
            signing_algorithm: self.sign_algo,
            rpc_v2_test_cdi_priv: None,
        };

        Ok((dice_info, explicit!(issuer_key)?))
    }
}

/// Derive the DICE certificate ID of a public key, hex encoded as it appears in the issuer and
/// subject fields of a chain entry. Matches `DiceDeriveCdiCertificateId` in the Open Profile for
/// DICE reference implementation.
fn dice_id(pub_key: &[u8]) -> Result<String, Error> {
    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA512, &DICE_ID_SALT).extract(pub_key);
    let info = [b"ID".as_slice()];
    let okm = prk
        .expand(&info, HkdfLen(DICE_ID_LEN))
        .map_err(|_e| rpc_err!(Failed, "failed to derive DICE certificate id."))?;
    let mut id = [0u8; DICE_ID_LEN];
    okm.fill(&mut id)
        .map_err(|_e| rpc_err!(Failed, "failed to derive DICE certificate id."))?;
    // Clear the top bit to keep the ID positive, as the reference implementation does.
    id[0] &= !0x80;
    Ok(hex::encode(id))
}

/// Return the SHA-512 digest of `data`, which is how the Open Profile for DICE hashes the
/// configuration descriptor.
fn sha512(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA512, data)
        .as_ref()
        .to_vec()
}

/// Measure `data` the way Android boot stages do: a SHA-256 digest, carried in the 64-byte hash
/// field that the Open Profile for DICE reference implementation defines.
fn measurement(data: &[u8]) -> Vec<u8> {
    pad_measurement(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

/// Place a digest in the 64-byte DICE hash field, zero padded as the reference implementation
/// leaves the unused trailing bytes.
fn pad_measurement(digest: &[u8]) -> Vec<u8> {
    let mut hash = vec![0u8; 64];
    let len = core::cmp::min(digest.len(), hash.len());
    hash[..len].copy_from_slice(&digest[..len]);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_wire::read_to_value;

    /// Deterministic stand-in for derivation from a hardware-backed key.
    struct FakeDerive;

    impl DeriveBytes for FakeDerive {
        fn derive_bytes(&self, context: &[u8], output_len: usize) -> Result<Vec<u8>, Error> {
            let mut out = Vec::new();
            let mut block = sha512(context);
            while out.len() < output_len {
                out.extend_from_slice(&block);
                block = sha512(&block);
            }
            out.truncate(output_len);
            Ok(out)
        }
    }

    fn artifacts() -> Artifacts<FakeDerive> {
        Artifacts::new(
            FakeDerive,
            CsrSigningAlgorithm::EdDSA,
            DiceBootInfo {
                vb_key: [0x11; 32],
                vb_hash: [0x22; 32],
                boot_patchlevel: 20250605,
                os_patchlevel: 202506,
                os_version: 16,
                locked: true,
            },
        )
    }

    fn field(payload: &[(Value, Value)], label: i64) -> Value {
        payload
            .iter()
            .find(|(key, _value)| key == &Value::Integer(label.into()))
            .unwrap_or_else(|| panic!("missing field {label} in DiceChainEntryPayload"))
            .1
            .clone()
    }

    fn payload_of(entry: &Value) -> Vec<(Value, Value)> {
        let Value::Array(entry) = entry else {
            panic!("DiceChainEntry is not a COSE_Sign1 array");
        };
        let Value::Bytes(payload) = &entry[2] else {
            panic!("DiceChainEntry has no payload");
        };
        match read_to_value(payload).expect("failed to parse DiceChainEntryPayload") {
            Value::Map(payload) => payload,
            _ => panic!("DiceChainEntryPayload is not a map"),
        }
    }

    #[test]
    fn dice_chain_has_an_entry_per_boot_stage() {
        let dice_info = artifacts()
            .get_dice_info(rpc::TestMode(false))
            .expect("failed to generate DICE info");
        let chain = read_to_value(&dice_info.pub_dice_artifacts.dice_cert_chain)
            .expect("failed to parse DiceCertChain");
        let Value::Array(chain) = chain else {
            panic!("DiceCertChain is not an array");
        };
        // `UDS_Pub`, followed by one entry per boot stage.
        assert_eq!(chain.len(), 4);

        let mut issuer: Option<Value> = None;
        for entry in chain.iter().skip(1) {
            let payload = payload_of(entry);
            if let Some(issuer) = issuer {
                assert_eq!(field(&payload, LABEL_ISSUER), issuer);
            }
            assert_eq!(
                field(&payload, LABEL_PROFILE_NAME),
                Value::Text(String::from("android.16"))
            );
            assert_eq!(
                field(&payload, LABEL_KEY_USAGE),
                Value::Bytes(vec![KEY_USAGE_CERT_SIGN])
            );
            assert_eq!(field(&payload, LABEL_MODE), Value::Bytes(vec![MODE_NORMAL]));

            let Value::Bytes(code_hash) = field(&payload, LABEL_CODE_HASH) else {
                panic!("code hash is not a byte string");
            };
            let Value::Bytes(authority_hash) = field(&payload, LABEL_AUTHORITY_HASH) else {
                panic!("authority hash is not a byte string");
            };
            let Value::Bytes(config_desc) = field(&payload, LABEL_CONFIG_DESC) else {
                panic!("configuration descriptor is not a byte string");
            };
            assert_eq!(code_hash.len(), 64);
            assert_eq!(authority_hash.len(), 64);
            assert_eq!(
                field(&payload, LABEL_CONFIG_HASH),
                Value::Bytes(sha512(&config_desc))
            );

            issuer = Some(field(&payload, LABEL_SUBJECT));
        }

        // The chain is not degenerate: the leaf key is not the root key.
        let leaf_key = field(&payload_of(&chain[3]), LABEL_SUBJECT_PUBLIC_KEY);
        let uds_key = Value::Bytes(
            kmr_ta::rkp::serialize_cbor(&chain[0]).expect("failed to serialize UDS_Pub"),
        );
        assert_ne!(leaf_key, uds_key);
    }

    #[test]
    fn dice_chain_reports_debug_mode_when_unlocked() {
        let artifacts = Artifacts::new(
            FakeDerive,
            CsrSigningAlgorithm::EdDSA,
            DiceBootInfo {
                locked: false,
                ..Default::default()
            },
        );
        let dice_info = artifacts
            .get_dice_info(rpc::TestMode(false))
            .expect("failed to generate DICE info");
        let chain = read_to_value(&dice_info.pub_dice_artifacts.dice_cert_chain)
            .expect("failed to parse DiceCertChain");
        let Value::Array(chain) = chain else {
            panic!("DiceCertChain is not an array");
        };
        for entry in chain.iter().skip(1) {
            assert_eq!(
                field(&payload_of(entry), LABEL_MODE),
                Value::Bytes(vec![MODE_DEBUG])
            );
        }
    }
}
