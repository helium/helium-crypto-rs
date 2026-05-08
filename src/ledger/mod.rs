//! Ledger hardware-wallet backend (Solana app).
//!
//! Constructs a [`Keypair`] backed by a Ledger device running the official
//! [Solana app]. The private key never leaves the device; signing is done
//! over USB-HID.
//!
//! Two on-device signing operations are exposed:
//! - [`Keypair::sign_solana_tx`] — `SIGN_MESSAGE` (INS 0x06). Signs serialized
//!   Solana [`solana_sdk::message::VersionedMessage`] bytes.
//! - [`Keypair::sign_offchain_envelope`] — `SIGN_OFFCHAIN_MESSAGE` (INS 0x07).
//!   Signs a fully-serialized sRFC-38 off-chain message envelope.
//!
//! The crate's [`crate::keypair::Sign`] trait is implemented but always
//! errors. The Solana app's `SIGN_MESSAGE` first tries to parse bytes
//! as a Solana transaction; with "Allow blind signing" enabled in app
//! settings it will fall through to signing arbitrary bytes, but the
//! user only sees a SHA-256 hash with no semantic context. Routing
//! generic byte signing through that path silently is unsafe, so this
//! backend forces callers to pick the right APDU explicitly via the
//! methods above.
//!
//! [Solana app]: https://github.com/LedgerHQ/app-solana

use crate::{ed25519, keypair, public_key, KeyTag, KeyType, Network, Result};
#[cfg(feature = "solana")]
use std::convert::TryFrom;
#[cfg(feature = "solana")]
use std::convert::TryInto;
use thiserror::Error;

/// SLIP-44 coin type for Solana.
const COIN_TYPE_SOLANA: u32 = 501;

/// BIP32 hardened-bit mask. Solana / ed25519 derivation requires every
/// component to have this bit set.
const HARDENED: u32 = 0x8000_0000;

/// Solana app caps derivation paths at 5 levels; we cap at the same.
const MAX_PATH_DEPTH: usize = 5;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ledger transport error: {0}")]
    Transport(String),
    #[error("ledger app: {0}")]
    Apdu(ApduStatus),
    #[error("invalid derivation path: {0}")]
    Path(String),
    #[error("device returned unexpected payload length {got}, expected {expected}")]
    PayloadLength { got: usize, expected: usize },
    #[error("device returned signature that does not verify against the cached public key")]
    SignatureMismatch,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

/// APDU status code returned by the Solana app. Known codes have human-
/// readable [`std::fmt::Display`] output; unknown codes still display as
/// hex so users can diagnose firmware/version mismatches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApduStatus {
    /// 0x5515 — BOLOS dashboard reports the device is locked.
    DeviceLocked,
    /// 0x6d02 — no app is open (BOLOS dashboard active).
    NoAppOpen,
    /// 0x6a80 — Solana app could not parse the message bytes.
    InvalidSolanaMessage,
    /// 0x6a81 — sRFC-38 off-chain header was malformed.
    InvalidOffchainHeader,
    /// 0x6a82 — sRFC-38 format byte and body content disagree.
    InvalidOffchainFormat,
    /// 0x6a83 — sRFC-38 declared body length is invalid.
    InvalidOffchainSize,
    /// 0x6700 — APDU body length did not match P3.
    IncorrectApduLength,
    /// 0x6982 — security status not satisfied (ISO 7816).
    SecurityStatusNotSatisfied,
    /// 0x6985 — user cancelled on the device.
    UserCancelled,
    /// 0x6b00 — invalid P1/P2 byte.
    InvalidApduP1P2,
    /// 0x6d00 — wrong app open, or a Solana app version that doesn't
    /// implement the requested INS.
    InstructionNotSupported,
    /// 0x6e00 — wrong app open (different CLA).
    WrongAppOpen,
    /// 0x6f00 — generic device error.
    DeviceError,
    /// Any other status returned by the device.
    Unknown(u16),
}

impl ApduStatus {
    pub fn from_code(code: u16) -> Self {
        match code {
            0x5515 => Self::DeviceLocked,
            0x6d02 => Self::NoAppOpen,
            0x6a80 => Self::InvalidSolanaMessage,
            0x6a81 => Self::InvalidOffchainHeader,
            0x6a82 => Self::InvalidOffchainFormat,
            0x6a83 => Self::InvalidOffchainSize,
            0x6700 => Self::IncorrectApduLength,
            0x6982 => Self::SecurityStatusNotSatisfied,
            0x6985 => Self::UserCancelled,
            0x6b00 => Self::InvalidApduP1P2,
            0x6d00 => Self::InstructionNotSupported,
            0x6e00 => Self::WrongAppOpen,
            0x6f00 => Self::DeviceError,
            other => Self::Unknown(other),
        }
    }

    pub fn code(&self) -> u16 {
        match self {
            Self::DeviceLocked => 0x5515,
            Self::NoAppOpen => 0x6d02,
            Self::InvalidSolanaMessage => 0x6a80,
            Self::InvalidOffchainHeader => 0x6a81,
            Self::InvalidOffchainFormat => 0x6a82,
            Self::InvalidOffchainSize => 0x6a83,
            Self::IncorrectApduLength => 0x6700,
            Self::SecurityStatusNotSatisfied => 0x6982,
            Self::UserCancelled => 0x6985,
            Self::InvalidApduP1P2 => 0x6b00,
            Self::InstructionNotSupported => 0x6d00,
            Self::WrongAppOpen => 0x6e00,
            Self::DeviceError => 0x6f00,
            Self::Unknown(c) => *c,
        }
    }

    fn label(&self) -> Option<&'static str> {
        let s = match self {
            Self::DeviceLocked => "device is locked — unlock with PIN",
            Self::NoAppOpen => "no app open — launch the Solana app on the device",
            Self::InvalidSolanaMessage => "invalid Solana message",
            Self::InvalidOffchainHeader => "invalid off-chain message header",
            Self::InvalidOffchainFormat => "invalid off-chain message format",
            Self::InvalidOffchainSize => "invalid off-chain message size",
            Self::IncorrectApduLength => "incorrect APDU length",
            Self::SecurityStatusNotSatisfied => "security status not satisfied",
            Self::UserCancelled => "operation cancelled on device",
            Self::InvalidApduP1P2 => "invalid APDU P1/P2",
            Self::InstructionNotSupported => {
                "instruction not supported — wrong app open, or update the Solana app"
            }
            Self::WrongAppOpen => "wrong app open — switch to the Solana app on the device",
            Self::DeviceError => "device error",
            Self::Unknown(_) => return None,
        };
        Some(s)
    }
}

impl std::fmt::Display for ApduStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = self.code();
        match self.label() {
            Some(label) => write!(f, "{label} — status 0x{code:04x}"),
            None => write!(f, "status 0x{code:04x}"),
        }
    }
}

/// A BIP32 derivation path. All components are stored with the hardened
/// bit ([`HARDENED`]) set; non-hardened input is rejected at construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath {
    components: Vec<u32>,
}

impl DerivationPath {
    /// Build a path from raw component values. Each component must already
    /// have the hardened bit set; otherwise returns [`Error::Path`]. Path
    /// depth is capped at [`MAX_PATH_DEPTH`].
    pub fn new(components: impl IntoIterator<Item = u32>) -> Result<Self> {
        let components: Vec<u32> = components.into_iter().collect();
        if components.is_empty() {
            return Err(Error::Path("path must have at least one component".into()).into());
        }
        if components.len() > MAX_PATH_DEPTH {
            return Err(Error::Path(format!(
                "path has {} components; max is {MAX_PATH_DEPTH}",
                components.len()
            ))
            .into());
        }
        if let Some(c) = components.iter().find(|c| *c & HARDENED == 0) {
            return Err(Error::Path(format!(
                "component 0x{c:08x} is not hardened (Solana ed25519 derivation requires all components hardened)"
            ))
            .into());
        }
        Ok(Self { components })
    }

    /// Standard Solana-ecosystem path: `m/44'/501'/<account>'/<change>'`.
    /// Matches Phantom, Solflare, Backpack, and Ledger Live defaults.
    pub fn solana(account: u32, change: u32) -> Self {
        Self::from_unhardened([44, COIN_TYPE_SOLANA, account, change])
            .expect("4-component path is within MAX_PATH_DEPTH")
    }

    /// Solana CLI 3-level path: `m/44'/501'/<account>'`.
    pub fn solana_cli(account: u32) -> Self {
        Self::from_unhardened([44, COIN_TYPE_SOLANA, account])
            .expect("3-component path is within MAX_PATH_DEPTH")
    }

    /// Build from raw indices, OR-ing on the hardened bit. Internal helper
    /// for the well-known constructors above; not exposed because callers
    /// should be explicit about hardening at the API boundary.
    fn from_unhardened(components: impl IntoIterator<Item = u32>) -> Result<Self> {
        Self::new(components.into_iter().map(|c| c | HARDENED))
    }

    /// Encode as APDU payload: `<count: u8> <component: u32 BE> ...`.
    pub(crate) fn to_apdu_bytes(&self) -> Vec<u8> {
        std::iter::once(self.components.len() as u8)
            .chain(self.components.iter().flat_map(|c| c.to_be_bytes()))
            .collect()
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("m")?;
        for c in &self.components {
            write!(f, "/{}'", c & !HARDENED)?;
        }
        Ok(())
    }
}

/// Callback invoked when a sign call is about to send bytes the on-device
/// parser will not be able to clear-sign — i.e. the device falls through
/// to its blind-sign confirmation, where the only thing the user sees is
/// a SHA-256 of the signed bytes. The hook receives that same hash so the
/// caller can surface it to the user (UI, log, etc.) and they can compare
/// against the device screen. Install via [`Keypair::with_blind_sign_hook`].
pub type BlindSignHook = Box<dyn Fn(&[u8; 32]) + Send + Sync>;

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    path: DerivationPath,
    serial: Option<String>,
    blind_sign_hook: Option<BlindSignHook>,
}

impl PartialEq for Keypair {
    /// Equality ignores [`BlindSignHook`] — two keypairs at the same path on
    /// the same device are equal regardless of which (if any) UI hook is
    /// attached.
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network
            && self.public_key == other.public_key
            && self.path == other.path
            && self.serial == other.serial
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("tag", &self.key_tag())
            .field("path", &self.path.to_string())
            .field("serial", &self.serial)
            .field("public", &self.public_key)
            .field("blind_sign_hook", &self.blind_sign_hook.is_some())
            .finish()
    }
}

impl Keypair {
    /// Open the Ledger Solana app at the given derivation path and read back
    /// the public key into a cached [`Keypair`]. Pass `serial = Some("...")`
    /// to disambiguate when multiple Ledgers are connected; `None` opens
    /// whichever device the transport library selects.
    ///
    /// The pubkey is fetched without on-device confirmation. Every
    /// subsequent call to [`Keypair::sign_solana_tx`] /
    /// [`Keypair::sign_offchain_envelope`] verifies the device-returned
    /// signature against this cached key, so a device swap or stale cache
    /// surfaces as [`Error::SignatureMismatch`] rather than a silently
    /// wrong signature.
    ///
    /// **Trust note:** until the first sign call completes, the cached
    /// `public_key` carries only USB-HID-transport trust — a compromised
    /// transport could return any pubkey here. Callers that need a user-
    /// confirmed address before signing (e.g. to display "send to this
    /// address" UI) should not rely on this value as authenticated until
    /// at least one signature has been verified against it.
    pub fn from_derivation_path(
        network: Network,
        path: DerivationPath,
        serial: Option<&str>,
    ) -> Result<Self> {
        let pk_bytes = transport::get_pubkey(serial, &path)?;
        let pk = ed25519::PublicKey(ed25519_compact::PublicKey::new(pk_bytes));
        Ok(Self {
            network,
            public_key: public_key::PublicKey::for_network(network, pk),
            path,
            serial: serial.map(String::from),
            blind_sign_hook: None,
        })
    }

    /// Install a callback invoked whenever a sign call is about to require
    /// on-device blind-signing. The callback receives the SHA-256 the device
    /// will display, letting the caller render it (UI prompt, log, …) so
    /// the user can compare against the device screen. Without a hook,
    /// blind-sign attempts proceed silently — callers can still pre-flight
    /// with [`requires_blind_sign`] if they need to gate UI before signing.
    pub fn with_blind_sign_hook<F>(mut self, hook: F) -> Self
    where
        F: Fn(&[u8; 32]) + Send + Sync + 'static,
    {
        self.blind_sign_hook = Some(Box::new(hook));
        self
    }

    /// Convenience: open at the standard Solana path `m/44'/501'/<account>'/<change>'`.
    pub fn solana(
        network: Network,
        account: u32,
        change: u32,
        serial: Option<&str>,
    ) -> Result<Self> {
        Self::from_derivation_path(network, DerivationPath::solana(account, change), serial)
    }

    /// USB serial of the device this keypair was opened against, if a serial
    /// filter was supplied at construction time.
    pub fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: KeyType::Ed25519,
        }
    }

    pub fn derivation_path(&self) -> &DerivationPath {
        &self.path
    }

    /// Sign a serialized Solana [`solana_sdk::message::VersionedMessage`]
    /// using `SIGN_MESSAGE` (INS 0x06). For any instruction the on-device
    /// parser does not recognise, the user must have "Allow blind signing"
    /// enabled in the Solana app settings; the device then displays only
    /// a SHA-256 hash for confirmation. If a [`BlindSignHook`] is installed
    /// (via [`Keypair::with_blind_sign_hook`]) it fires with that hash
    /// before the APDU is sent, so callers can surface it for comparison.
    ///
    /// The returned signature is verified against the cached public key
    /// before returning; a mismatch surfaces as [`Error::SignatureMismatch`].
    pub fn sign_solana_tx(&self, serialized_message: &[u8]) -> Result<[u8; 64]> {
        #[cfg(feature = "solana")]
        if let Some(hook) = self.blind_sign_hook.as_ref() {
            if requires_blind_sign(serialized_message) {
                hook(&sha256(serialized_message));
            }
        }
        let bytes =
            transport::sign_message(self.serial.as_deref(), &self.path, serialized_message)?;
        self.verify_signature(serialized_message, &bytes)?;
        Ok(bytes)
    }

    /// Sign a pre-formed sRFC-38 off-chain message envelope using
    /// `SIGN_OFFCHAIN_MESSAGE` (INS 0x07). Callers are responsible for
    /// envelope construction.
    ///
    /// The returned signature is verified against the cached public key
    /// before returning; a mismatch surfaces as [`Error::SignatureMismatch`].
    /// Note that the device's blind-sign confirmation screen displays a
    /// SHA-256 of the message *body* (the bytes after the sRFC-38 header,
    /// not the full envelope). Callers that want to display the same hash
    /// to the user must compute it from the body slice themselves.
    pub fn sign_offchain_envelope(&self, envelope: &[u8]) -> Result<[u8; 64]> {
        let bytes = transport::sign_offchain_message(self.serial.as_deref(), &self.path, envelope)?;
        self.verify_signature(envelope, &bytes)?;
        Ok(bytes)
    }

    fn verify_signature(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        use public_key::Verify;
        self.public_key
            .verify(message, signature)
            .map_err(|_| Error::SignatureMismatch.into())
    }
}

impl keypair::Sign for Keypair {
    /// **Not supported on the Ledger backend.** The Solana app's
    /// `SIGN_MESSAGE` will sign arbitrary bytes when blind-signing is
    /// enabled, but the user only sees a SHA-256 hash with no semantic
    /// context — silently routing through that path is unsafe. Callers
    /// must select an explicit signing path:
    /// - [`Keypair::sign_solana_tx`] for serialized
    ///   [`solana_sdk::message::VersionedMessage`]s.
    /// - [`Keypair::sign_offchain_envelope`] for pre-formed sRFC-38
    ///   off-chain messages.
    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "raw Sign::sign is not supported on Ledger; use sign_solana_tx or sign_offchain_envelope",
        )
        .into())
    }
}

/// Implements the Solana SDK `Signer` trait. `try_sign_message` routes
/// through `SIGN_MESSAGE` (INS 0x06); callers must pass serialized
/// [`solana_sdk::message::VersionedMessage`] bytes. For arbitrary off-chain
/// bytes, use [`Keypair::sign_offchain_envelope`] explicitly.
#[cfg(feature = "solana")]
impl solana_sdk::signer::Signer for Keypair {
    fn try_pubkey(
        &self,
    ) -> std::result::Result<solana_sdk::pubkey::Pubkey, solana_sdk::signer::SignerError> {
        solana_sdk::pubkey::Pubkey::try_from(self.public_key.clone()).map_err(into_signer_error)
    }

    fn try_sign_message(
        &self,
        message: &[u8],
    ) -> std::result::Result<solana_sdk::signature::Signature, solana_sdk::signer::SignerError>
    {
        let bytes = self.sign_solana_tx(message).map_err(into_signer_error)?;
        Ok(solana_sdk::signature::Signature::from(bytes))
    }

    fn is_interactive(&self) -> bool {
        true
    }
}

#[cfg(feature = "solana")]
fn into_signer_error(e: impl std::fmt::Display) -> solana_sdk::signer::SignerError {
    solana_sdk::signer::SignerError::Custom(e.to_string())
}

/// SHA-256 helper; the device's blind-sign screen displays this same hash
/// over the bytes passed to `SIGN_MESSAGE`.
#[cfg(feature = "solana")]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Returns true when the serialized message contains at least one
/// instruction targeting a program the Solana Ledger app does *not*
/// clear-sign — i.e. the device falls through to blind-sign, where the
/// only thing the user sees is a SHA-256 of the message bytes.
///
/// The whitelist is conservative: a false negative (claiming clear-sign
/// when the device actually blind-signs) silently skips verification, so
/// any parse error or unknown program flips this to true.
#[cfg(feature = "solana")]
pub fn requires_blind_sign(message: &[u8]) -> bool {
    use solana_sdk::pubkey;
    use solana_sdk::pubkey::Pubkey;

    const CLEAR_SIGN_PROGRAMS: &[Pubkey] = &[
        pubkey!("11111111111111111111111111111111"), // System
        pubkey!("ComputeBudget111111111111111111111111111111"),
        pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"), // SPL Token
        pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"), // SPL Token-2022
        pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"), // SPL ATA
    ];

    match parse_program_ids(message) {
        Some(ids) => ids
            .into_iter()
            .any(|id| !CLEAR_SIGN_PROGRAMS.contains(&Pubkey::new_from_array(id))),
        None => true,
    }
}

/// Parse just enough of a serialized [`solana_sdk::message::VersionedMessage`]
/// to extract every instruction's program ID (resolved against the static
/// account-keys list, since program IDs cannot come from address-lookup
/// tables). Returns `None` on any malformed or truncated input — callers
/// should treat that as "blind-sign required" rather than silently trust.
#[cfg(feature = "solana")]
fn parse_program_ids(message: &[u8]) -> Option<Vec<[u8; 32]>> {
    let mut cursor: usize = 0;
    // V0 messages start with a 0x80 version marker; legacy messages omit
    // it and begin directly with the message header.
    if *message.first()? == 0x80 {
        cursor += 1;
    }

    // Header: num_required_signatures, num_readonly_signed, num_readonly_unsigned.
    cursor = cursor.checked_add(3)?;
    if message.len() < cursor {
        return None;
    }

    // Static account keys: compact-u16 length + N * 32 bytes.
    let (key_count, n) = read_compact_u16(message.get(cursor..)?)?;
    cursor = cursor.checked_add(n)?;
    let keys_start = cursor;
    cursor = cursor.checked_add((key_count as usize).checked_mul(32)?)?;
    if message.len() < cursor {
        return None;
    }

    // Recent blockhash.
    cursor = cursor.checked_add(32)?;
    if message.len() < cursor {
        return None;
    }

    // Instructions: compact-u16 length + N instructions.
    let (ix_count, n) = read_compact_u16(message.get(cursor..)?)?;
    cursor = cursor.checked_add(n)?;

    let mut program_ids = Vec::with_capacity(ix_count as usize);
    for _ in 0..ix_count {
        let program_id_index = *message.get(cursor)? as usize;
        cursor = cursor.checked_add(1)?;

        // Reject out-of-bounds program-id indices explicitly: without this,
        // a malformed message could read 32 bytes from the recent blockhash
        // or instruction body and coincidentally match a whitelisted
        // program, defeating the fail-safe.
        if program_id_index >= key_count as usize {
            return None;
        }

        // Accounts: compact-u16 length + N bytes (one byte per account index).
        let (acct_count, n) = read_compact_u16(message.get(cursor..)?)?;
        cursor = cursor.checked_add(n)?.checked_add(acct_count as usize)?;

        // Instruction data: compact-u16 length + N bytes.
        let (data_len, n) = read_compact_u16(message.get(cursor..)?)?;
        cursor = cursor.checked_add(n)?.checked_add(data_len as usize)?;

        if message.len() < cursor {
            return None;
        }

        let key_offset = keys_start + program_id_index * 32;
        let key_bytes: [u8; 32] = message.get(key_offset..key_offset + 32)?.try_into().ok()?;
        program_ids.push(key_bytes);
    }

    Some(program_ids)
}

/// Compact-u16 (Solana shortvec) decoder. 1–3 bytes; each byte carries 7
/// data bits and a continuation flag. Rejects overlong encodings (3-byte
/// forms with the high byte == 0 or > 3) per the shortvec spec.
#[cfg(feature = "solana")]
fn read_compact_u16(buf: &[u8]) -> Option<(u16, usize)> {
    let b1 = *buf.first()?;
    if b1 & 0x80 == 0 {
        return Some((b1 as u16, 1));
    }
    let b2 = *buf.get(1)?;
    if b2 & 0x80 == 0 {
        // 2-byte form must encode a value that doesn't fit in 1 byte.
        if b2 == 0 {
            return None;
        }
        return Some(((b1 as u16 & 0x7f) | ((b2 as u16) << 7), 2));
    }
    let b3 = *buf.get(2)?;
    // 3-byte form: top byte holds bits 14-15 only; b3 must be 1..=3.
    if b3 == 0 || b3 > 3 {
        return None;
    }
    let value = (b1 as u16 & 0x7f) | ((b2 as u16 & 0x7f) << 7) | ((b3 as u16) << 14);
    Some((value, 3))
}

/// Summary of a connected Ledger device returned by [`list_devices`].
#[derive(Clone, Debug, serde::Serialize)]
pub struct DeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
}

/// Enumerate every Ledger device hidapi can see. Use this to discover the
/// USB serial of a specific device when more than one is attached, or to
/// confirm a serial is being exposed at all (some Ledger device/firmware
/// combinations report `None`).
pub fn list_devices() -> Result<Vec<DeviceInfo>> {
    use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
    let api = HidApi::new().map_err(|e| Error::Transport(e.to_string()))?;
    Ok(TransportNativeHID::list_ledgers(&api)
        .map(|d| DeviceInfo {
            vendor_id: d.vendor_id(),
            product_id: d.product_id(),
            manufacturer: d.manufacturer_string().map(String::from),
            product: d.product_string().map(String::from),
            serial: d.serial_number().map(String::from),
        })
        .collect())
}

/// USB-HID transport to the Solana app.
///
/// APDU framing follows the canonical Agave `solana-remote-wallet` reference:
/// - First chunk of a multi-APDU sign request carries `[num_signers=1]
///   [path_len][path components, big-endian u32 each][message bytes...]`.
/// - Continuation chunks carry only further message bytes, with `P2_EXTEND`
///   set; intermediate chunks add `P2_MORE`. The final APDU clears `P2_MORE`
///   to signal end of input.
/// - Max single-APDU body = 255 bytes.
mod transport {
    use super::{ApduStatus, DerivationPath, Error};
    use ledger_apdu::APDUCommand;
    use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
    use std::sync::Mutex;

    const CLA: u8 = 0xe0;
    const INS_GET_PUBKEY: u8 = 0x05;
    const INS_SIGN_MESSAGE: u8 = 0x06;
    const INS_SIGN_OFFCHAIN_MESSAGE: u8 = 0x07;
    const P1_NON_CONFIRM: u8 = 0x00;
    const P1_CONFIRM: u8 = 0x01;
    const P2_EXTEND: u8 = 0x01;
    const P2_MORE: u8 = 0x02;
    const MAX_CHUNK_SIZE: usize = 255;
    const APDU_SUCCESS: u16 = 0x9000;
    const PUBKEY_LEN: usize = 32;
    const SIGNATURE_LEN: usize = 64;

    /// Process-global, lazily-opened handle to a single Ledger device. Held
    /// for the lifetime of the process — reopening on every call is expensive
    /// and risks the hidapi double-open lockup. The cached entry tracks which
    /// USB serial it was opened with so subsequent calls in the same process
    /// can reject mismatches rather than silently using the wrong device.
    static TRANSPORT: Mutex<Option<(Option<String>, TransportNativeHID)>> = Mutex::new(None);

    fn with_transport<F, R>(serial: Option<&str>, f: F) -> super::Result<R>
    where
        F: FnOnce(&TransportNativeHID) -> super::Result<R>,
    {
        // A poisoned mutex means a panic occurred while another caller held
        // the guard. The cached transport may be mid-APDU or otherwise in
        // an unknown state, so discard it defensively and let the next
        // call reopen — better than locking every subsequent call out
        // forever or reusing a possibly-inconsistent handle.
        let mut guard = TRANSPORT.lock().unwrap_or_else(|poisoned| {
            let mut g = poisoned.into_inner();
            *g = None;
            g
        });
        if let Some((cached_serial, _)) = guard.as_ref() {
            if cached_serial.as_deref() != serial {
                return Err(Error::Transport(format!(
                    "ledger already opened with serial {cached_serial:?}; \
                     cannot reopen with serial {serial:?} in the same process"
                ))
                .into());
            }
        } else {
            let api = HidApi::new().map_err(|e| Error::Transport(e.to_string()))?;
            let transport = open_device(&api, serial)?;
            *guard = Some((serial.map(String::from), transport));
        }
        f(&guard.as_ref().expect("transport just initialized").1)
    }

    fn open_device(api: &HidApi, serial: Option<&str>) -> super::Result<TransportNativeHID> {
        match serial {
            None => {
                TransportNativeHID::new(api).map_err(|e| Error::Transport(e.to_string()).into())
            }
            Some(want) => {
                let device = TransportNativeHID::list_ledgers(api)
                    .find(|d| d.serial_number() == Some(want))
                    .ok_or_else(|| {
                        Error::Transport(format!(
                            "no Ledger device with serial '{want}' is connected"
                        ))
                    })?;
                TransportNativeHID::open_device(api, device)
                    .map_err(|e| Error::Transport(e.to_string()).into())
            }
        }
    }

    fn exchange(
        transport: &TransportNativeHID,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> super::Result<Vec<u8>> {
        let cmd = APDUCommand {
            cla: CLA,
            ins,
            p1,
            p2,
            data,
        };
        let answer = transport
            .exchange(&cmd)
            .map_err(|e| Error::Transport(e.to_string()))?;
        let retcode = answer.retcode();
        if retcode != APDU_SUCCESS {
            return Err(Error::Apdu(ApduStatus::from_code(retcode)).into());
        }
        Ok(answer.data().to_vec())
    }

    pub(super) fn get_pubkey(
        serial: Option<&str>,
        path: &DerivationPath,
    ) -> super::Result<[u8; PUBKEY_LEN]> {
        with_transport(serial, |t| {
            let resp = exchange(
                t,
                INS_GET_PUBKEY,
                P1_NON_CONFIRM,
                0x00,
                &path.to_apdu_bytes(),
            )?;
            if resp.len() != PUBKEY_LEN {
                return Err(Error::PayloadLength {
                    got: resp.len(),
                    expected: PUBKEY_LEN,
                }
                .into());
            }
            let mut out = [0u8; PUBKEY_LEN];
            out.copy_from_slice(&resp);
            Ok(out)
        })
    }

    /// Plan the (p2, chunk) pairs for a chunked sign APDU. Pure helper so
    /// the framing logic can be exercised without a device. The caller is
    /// expected to send each pair in order.
    fn plan_chunks(payload: &[u8]) -> Vec<(u8, &[u8])> {
        if payload.is_empty() {
            return vec![(0, payload)];
        }
        let mut chunks = Vec::with_capacity(payload.len().div_ceil(MAX_CHUNK_SIZE));
        let mut remaining = payload;
        let mut p2 = 0u8;
        while remaining.len() > MAX_CHUNK_SIZE {
            let (chunk, rest) = remaining.split_at(MAX_CHUNK_SIZE);
            chunks.push((p2 | P2_MORE, chunk));
            remaining = rest;
            p2 = P2_EXTEND;
        }
        chunks.push((p2, remaining));
        chunks
    }

    /// Send a chunked sign request. The first chunk carries the path-prefixed
    /// payload; continuations carry only further bytes. The 64-byte ed25519
    /// signature is read from the final APDU response.
    fn sign_chunked(
        serial: Option<&str>,
        ins: u8,
        payload: &[u8],
    ) -> super::Result<[u8; SIGNATURE_LEN]> {
        with_transport(serial, |t| {
            let plan = plan_chunks(payload);
            let last_idx = plan.len() - 1;
            let mut final_data: Option<Vec<u8>> = None;
            for (i, (p2, chunk)) in plan.into_iter().enumerate() {
                let resp = exchange(t, ins, P1_CONFIRM, p2, chunk)?;
                if i == last_idx {
                    final_data = Some(resp);
                } else if !resp.is_empty() {
                    return Err(Error::Transport(format!(
                        "device returned {} unexpected bytes on intermediate sign chunk",
                        resp.len()
                    ))
                    .into());
                }
            }
            let final_data = final_data.expect("plan_chunks always produces at least one chunk");
            if final_data.len() != SIGNATURE_LEN {
                return Err(Error::PayloadLength {
                    got: final_data.len(),
                    expected: SIGNATURE_LEN,
                }
                .into());
            }
            let mut out = [0u8; SIGNATURE_LEN];
            out.copy_from_slice(&final_data);
            Ok(out)
        })
    }

    /// Build the path-prefixed payload and dispatch to `sign_chunked` for
    /// either INS_SIGN_MESSAGE or INS_SIGN_OFFCHAIN_MESSAGE.
    fn sign_with_path(
        serial: Option<&str>,
        ins: u8,
        path: &DerivationPath,
        body: &[u8],
    ) -> super::Result<[u8; SIGNATURE_LEN]> {
        let path_bytes = path.to_apdu_bytes();
        let mut payload = Vec::with_capacity(1 + path_bytes.len() + body.len());
        payload.push(1u8); // num_signers — firmware rejects anything other than 1
        payload.extend_from_slice(&path_bytes);
        payload.extend_from_slice(body);
        sign_chunked(serial, ins, &payload)
    }

    pub(super) fn sign_message(
        serial: Option<&str>,
        path: &DerivationPath,
        serialized_message: &[u8],
    ) -> super::Result<[u8; SIGNATURE_LEN]> {
        sign_with_path(serial, INS_SIGN_MESSAGE, path, serialized_message)
    }

    /// Send a `SIGN_OFFCHAIN_MESSAGE` APDU. `envelope` is the fully-
    /// serialized sRFC-38 off-chain message (domain + version + format +
    /// signers + length + body); the firmware reads the format byte from
    /// the envelope itself.
    pub(super) fn sign_offchain_message(
        serial: Option<&str>,
        path: &DerivationPath,
        envelope: &[u8],
    ) -> super::Result<[u8; SIGNATURE_LEN]> {
        sign_with_path(serial, INS_SIGN_OFFCHAIN_MESSAGE, path, envelope)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn plan_chunks_empty() {
            let plan = plan_chunks(&[]);
            assert_eq!(plan.len(), 1);
            assert_eq!(plan[0].0, 0);
            assert!(plan[0].1.is_empty());
        }

        #[test]
        fn plan_chunks_single_byte() {
            let plan = plan_chunks(&[0xab]);
            assert_eq!(plan.len(), 1);
            assert_eq!(plan[0].0, 0);
            assert_eq!(plan[0].1, &[0xab]);
        }

        #[test]
        fn plan_chunks_exact_max() {
            let payload = vec![0u8; MAX_CHUNK_SIZE];
            let plan = plan_chunks(&payload);
            assert_eq!(plan.len(), 1);
            assert_eq!(plan[0].0, 0);
            assert_eq!(plan[0].1.len(), MAX_CHUNK_SIZE);
        }

        #[test]
        fn plan_chunks_two_chunks() {
            let payload = vec![0u8; MAX_CHUNK_SIZE + 1];
            let plan = plan_chunks(&payload);
            assert_eq!(plan.len(), 2);
            assert_eq!(plan[0].0, P2_MORE);
            assert_eq!(plan[0].1.len(), MAX_CHUNK_SIZE);
            assert_eq!(plan[1].0, P2_EXTEND);
            assert_eq!(plan[1].1.len(), 1);
        }

        #[test]
        fn plan_chunks_three_chunks() {
            let payload = vec![0u8; 2 * MAX_CHUNK_SIZE + 1];
            let plan = plan_chunks(&payload);
            assert_eq!(plan.len(), 3);
            assert_eq!(plan[0].0, P2_MORE);
            assert_eq!(plan[1].0, P2_EXTEND | P2_MORE);
            assert_eq!(plan[2].0, P2_EXTEND);
            assert_eq!(plan[2].1.len(), 1);
        }

        #[test]
        fn plan_chunks_two_exact() {
            let payload = vec![0u8; 2 * MAX_CHUNK_SIZE];
            let plan = plan_chunks(&payload);
            assert_eq!(plan.len(), 2);
            assert_eq!(plan[0].0, P2_MORE);
            assert_eq!(plan[1].0, P2_EXTEND);
            assert_eq!(plan[1].1.len(), MAX_CHUNK_SIZE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "solana")]
    #[test]
    fn requires_blind_sign_for_unknown_program() {
        use solana_sdk::instruction::{AccountMeta, Instruction};
        use solana_sdk::message::{v0, VersionedMessage};
        use solana_sdk::pubkey::Pubkey;
        let payer = Pubkey::new_unique();
        // A made-up program ID — definitely not in the clear-sign whitelist.
        let anchor_like = Pubkey::new_unique();
        let ix = Instruction::new_with_bytes(
            anchor_like,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            vec![AccountMeta::new(payer, true)],
        );
        let msg = VersionedMessage::V0(
            v0::Message::try_compile(&payer, &[ix], &[], Default::default()).unwrap(),
        );
        assert!(requires_blind_sign(&msg.serialize()));
    }

    #[cfg(feature = "solana")]
    #[test]
    fn does_not_require_blind_sign_for_sol_transfer() {
        use solana_sdk::message::{v0, VersionedMessage};
        use solana_sdk::pubkey::Pubkey;
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let ix = solana_sdk::system_instruction::transfer(&from, &to, 1000);
        let msg = VersionedMessage::V0(
            v0::Message::try_compile(&from, &[ix], &[], Default::default()).unwrap(),
        );
        assert!(!requires_blind_sign(&msg.serialize()));
    }

    #[cfg(feature = "solana")]
    #[test]
    fn requires_blind_sign_for_mixed_instructions() {
        use solana_sdk::instruction::{AccountMeta, Instruction};
        use solana_sdk::message::{v0, VersionedMessage};
        use solana_sdk::pubkey::Pubkey;
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let unknown_program = Pubkey::new_unique();
        let transfer = solana_sdk::system_instruction::transfer(&from, &to, 1000);
        let unknown =
            Instruction::new_with_bytes(unknown_program, &[], vec![AccountMeta::new(from, true)]);
        let msg = VersionedMessage::V0(
            v0::Message::try_compile(&from, &[transfer, unknown], &[], Default::default()).unwrap(),
        );
        assert!(requires_blind_sign(&msg.serialize()));
    }

    #[cfg(feature = "solana")]
    #[test]
    fn requires_blind_sign_on_garbage_input() {
        // Any parse failure should fail safe — print the hash rather than
        // silently skip verification.
        assert!(requires_blind_sign(&[]));
        assert!(requires_blind_sign(&[0x80]));
        assert!(requires_blind_sign(&[0xff; 4]));
    }

    #[cfg(feature = "solana")]
    #[test]
    fn parse_program_ids_rejects_oob_index() {
        // Hand-build a minimal V0 message where a single instruction has
        // a program_id_index past the static-keys array.
        let mut msg = vec![0x80]; // V0 marker
        msg.extend_from_slice(&[1, 0, 0]); // header: 1 sig, 0 ro signed, 0 ro unsigned
        msg.push(1); // 1 static key
        msg.extend_from_slice(&[0u8; 32]); // the one key
        msg.extend_from_slice(&[0u8; 32]); // recent blockhash
        msg.push(1); // 1 instruction
        msg.push(99); // program_id_index = 99 (oob — only 1 key)
        msg.push(0); // 0 accounts
        msg.push(0); // 0 data bytes
                     // No address-lookup-table entries needed — V0 omits trailing bytes.
        assert!(parse_program_ids(&msg).is_none());
        assert!(requires_blind_sign(&msg));
    }

    #[cfg(feature = "solana")]
    #[test]
    fn compact_u16_branches() {
        // 1-byte: 0..=0x7f
        assert_eq!(read_compact_u16(&[0x00]), Some((0, 1)));
        assert_eq!(read_compact_u16(&[0x7f]), Some((0x7f, 1)));
        // 2-byte: 0x80..=0x3fff
        assert_eq!(read_compact_u16(&[0x80, 0x01]), Some((0x80, 2)));
        assert_eq!(read_compact_u16(&[0xff, 0x7f]), Some((0x3fff, 2)));
        // 3-byte: 0x4000..=0xffff
        assert_eq!(read_compact_u16(&[0x80, 0x80, 0x01]), Some((0x4000, 3)));
        assert_eq!(read_compact_u16(&[0xff, 0xff, 0x03]), Some((0xffff, 3)));
    }

    #[cfg(feature = "solana")]
    #[test]
    fn compact_u16_truncated() {
        assert_eq!(read_compact_u16(&[]), None);
        assert_eq!(read_compact_u16(&[0x80]), None);
        assert_eq!(read_compact_u16(&[0x80, 0x80]), None);
    }

    #[cfg(feature = "solana")]
    #[test]
    fn compact_u16_rejects_overlong() {
        // 3-byte form with high byte == 0 (could be encoded in 2 bytes).
        assert_eq!(read_compact_u16(&[0x80, 0x80, 0x00]), None);
        // 3-byte form with high byte > 3 (would overflow u16).
        assert_eq!(read_compact_u16(&[0x80, 0x80, 0x04]), None);
        assert_eq!(read_compact_u16(&[0xff, 0xff, 0xff]), None);
        // 2-byte form with second byte == 0 (could be encoded in 1 byte).
        assert_eq!(read_compact_u16(&[0x80, 0x00]), None);
    }

    #[test]
    fn apdu_error_messages() {
        assert_eq!(
            Error::Apdu(ApduStatus::from_code(0x6e00)).to_string(),
            "ledger app: wrong app open — switch to the Solana app on the device — status 0x6e00",
        );
        assert_eq!(
            Error::Apdu(ApduStatus::from_code(0x5515)).to_string(),
            "ledger app: device is locked — unlock with PIN — status 0x5515",
        );
        assert_eq!(
            Error::Apdu(ApduStatus::from_code(0x6d02)).to_string(),
            "ledger app: no app open — launch the Solana app on the device — status 0x6d02",
        );
        assert_eq!(
            Error::Apdu(ApduStatus::from_code(0x6985)).to_string(),
            "ledger app: operation cancelled on device — status 0x6985",
        );
        assert_eq!(
            Error::Apdu(ApduStatus::from_code(0x6a82)).to_string(),
            "ledger app: invalid off-chain message format — status 0x6a82",
        );
        assert_eq!(
            Error::Apdu(ApduStatus::from_code(0x6982)).to_string(),
            "ledger app: security status not satisfied — status 0x6982",
        );
        // Unknown code: hex only, no spurious dash.
        assert_eq!(
            Error::Apdu(ApduStatus::from_code(0x1234)).to_string(),
            "ledger app: status 0x1234",
        );
    }

    #[test]
    fn apdu_status_roundtrip() {
        for code in [0x5515u16, 0x6d02, 0x6a82, 0x6985, 0x6e00, 0x9999] {
            assert_eq!(ApduStatus::from_code(code).code(), code);
        }
    }

    #[cfg(feature = "solana")]
    #[test]
    fn sha256_matches_ref() {
        // Pin the helper so a hook caller can rely on the hash being
        // SHA-256 of the input bytes (same as the device's display).
        let h = sha256(b"hello");
        // Known SHA-256 of "hello".
        let expected =
            hex_literal::hex!("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(h, expected);
    }

    #[test]
    fn derivation_path_apdu_encoding() {
        let path = DerivationPath::solana(0, 0);
        let bytes = path.to_apdu_bytes();
        // 1-byte count + 4 components * 4 bytes each
        assert_eq!(bytes.len(), 1 + 4 * 4);
        assert_eq!(bytes[0], 4);
        // first component: 44' = 0x8000002c
        assert_eq!(&bytes[1..5], &[0x80, 0x00, 0x00, 0x2c]);
        // second component: 501' = 0x800001f5
        assert_eq!(&bytes[5..9], &[0x80, 0x00, 0x01, 0xf5]);
    }

    #[test]
    fn derivation_path_display() {
        assert_eq!(DerivationPath::solana(0, 0).to_string(), "m/44'/501'/0'/0'",);
        assert_eq!(DerivationPath::solana_cli(3).to_string(), "m/44'/501'/3'");
    }

    #[test]
    fn derivation_path_rejects_unhardened() {
        let err = DerivationPath::new([44]).unwrap_err();
        assert!(err.to_string().contains("not hardened"));
    }

    #[test]
    fn derivation_path_rejects_too_long() {
        let err =
            DerivationPath::new(std::iter::repeat_n(HARDENED | 1, MAX_PATH_DEPTH + 1)).unwrap_err();
        assert!(err.to_string().contains("max is"));
    }

    #[test]
    fn derivation_path_rejects_empty() {
        assert!(DerivationPath::new(std::iter::empty()).is_err());
    }

    #[test]
    fn derivation_path_accepts_hardened() {
        let path = DerivationPath::new([HARDENED | 44, HARDENED | 501]).unwrap();
        assert_eq!(path.to_string(), "m/44'/501'");
    }
}
