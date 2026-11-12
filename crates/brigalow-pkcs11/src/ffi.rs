//! PKCS#11 v2.40 ABI. Callers must supply valid, aligned buffers of stated length.
//! Unsafe code is confined here: checked pointer/length conversion and output copies.
#![allow(non_snake_case, clippy::missing_safety_doc, clippy::too_many_arguments)]
use crate::remote::Remote;
use cryptoki_sys::*;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::c_void,
    sync::{Mutex, OnceLock},
};
struct Session {
    search: Option<Vec<CK_OBJECT_HANDLE>>,
    sign: Option<Operation>,
    flags: CK_FLAGS,
}
#[derive(Clone)]
enum Operation {
    DigestInfo,
    Hash(Sha256),
}
struct State {
    remote: Remote,
    sessions: BTreeMap<CK_SESSION_HANDLE, Session>,
    next: CK_SESSION_HANDLE,
}
static STATE: OnceLock<Mutex<Option<State>>> = OnceLock::new();
fn state(f: impl FnOnce(&mut State) -> CK_RV) -> CK_RV {
    let Ok(mut guard) = STATE.get_or_init(|| Mutex::new(None)).lock() else {
        return CKR_GENERAL_ERROR;
    };
    match guard.as_mut() {
        Some(s) => f(s),
        None => CKR_CRYPTOKI_NOT_INITIALIZED,
    }
}
fn padded<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [b' '; N];
    let n = s.len().min(N);
    out[..n].copy_from_slice(&s.as_bytes()[..n]);
    out
}
unsafe fn input<'a>(p: *const u8, n: CK_ULONG, max: usize) -> Result<&'a [u8], CK_RV> {
    if n as usize > max || (n > 0 && p.is_null()) {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if n == 0 {
        Ok(&[])
    } else {
        Ok(std::slice::from_raw_parts(p, n as usize))
    }
}
unsafe fn output<T: Copy>(p: *mut T, count: *mut CK_ULONG, items: &[T]) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if p.is_null() {
        *count = items.len() as CK_ULONG;
        return CKR_OK;
    }
    if *count < items.len() as CK_ULONG {
        *count = items.len() as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(items.as_ptr(), p, items.len());
    *count = items.len() as CK_ULONG;
    CKR_OK
}
#[no_mangle]
pub unsafe extern "C" fn C_Initialize(args: *mut c_void) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if !args.is_null() {
            let args = &*args.cast::<CK_C_INITIALIZE_ARGS>();
            if !args.pReserved.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            let callbacks = [
                args.CreateMutex.is_some(),
                args.DestroyMutex.is_some(),
                args.LockMutex.is_some(),
                args.UnlockMutex.is_some(),
            ];
            if callbacks.iter().any(|v| *v) && !callbacks.iter().all(|v| *v) {
                return CKR_ARGUMENTS_BAD;
            }
            // We use Rust's OS mutex, never caller-provided locking callbacks.
            if callbacks[0] && args.flags & CKF_OS_LOCKING_OK == 0 {
                return CKR_CANT_LOCK;
            }
        }
        let Ok(mut guard) = STATE.get_or_init(|| Mutex::new(None)).lock() else {
            return CKR_GENERAL_ERROR;
        };
        if guard.is_some() {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        match Remote::load() {
            Ok(remote) => {
                *guard = Some(State {
                    remote,
                    sessions: BTreeMap::new(),
                    next: 1,
                });
                CKR_OK
            }
            Err(()) => CKR_FUNCTION_FAILED,
        }
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_Finalize(reserved: *mut c_void) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if !reserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let Ok(mut guard) = STATE.get_or_init(|| Mutex::new(None)).lock() else {
            return CKR_GENERAL_ERROR;
        };
        if guard.take().is_some() {
            CKR_OK
        } else {
            CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(out: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        *out = std::ptr::addr_of!(FUNCTIONS).cast_mut();
        CKR_OK
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_GetInfo(out: *mut CK_INFO) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        state(|_| {
            *out = CK_INFO {
                cryptokiVersion: CK_VERSION {
                    major: 2,
                    minor: 40,
                },
                manufacturerID: padded("Brigalow"),
                flags: 0,
                libraryDescription: padded("Brigalow digest client"),
                libraryVersion: CK_VERSION { major: 0, minor: 1 },
            };
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_GetSlotList(
    _present: CK_BBOOL,
    out: *mut CK_SLOT_ID,
    count: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state(|_| output(out, count, &[1]))
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_GetSlotInfo(slot: CK_SLOT_ID, out: *mut CK_SLOT_INFO) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if slot != 1 {
            return CKR_SLOT_ID_INVALID;
        }
        state(|_| {
            *out = CK_SLOT_INFO {
                slotDescription: padded("Brigalow policy-bound signing"),
                manufacturerID: padded("Brigalow"),
                flags: CKF_TOKEN_PRESENT,
                hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                firmwareVersion: CK_VERSION { major: 0, minor: 1 },
            };
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_GetTokenInfo(slot: CK_SLOT_ID, out: *mut CK_TOKEN_INFO) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if slot != 1 {
            return CKR_SLOT_ID_INVALID;
        }
        state(|s| {
            *out = CK_TOKEN_INFO {
                label: padded("Brigalow"),
                manufacturerID: padded("Brigalow"),
                model: padded(match s.remote.key.trust {
                    brigalow_core::TrustTier::Lab => "lab",
                    brigalow_core::TrustTier::Private => "private",
                    brigalow_core::TrustTier::ExternalCa => "external-ca",
                    brigalow_core::TrustTier::Untrusted => "untrusted",
                }),
                serialNumber: padded(&s.remote.key.key.id.to_string()),
                flags: CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED,
                ulMaxSessionCount: 64,
                ulSessionCount: s.sessions.len() as CK_ULONG,
                ulMaxRwSessionCount: 64,
                ulRwSessionCount: s.sessions.len() as CK_ULONG,
                ulMaxPinLen: 0,
                ulMinPinLen: 0,
                ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
                ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
                ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
                ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
                hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                firmwareVersion: CK_VERSION { major: 0, minor: 1 },
                utcTime: [b' '; 16],
            };
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismList(
    slot: CK_SLOT_ID,
    out: *mut CK_MECHANISM_TYPE,
    count: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if slot != 1 {
            return CKR_SLOT_ID_INVALID;
        }
        state(|_| output(out, count, &[CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS]))
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slot: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    out: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if slot != 1 {
            return CKR_SLOT_ID_INVALID;
        }
        if ![CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS].contains(&mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        state(|_| {
            *out = CK_MECHANISM_INFO {
                ulMinKeySize: 3072,
                ulMaxKeySize: 3072,
                flags: CKF_SIGN,
            };
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_OpenSession(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _app: *mut c_void,
    _notify: CK_NOTIFY,
    out: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if slot != 1 {
            return CKR_SLOT_ID_INVALID;
        }
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        state(|s| {
            if s.sessions.len() >= 64 || s.next == CK_SESSION_HANDLE::MAX {
                return CKR_SESSION_COUNT;
            }
            let id = s.next;
            s.next += 1;
            s.sessions.insert(
                id,
                Session {
                    search: None,
                    sign: None,
                    flags,
                },
            );
            *out = id;
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state(|s| {
            if s.sessions.remove(&session).is_some() {
                CKR_OK
            } else {
                CKR_SESSION_HANDLE_INVALID
            }
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_CloseAllSessions(slot: CK_SLOT_ID) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if slot != 1 {
            return CKR_SLOT_ID_INVALID;
        }
        state(|s| {
            s.sessions.clear();
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_GetSessionInfo(
    session: CK_SESSION_HANDLE,
    out: *mut CK_SESSION_INFO,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        state(|s| {
            let Some(session) = s.sessions.get(&session) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            *out = CK_SESSION_INFO {
                slotID: 1,
                state: if session.flags & CKF_RW_SESSION != 0 {
                    CKS_RW_USER_FUNCTIONS
                } else {
                    CKS_RO_USER_FUNCTIONS
                },
                flags: session.flags,
                ulDeviceError: 0,
            };
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_Login(
    session: CK_SESSION_HANDLE,
    user: CK_USER_TYPE,
    _pin: *mut CK_UTF8CHAR,
    _len: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if user != CKU_USER {
            return CKR_USER_TYPE_INVALID;
        }
        state(|s| {
            if s.sessions.contains_key(&session) {
                CKR_OK
            } else {
                CKR_SESSION_HANDLE_INVALID
            }
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_Logout(session: CK_SESSION_HANDLE) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state(|s| {
            let Some(session) = s.sessions.get_mut(&session) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            session.sign = None;
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
fn attribute(
    remote: &Remote,
    object: CK_OBJECT_HANDLE,
    kind: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let class = match object {
        1 => CKO_PUBLIC_KEY,
        2 => CKO_PRIVATE_KEY,
        3 if !remote.key.chain.is_empty() => CKO_CERTIFICATE,
        _ => return Err(CKR_OBJECT_HANDLE_INVALID),
    };
    let boolean = |v: bool| vec![if v { CK_TRUE } else { CK_FALSE }];
    let ulong = |v: CK_ULONG| v.to_ne_bytes().to_vec();
    match kind {
        CKA_CLASS => Ok(ulong(class)),
        CKA_TOKEN => Ok(boolean(true)),
        CKA_PRIVATE => Ok(boolean(object == 2)),
        CKA_LABEL => Ok(b"brigalow".to_vec()),
        CKA_ID => Ok(remote.key.key.id.as_bytes().to_vec()),
        CKA_MODIFIABLE | CKA_COPYABLE | CKA_DESTROYABLE | CKA_EXTRACTABLE | CKA_ENCRYPT
        | CKA_DECRYPT | CKA_WRAP | CKA_UNWRAP | CKA_DERIVE | CKA_VERIFY => Ok(boolean(false)),
        CKA_SENSITIVE | CKA_ALWAYS_SENSITIVE | CKA_NEVER_EXTRACTABLE => Ok(boolean(object == 2)),
        CKA_SIGN => Ok(boolean(object == 2)),
        CKA_ALWAYS_AUTHENTICATE => Ok(boolean(false)),
        CKA_KEY_TYPE if object < 3 => Ok(ulong(CKK_RSA)),
        CKA_MODULUS_BITS if object < 3 => Ok(ulong(3072)),
        CKA_PUBLIC_KEY_INFO if object < 3 => Ok(remote.key.public_key.clone()),
        CKA_MODULUS | CKA_PUBLIC_EXPONENT if object < 3 => {
            let key = rsa::PublicKey::from_public_key_der(&remote.key.public_key)
                .map_err(|_| CKR_DEVICE_ERROR)?;
            Ok(if kind == CKA_MODULUS {
                key.n_bytes().into_vec()
            } else {
                key.e_bytes().into_vec()
            })
        }
        CKA_CERTIFICATE_TYPE if object == 3 => Ok(ulong(CKC_X_509)),
        CKA_VALUE if object == 3 => Ok(remote.key.chain[0].clone()),
        CKA_VALUE | CKA_PRIVATE_EXPONENT | CKA_PRIME_1 | CKA_PRIME_2 | CKA_EXPONENT_1
        | CKA_EXPONENT_2 | CKA_COEFFICIENT
            if object == 2 =>
        {
            Err(CKR_ATTRIBUTE_SENSITIVE)
        }
        CKA_SUBJECT | CKA_ISSUER | CKA_SERIAL_NUMBER if object == 3 => {
            use der::{Decode, Encode};
            let cert = x509_cert::Certificate::from_der(&remote.key.chain[0])
                .map_err(|_| CKR_DEVICE_ERROR)?;
            match kind {
                CKA_SUBJECT => cert.tbs_certificate.subject.to_der(),
                CKA_ISSUER => cert.tbs_certificate.issuer.to_der(),
                _ => cert.tbs_certificate.serial_number.to_der(),
            }
            .map_err(|_| CKR_DEVICE_ERROR)
        }
        _ => Err(CKR_ATTRIBUTE_TYPE_INVALID),
    }
}
#[no_mangle]
pub unsafe extern "C" fn C_GetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attrs: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if count > 64 || (count > 0 && attrs.is_null()) {
            return CKR_ARGUMENTS_BAD;
        }
        state(|s| {
            if !s.sessions.contains_key(&session) {
                return CKR_SESSION_HANDLE_INVALID;
            }
            let mut result = CKR_OK;
            for i in 0..count as usize {
                let a = &mut *attrs.add(i);
                match attribute(&s.remote, object, a.type_) {
                    Ok(value) => {
                        let r = output(a.pValue.cast::<u8>(), &mut a.ulValueLen, &value);
                        if r != CKR_OK {
                            result = r;
                        }
                    }
                    Err(e) => {
                        a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        result = e;
                    }
                }
            }
            result
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsInit(
    session: CK_SESSION_HANDLE,
    attrs: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if count > 64 || (count > 0 && attrs.is_null()) {
            return CKR_ARGUMENTS_BAD;
        }
        state(|s| {
            let Some(session) = s.sessions.get_mut(&session) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            if session.search.is_some() {
                return CKR_OPERATION_ACTIVE;
            }
            let mut found = vec![];
            for object in 1..=if s.remote.key.chain.is_empty() { 2 } else { 3 } {
                let mut matches = true;
                for i in 0..count as usize {
                    let a = &*attrs.add(i);
                    let value = match input(a.pValue.cast(), a.ulValueLen, 65536) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if attribute(&s.remote, object, a.type_).map_or(true, |v| v != value) {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    found.push(object);
                }
            }
            session.search = Some(found);
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_FindObjects(
    session: CK_SESSION_HANDLE,
    out: *mut CK_OBJECT_HANDLE,
    max: CK_ULONG,
    count: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if count.is_null() || (max > 0 && out.is_null()) {
            return CKR_ARGUMENTS_BAD;
        }
        state(|s| {
            let Some(session) = s.sessions.get_mut(&session) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            let Some(found) = &mut session.search else {
                return CKR_OPERATION_NOT_INITIALIZED;
            };
            let n = (max as usize).min(found.len());
            for (i, id) in found.drain(..n).enumerate() {
                *out.add(i) = id;
            }
            *count = n as CK_ULONG;
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state(|s| {
            let Some(session) = s.sessions.get_mut(&session) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            if session.search.take().is_some() {
                CKR_OK
            } else {
                CKR_OPERATION_NOT_INITIALIZED
            }
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_SignInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if key != 2 {
            return CKR_KEY_HANDLE_INVALID;
        }
        if (*mechanism).ulParameterLen != 0 {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        let operation = match (*mechanism).mechanism {
            CKM_RSA_PKCS => Operation::DigestInfo,
            CKM_SHA256_RSA_PKCS => Operation::Hash(Sha256::new()),
            _ => return CKR_MECHANISM_INVALID,
        };
        state(|s| {
            let Some(session) = s.sessions.get_mut(&session) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            if session.sign.is_some() {
                return CKR_OPERATION_ACTIVE;
            }
            session.sign = Some(operation);
            CKR_OK
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
fn digest(operation: Operation, bytes: &[u8]) -> Result<[u8; 32], CK_RV> {
    match operation {
        Operation::Hash(mut h) => {
            h.update(bytes);
            Ok(h.finalize().into())
        }
        Operation::DigestInfo => {
            // Strict SHA-256 DigestInfo encoding only; RSA padding/signing stays server-side.
            const PREFIX: &[u8] = &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ];
            if bytes.len() != 51 || !bytes.starts_with(PREFIX) {
                return Err(CKR_DATA_INVALID);
            }
            bytes[19..].try_into().map_err(|_| CKR_DATA_INVALID)
        }
    }
}
unsafe fn sign(
    session: CK_SESSION_HANDLE,
    data: &[u8],
    out: *mut CK_BYTE,
    len: *mut CK_ULONG,
) -> CK_RV {
    if len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    state(|s| {
        let Some(session) = s.sessions.get_mut(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(operation) = session.sign.as_ref() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if out.is_null() {
            *len = 384;
            return CKR_OK;
        }
        if *len < 384 {
            *len = 384;
            return CKR_BUFFER_TOO_SMALL;
        }
        let digest = digest(operation.clone(), data);
        session.sign = None;
        match digest {
            Err(e) => e,
            Ok(d) => match s.remote.sign(d) {
                Ok(signature) => output(out, len, &signature),
                Err(()) => CKR_FUNCTION_FAILED,
            },
        }
    })
}
#[no_mangle]
pub unsafe extern "C" fn C_Sign(
    session: CK_SESSION_HANDLE,
    data: *mut CK_BYTE,
    size: CK_ULONG,
    out: *mut CK_BYTE,
    len: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = match input(data, size, 16 * 1024 * 1024) {
            Ok(v) => v,
            Err(e) => return e,
        };
        sign(session, bytes, out, len)
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_SignUpdate(
    session: CK_SESSION_HANDLE,
    data: *mut CK_BYTE,
    size: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = match input(data, size, 16 * 1024 * 1024) {
            Ok(v) => v,
            Err(e) => return e,
        };
        state(|s| {
            let Some(session) = s.sessions.get_mut(&session) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            match &mut session.sign {
                Some(Operation::Hash(h)) => {
                    h.update(bytes);
                    CKR_OK
                }
                Some(Operation::DigestInfo) => CKR_FUNCTION_NOT_SUPPORTED,
                None => CKR_OPERATION_NOT_INITIALIZED,
            }
        })
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}
#[no_mangle]
pub unsafe extern "C" fn C_SignFinal(
    session: CK_SESSION_HANDLE,
    out: *mut CK_BYTE,
    len: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sign(session, &[], out, len)
    }))
    .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_InitToken(
    _arg1: CK_SLOT_ID,
    _arg2: *mut CK_UTF8CHAR,
    _arg3: CK_ULONG,
    _arg4: *mut CK_UTF8CHAR,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_InitPIN(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_UTF8CHAR,
    _arg3: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_SetPIN(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_UTF8CHAR,
    _arg3: CK_ULONG,
    _arg4: *mut CK_UTF8CHAR,
    _arg5: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_GetOperationState(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_SetOperationState(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: CK_OBJECT_HANDLE,
    _arg5: CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_CreateObject(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_ATTRIBUTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_CopyObject(
    _arg1: CK_SESSION_HANDLE,
    _arg2: CK_OBJECT_HANDLE,
    _arg3: *mut CK_ATTRIBUTE,
    _arg4: CK_ULONG,
    _arg5: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DestroyObject(
    _arg1: CK_SESSION_HANDLE,
    _arg2: CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_GetObjectSize(
    _arg1: CK_SESSION_HANDLE,
    _arg2: CK_OBJECT_HANDLE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_SetAttributeValue(
    _arg1: CK_SESSION_HANDLE,
    _arg2: CK_OBJECT_HANDLE,
    _arg3: *mut CK_ATTRIBUTE,
    _arg4: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_EncryptInit(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_Encrypt(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_EncryptUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_EncryptFinal(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptInit(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_Decrypt(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptFinal(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DigestInit(_arg1: CK_SESSION_HANDLE, _arg2: *mut CK_MECHANISM) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_Digest(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DigestUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DigestKey(_arg1: CK_SESSION_HANDLE, _arg2: CK_OBJECT_HANDLE) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DigestFinal(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_SignRecoverInit(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_SignRecover(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyInit(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_Verify(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyFinal(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyRecoverInit(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyRecover(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DigestEncryptUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptDigestUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_SignEncryptUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptVerifyUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_GenerateKey(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: *mut CK_ATTRIBUTE,
    _arg4: CK_ULONG,
    _arg5: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_GenerateKeyPair(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: *mut CK_ATTRIBUTE,
    _arg4: CK_ULONG,
    _arg5: *mut CK_ATTRIBUTE,
    _arg6: CK_ULONG,
    _arg7: *mut CK_OBJECT_HANDLE,
    _arg8: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_WrapKey(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
    _arg4: CK_OBJECT_HANDLE,
    _arg5: *mut CK_BYTE,
    _arg6: *mut CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_UnwrapKey(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
    _arg4: *mut CK_BYTE,
    _arg5: CK_ULONG,
    _arg6: *mut CK_ATTRIBUTE,
    _arg7: CK_ULONG,
    _arg8: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_DeriveKey(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
    _arg4: *mut CK_ATTRIBUTE,
    _arg5: CK_ULONG,
    _arg6: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_SeedRandom(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_GenerateRandom(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionStatus(_arg1: CK_SESSION_HANDLE) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_CancelFunction(_arg1: CK_SESSION_HANDLE) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

#[no_mangle]
pub unsafe extern "C" fn C_WaitForSlotEvent(
    _arg1: CK_FLAGS,
    _arg2: *mut CK_SLOT_ID,
    _arg3: *mut ::std::os::raw::c_void,
) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| CKR_FUNCTION_NOT_SUPPORTED))
        .unwrap_or(CKR_GENERAL_ERROR)
}

static FUNCTIONS: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_info_rejects_raw_rsa_wrong_oid_and_trailing_bytes() {
        let expected = [7; 32];
        let mut encoded = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        encoded.extend(expected);
        assert_eq!(digest(Operation::DigestInfo, &encoded), Ok(expected));
        assert_eq!(
            digest(Operation::DigestInfo, &expected),
            Err(CKR_DATA_INVALID)
        );
        encoded[14] = 2;
        assert_eq!(
            digest(Operation::DigestInfo, &encoded),
            Err(CKR_DATA_INVALID)
        );
        encoded[14] = 1;
        encoded.push(0);
        assert_eq!(
            digest(Operation::DigestInfo, &encoded),
            Err(CKR_DATA_INVALID)
        );
        let mut stream = Sha256::new();
        stream.update(b"one");
        assert_eq!(
            digest(Operation::Hash(stream), b"two"),
            Ok(Sha256::digest(b"onetwo").into())
        );
    }

    #[test]
    fn abi_rejects_invalid_buffers_and_preserves_small_outputs() {
        unsafe {
            assert_eq!(C_GetFunctionList(std::ptr::null_mut()), CKR_ARGUMENTS_BAD);
            assert_eq!(input(std::ptr::null(), 1, 4), Err(CKR_ARGUMENTS_BAD));
            assert_eq!(input(std::ptr::null(), 0, 4), Ok(&[][..]));
            let mut buffer = [99u8; 2];
            let mut length = 1;
            assert_eq!(
                output(buffer.as_mut_ptr(), &mut length, &[1, 2]),
                CKR_BUFFER_TOO_SMALL
            );
            assert_eq!(length, 2);
            assert_eq!(buffer, [99, 99]);
            assert_eq!(output(buffer.as_mut_ptr(), &mut length, &[1, 2]), CKR_OK);
            assert_eq!(buffer, [1, 2]);
            let mut args: CK_C_INITIALIZE_ARGS = std::mem::zeroed();
            args.pReserved = std::ptr::dangling_mut::<c_void>();
            assert_eq!(
                C_Initialize((&mut args as *mut CK_C_INITIALIZE_ARGS).cast()),
                CKR_ARGUMENTS_BAD
            );
        }
    }
}
