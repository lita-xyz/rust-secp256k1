// SPDX-License-Identifier: CC0-1.0

//! Provides a signing function that allows recovering the public key from the
//! signature.
//!

use core::ptr;

#[cfg(target_arch = "valida")]
use valida_secp256k1::ecdsa as ecdsa_valida;
#[cfg(target_arch = "valida")]
use valida_secp256k1::secp256k1 as secp256k1_valida;

use self::super_ffi::CPtr;
use super::ffi as super_ffi;
use crate::ecdsa::Signature;
use crate::ffi::recovery as ffi;
use crate::{key, Error, Message, Secp256k1, Signing, Verification};

/// A tag used for recovering the public key from a compact signature.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RecoveryId {
    /// Signature recovery ID 0
    Zero,
    /// Signature recovery ID 1
    One,
    /// Signature recovery ID 2
    Two,
    /// Signature recovery ID 3
    Three,
}

impl TryFrom<i32> for RecoveryId {
    type Error = Error;
    #[inline]
    fn try_from(id: i32) -> Result<RecoveryId, Error> {
        match id {
            0 => Ok(RecoveryId::Zero),
            1 => Ok(RecoveryId::One),
            2 => Ok(RecoveryId::Two),
            3 => Ok(RecoveryId::Three),
            _ => Err(Error::InvalidRecoveryId),
        }
    }
}

impl From<RecoveryId> for i32 {
    #[inline]
    fn from(val: RecoveryId) -> Self {
        match val {
            RecoveryId::Zero => 0,
            RecoveryId::One => 1,
            RecoveryId::Two => 2,
            RecoveryId::Three => 3,
        }
    }
}

/// An ECDSA signature with a recovery ID for pubkey recovery.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Ord, PartialOrd)]
pub struct RecoverableSignature(pub ffi::RecoverableSignature);

impl RecoverableSignature {
    #[inline]
    /// Converts a compact-encoded byte slice to a signature. This
    /// representation is nonstandard and defined by the libsecp256k1 library.
    pub fn from_compact(data: &[u8], recid: RecoveryId) -> Result<RecoverableSignature, Error> {
        if data.is_empty() {
            return Err(Error::InvalidSignature);
        }

        let mut ret = ffi::RecoverableSignature::new();

        unsafe {
            if data.len() != 64 {
                Err(Error::InvalidSignature)
            } else if ffi::secp256k1_ecdsa_recoverable_signature_parse_compact(
                super_ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
                recid.into(),
            ) == 1
            {
                Ok(RecoverableSignature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions.
    #[inline]
    #[deprecated(since = "0.25.0", note = "Use Self::as_c_ptr if you need to access the FFI layer")]
    pub fn as_ptr(&self) -> *const ffi::RecoverableSignature { self.as_c_ptr() }

    /// Obtains a raw mutable pointer suitable for use with FFI functions.
    #[inline]
    #[deprecated(
        since = "0.25.0",
        note = "Use Self::as_mut_c_ptr if you need to access the FFI layer"
    )]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::RecoverableSignature { self.as_mut_c_ptr() }

    #[inline]
    /// Serializes the recoverable signature in compact format.
    pub fn serialize_compact(&self) -> (RecoveryId, [u8; 64]) {
        let mut ret = [0u8; 64];
        let mut recid = RecoveryId::Zero.into();
        unsafe {
            let err = ffi::secp256k1_ecdsa_recoverable_signature_serialize_compact(
                super_ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                &mut recid,
                self.as_c_ptr(),
            );
            assert!(err == 1);
        }
        (recid.try_into().expect("ffi returned invalid RecoveryId!"), ret)
    }

    /// Converts a recoverable signature to a non-recoverable one (this is needed
    /// for verification).
    #[inline]
    pub fn to_standard(&self) -> Signature {
        unsafe {
            let mut ret = super_ffi::Signature::new();
            let err = ffi::secp256k1_ecdsa_recoverable_signature_convert(
                super_ffi::secp256k1_context_no_precomp,
                &mut ret,
                self.as_c_ptr(),
            );
            assert!(err == 1);
            Signature(ret)
        }
    }

    /// Determines the public key for which this [`Signature`] is valid for `msg`. Requires a
    /// verify-capable context.
    #[inline]
    #[cfg(feature = "global-context")]
    pub fn recover(&self, msg: &Message) -> Result<key::PublicKey, Error> {
        crate::SECP256K1.recover_ecdsa(msg, self)
    }
}

impl CPtr for RecoverableSignature {
    type Target = ffi::RecoverableSignature;
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// Creates a new recoverable signature from a FFI one.
impl From<ffi::RecoverableSignature> for RecoverableSignature {
    #[inline]
    fn from(sig: ffi::RecoverableSignature) -> RecoverableSignature { RecoverableSignature(sig) }
}

impl<C: Signing> Secp256k1<C> {
    fn sign_ecdsa_recoverable_with_noncedata_pointer(
        &self,
        msg: &Message,
        sk: &key::SecretKey,
        noncedata_ptr: *const super_ffi::types::c_void,
    ) -> RecoverableSignature {
        let mut ret = ffi::RecoverableSignature::new();
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(
                ffi::secp256k1_ecdsa_sign_recoverable(
                    self.ctx.as_ptr(),
                    &mut ret,
                    msg.as_c_ptr(),
                    sk.as_c_ptr(),
                    super_ffi::secp256k1_nonce_function_rfc6979,
                    noncedata_ptr
                ),
                1
            );
        }

        RecoverableSignature::from(ret)
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign_ecdsa_recoverable(
        &self,
        msg: &Message,
        sk: &key::SecretKey,
    ) -> RecoverableSignature {
        self.sign_ecdsa_recoverable_with_noncedata_pointer(msg, sk, ptr::null())
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// and includes 32 bytes of noncedata in the nonce generation via inclusion in
    /// one of the hash operations during nonce generation. This is useful when multiple
    /// signatures are needed for the same Message and SecretKey while still using RFC6979.
    /// Requires a signing-capable context.
    pub fn sign_ecdsa_recoverable_with_noncedata(
        &self,
        msg: &Message,
        sk: &key::SecretKey,
        noncedata: &[u8; 32],
    ) -> RecoverableSignature {
        let noncedata_ptr = noncedata.as_ptr() as *const super_ffi::types::c_void;
        self.sign_ecdsa_recoverable_with_noncedata_pointer(msg, sk, noncedata_ptr)
    }
}

#[cfg(target_arch = "valida")]
fn convert_signature(
    signature_serialized: &[u8],
) -> Result<ecdsa_valida::Signature<secp256k1_valida::Secp256k1Point>, Error> {
    let mut r: [u8; 32] = signature_serialized[0..32].try_into().unwrap();
    r.reverse();

    let mut s: [u8; 32] = signature_serialized[32..64].try_into().unwrap();
    s.reverse();

    let r = secp256k1_valida::Secp256k1Scalar::create(r).ok_or(Error::InvalidSignature)?;
    let s = secp256k1_valida::Secp256k1Scalar::create(s).ok_or(Error::InvalidSignature)?;

    Ok(ecdsa_valida::Signature { r, s })
}

impl<C: Verification> Secp256k1<C> {
    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`. Requires a verify-capable context.
    #[cfg(not(target_arch = "valida"))]
    pub fn recover_ecdsa(
        &self,
        msg: &Message,
        sig: &RecoverableSignature,
    ) -> Result<key::PublicKey, Error> {
        unsafe {
            let mut pk = super_ffi::PublicKey::new();
            if ffi::secp256k1_ecdsa_recover(
                self.ctx.as_ptr(),
                &mut pk,
                sig.as_c_ptr(),
                msg.as_c_ptr(),
            ) != 1
            {
                return Err(Error::InvalidSignature);
            }
            Ok(key::PublicKey::from(pk))
        }
    }

    #[cfg(target_arch = "valida")]
    pub fn recover_ecdsa(
        &self,
        msg: &Message,
        sig: &RecoverableSignature,
    ) -> Result<key::PublicKey, Error> {
        let recid = sig.0 .0[64];
        let sig = sig.to_standard().serialize_compact();
        let sig = convert_signature(&sig)?;
        // FIXME: don't expose RecoverableSignature internal structure
        let pk = ecdsa_valida::ECDSA::<secp256k1_valida::Secp256k1Point>::recover(
            msg.as_ref(),
            &sig,
            &ecdsa_valida::RecoveryId::new(recid).ok_or(Error::InvalidRecoveryId)?,
        )
        .map_err(|_| Error::IncorrectSignature)?;

        let repr: ([u8; 32], [u8; 32]) = pk.to_repr();
        // FIXME: don't expose key::PublicKey, crate::ffi::PublicKey internal structure
        Ok(key::PublicKey(crate::ffi::PublicKey(
            [&repr.0[..], &repr.1].concat().try_into().unwrap(),
        )))
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::{RecoverableSignature, RecoveryId};
    use crate::constants::ONE;
    use crate::{Error, Message, PublicKey, Secp256k1, SecretKey};

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn capabilities() {
        let sign = Secp256k1::signing_only();
        let vrfy = Secp256k1::verification_only();
        let full = Secp256k1::new();

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();

        // Try key generation
        let (sk, pk) = full.generate_keypair(&mut rand::thread_rng());

        // Try signing
        assert_eq!(sign.sign_ecdsa_recoverable(&msg, &sk), full.sign_ecdsa_recoverable(&msg, &sk));
        let sigr = full.sign_ecdsa_recoverable(&msg, &sk);

        // Try pk recovery
        assert!(vrfy.recover_ecdsa(&msg, &sigr).is_ok());
        assert!(full.recover_ecdsa(&msg, &sigr).is_ok());

        assert_eq!(vrfy.recover_ecdsa(&msg, &sigr), full.recover_ecdsa(&msg, &sigr));
        assert_eq!(full.recover_ecdsa(&msg, &sigr), Ok(pk));
    }

    #[test]
    fn recid_sanity_check() {
        let one = RecoveryId::One;
        assert_eq!(one, one.clone());
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]  // fixed sig vectors can't work with fuzz-sigs
    #[cfg(all(feature = "rand", feature = "std"))]
    #[rustfmt::skip]
    fn sign() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let sk = SecretKey::from_slice(&ONE).unwrap();
        let msg = Message::from_digest_slice(&ONE).unwrap();

        let sig = s.sign_ecdsa_recoverable(&msg, &sk);

        assert_eq!(Ok(sig), RecoverableSignature::from_compact(&[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
            RecoveryId::One))
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]  // fixed sig vectors can't work with fuzz-sigs
    #[cfg(all(feature = "rand", feature = "std"))]
    #[rustfmt::skip]
    fn sign_with_noncedata() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let sk = SecretKey::from_slice(&ONE).unwrap();
        let msg = Message::from_digest_slice(&ONE).unwrap();
        let noncedata = [42u8; 32];

        let sig = s.sign_ecdsa_recoverable_with_noncedata(&msg, &sk, &noncedata);

        assert_eq!(Ok(sig), RecoverableSignature::from_compact(&[
            0xb5, 0x0b, 0xb6, 0x79, 0x5f, 0x31, 0x74, 0x8a,
            0x4d, 0x37, 0xc3, 0xa9, 0x7e, 0xbd, 0x06, 0xa2,
            0x2e, 0xa3, 0x37, 0x71, 0x04, 0x0f, 0x5c, 0x05,
            0xd6, 0xe2, 0xbb, 0x2d, 0x38, 0xc6, 0x22, 0x7c,
            0x34, 0x3b, 0x66, 0x59, 0xdb, 0x96, 0x99, 0x59,
            0xd9, 0xfd, 0xdb, 0x44, 0xbd, 0x0d, 0xd9, 0xb9,
            0xdd, 0x47, 0x66, 0x6a, 0xb5, 0x28, 0x71, 0x90,
            0x1d, 0x17, 0x61, 0xeb, 0x82, 0xec, 0x87, 0x22],
            RecoveryId::Zero))
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn sign_and_verify_fail() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut rand::thread_rng());

        let sigr = s.sign_ecdsa_recoverable(&msg, &sk);
        let sig = sigr.to_standard();

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();
        assert_eq!(s.verify_ecdsa(&msg, &sig, &pk), Err(Error::IncorrectSignature));

        let recovered_key = s.recover_ecdsa(&msg, &sigr).unwrap();
        assert!(recovered_key != pk);
    }

    struct TestVector {
        msg: [u8; 32],
        pk: [u8; 33],
        recid: i32,
        sig: [u8; 64]
    }

    const TEST_VECTORS: [TestVector; 9] = [
        TestVector {
            msg: [197, 5, 206, 151, 255, 219, 95, 255, 158, 250, 30, 125, 116, 98, 150, 242, 73, 99, 85, 129, 142, 196, 237, 106, 159, 105, 206, 45, 80, 20, 145, 229],
            pk: [2, 249, 22, 68, 200, 222, 223, 179, 139, 77, 55, 220, 80, 25, 3, 234, 173, 160, 58, 238, 160, 203, 253, 134, 198, 162, 208, 103, 42, 122, 101, 133, 20],
            recid: 0,
            sig: [12, 125, 215, 127, 170, 72, 255, 35, 162, 53, 127, 211, 229, 117, 248, 102, 217, 60, 181, 151, 52, 29, 6, 182, 108, 77, 184, 44, 103, 154, 16, 207, 1, 160, 240, 64, 163, 92, 112, 8, 172, 121, 106, 40, 130, 82, 181, 108, 1, 177, 11, 116, 220, 61, 32, 117, 53, 137, 134, 137, 234, 3, 196, 27]
          },
        TestVector {
            msg: [126, 23, 162, 95, 120, 117, 98, 210, 102, 46, 185, 48, 5, 152, 11, 241, 153, 139, 132, 14, 253, 54, 137, 219, 76, 100, 201, 72, 218, 253, 111, 179],
            pk: [2, 230, 47, 35, 137, 106, 93, 171, 54, 98, 246, 171, 209, 43, 82, 117, 228, 114, 164, 57, 248, 46, 87, 181, 116, 114, 4, 205, 154, 132, 233, 85, 209],
            recid: 1,
            sig: [47, 135, 46, 159, 188, 219, 225, 59, 206, 151, 16, 128, 148, 187, 91, 212, 56, 58, 226, 140, 129, 71, 113, 159, 244, 101, 65, 227, 165, 246, 44, 88, 32, 64, 68, 57, 97, 153, 61, 197, 188, 150, 106, 113, 131, 73, 220, 192, 223, 170, 3, 108, 140, 164, 240, 104, 210, 126, 0, 20, 93, 187, 93, 169]
        },
        TestVector {
            msg: [180, 167, 89, 100, 158, 177, 123, 233, 79, 23, 106, 163, 126, 135, 20, 108, 246, 201, 16, 135, 132, 7, 233, 34, 159, 169, 243, 120, 70, 142, 244, 212],
            pk: [2, 72, 109, 249, 30, 12, 141, 128, 127, 90, 35, 208, 253, 246, 248, 219, 28, 211, 142, 109, 104, 0, 245, 221, 84, 111, 127, 95, 124, 12, 51, 254, 202],
            recid: 1,
            sig: [241, 143, 255, 110, 136, 207, 64, 137, 130, 123, 243, 237, 66, 20, 51, 253, 16, 36, 105, 226, 95, 22, 169, 120, 84, 97, 9, 157, 13, 222, 239, 6, 29, 117, 207, 142, 204, 119, 201, 16, 145, 238, 188, 153, 171, 112, 79, 247, 255, 92, 109, 27, 168, 159, 189, 36, 94, 61, 111, 124, 202, 34, 64, 143]
        },
        TestVector {
            msg: [87, 149, 107, 142, 216, 41, 26, 195, 116, 55, 198, 40, 60, 246, 248, 228, 145, 24, 232, 172, 244, 59, 208, 123, 145, 67, 115, 230, 222, 38, 55, 96],
            pk: [3, 1, 210, 44, 78, 39, 151, 76, 11, 123, 46, 50, 231, 64, 25, 222, 248, 248, 114, 218, 254, 154, 160, 213, 155, 67, 226, 138, 88, 175, 192, 212, 22],
            recid: 0,
            sig: [247, 15, 15, 21, 134, 116, 201, 41, 200, 75, 237, 97, 183, 54, 250, 200, 88, 229, 220, 45, 10, 40, 230, 254, 210, 84, 132, 23, 90, 20, 166, 246, 77, 81, 151, 25, 24, 198, 166, 115, 64, 126, 94, 106, 64, 208, 11, 87, 117, 65, 20, 106, 35, 181, 78, 181, 194, 218, 146, 9, 40, 252, 126, 53]
        },
        TestVector {
            msg: [176, 51, 154, 241, 194, 182, 167, 233, 147, 210, 166, 22, 75, 220, 98, 214, 28, 33, 242, 115, 203, 243, 19, 176, 220, 216, 106, 150, 217, 166, 240, 81],
            pk: [2, 210, 190, 12, 247, 135, 15, 248, 84, 98, 198, 184, 192, 253, 121, 177, 52, 172, 57, 20, 2, 239, 107, 122, 136, 193, 200, 199, 30, 31, 63, 142, 5],
            recid: 0,
            sig: [43, 195, 143, 213, 137, 163, 206, 185, 197, 62, 54, 25, 195, 208, 62, 241, 128, 241, 56, 211, 14, 39, 241, 44, 172, 250, 83, 174, 37, 247, 7, 91, 40, 137, 58, 143, 93, 173, 12, 229, 27, 194, 73, 142, 250, 36, 219, 118, 228, 96, 130, 247, 14, 35, 190, 19, 180, 195, 115, 64, 118, 87, 37, 98]
        },
        TestVector {
            msg: [82, 92, 251, 10, 59, 206, 204, 48, 18, 229, 101, 139, 216, 253, 24, 221, 52, 188, 209, 187, 68, 139, 209, 164, 242, 249, 184, 66, 37, 51, 39, 31],
            pk: [2, 198, 197, 184, 99, 155, 170, 116, 121, 146, 1, 178, 67, 136, 82, 195, 238, 28, 137, 27, 150, 158, 187, 87, 125, 163, 108, 25, 25, 11, 232, 178, 250],
            recid: 0,
            sig: [126, 141, 146, 32, 93, 5, 13, 126, 240, 237, 92, 95, 111, 101, 216, 22, 156, 36, 12, 189, 72, 26, 101, 69, 8, 144, 47, 33, 37, 155, 55, 189, 7, 71, 204, 183, 156, 115, 195, 49, 214, 125, 93, 63, 194, 249, 156, 14, 102, 220, 72, 190, 187, 95, 97, 147, 143, 254, 94, 50, 209, 158, 199, 129]
        },
        TestVector {
            msg: [229, 107, 229, 20, 24, 196, 164, 52, 192, 92, 219, 97, 98, 196, 38, 168, 225, 74, 77, 49, 186, 38, 31, 212, 226, 138, 208, 126, 120, 250, 58, 212],
            pk: [3, 77, 165, 200, 110, 254, 176, 235, 5, 187, 27, 204, 241, 1, 188, 164, 157, 37, 29, 100, 154, 46, 1, 72, 225, 87, 157, 146, 153, 34, 241, 23, 163],
            recid: 1,
            sig: [99, 147, 171, 34, 165, 71, 184, 234, 11, 67, 229, 243, 166, 67, 182, 198, 14, 87, 4, 60, 106, 96, 39, 140, 17, 246, 75, 171, 14, 215, 150, 175, 38, 30, 163, 41, 129, 32, 45, 169, 58, 99, 250, 140, 151, 152, 167, 121, 164, 228, 25, 243, 174, 171, 222, 217, 53, 3, 88, 38, 77, 98, 204, 99]
        },
        TestVector {
            msg: [202, 219, 232, 195, 4, 75, 211, 215, 61, 247, 86, 77, 105, 133, 107, 198, 170, 195, 7, 84, 76, 41, 157, 236, 246, 253, 252, 95, 106, 252, 78, 171],
            pk: [3, 254, 71, 238, 253, 52, 8, 232, 133, 177, 53, 39, 209, 197, 52, 228, 124, 102, 28, 182, 147, 55, 213, 117, 212, 242, 8, 126, 172, 227, 240, 137, 180],
            recid: 0,
            sig: [202, 36, 131, 105, 61, 43, 175, 242, 213, 173, 199, 164, 245, 32, 203, 234, 18, 20, 54, 136, 164, 243, 181, 225, 128, 31, 152, 102, 15, 24, 200, 84, 37, 31, 216, 151, 47, 34, 21, 243, 101, 137, 195, 187, 141, 160, 244, 20, 150, 110, 206, 7, 47, 173, 149, 87, 208, 7, 73, 20, 111, 215, 73, 150]
        },
        TestVector {
            msg: [192, 245, 243, 238, 84, 115, 160, 96, 152, 125, 231, 44, 38, 48, 35, 243, 223, 5, 58, 128, 200, 54, 165, 54, 147, 47, 139, 179, 78, 27, 152, 226],
            pk: [3, 118, 153, 186, 249, 67, 14, 249, 99, 134, 51, 85, 118, 160, 127, 144, 221, 218, 128, 220, 60, 185, 43, 125, 196, 130, 47, 61, 39, 40, 99, 92, 119],
            recid: 1,
            sig: [85, 150, 188, 78, 174, 22, 239, 246, 232, 159, 2, 206, 254, 211, 243, 155, 59, 244, 249, 136, 18, 237, 101, 152, 141, 149, 24, 207, 8, 81, 204, 73, 66, 207, 4, 204, 123, 225, 250, 64, 138, 164, 58, 146, 81, 72, 31, 140, 120, 20, 137, 213, 224, 51, 29, 194, 178, 36, 170, 241, 10, 216, 94, 230]
        }
    ];

    #[test]
    fn recover_and_verify_fixed_test_vectors() {
        let s = Secp256k1::new();
        for t in TEST_VECTORS {

            let sig = RecoverableSignature::from_compact(&t.sig, RecoveryId::try_from(t.recid).unwrap()).unwrap();
            let msg = Message::from_digest_slice(&t.msg).unwrap();
            let pk = PublicKey::from_slice(&t.pk).unwrap();

            assert_eq!(s.recover_ecdsa(&msg, &sig), Ok(pk));
            assert!(s.verify_ecdsa(&msg, &sig.to_standard(), &pk).is_ok());
        }
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn sign_with_recovery() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut rand::thread_rng());

        let sig = s.sign_ecdsa_recoverable(&msg, &sk);

        assert_eq!(s.recover_ecdsa(&msg, &sig), Ok(pk));
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn sign_with_recovery_and_noncedata() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();

        let noncedata = [42u8; 32];

        let (sk, pk) = s.generate_keypair(&mut rand::thread_rng());

        let sig = s.sign_ecdsa_recoverable_with_noncedata(&msg, &sk, &noncedata);

        assert_eq!(s.recover_ecdsa(&msg, &sig), Ok(pk));
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn bad_recovery() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let msg = Message::from_digest_slice(&[0x55; 32]).unwrap();

        // Zero is not a valid sig
        let sig = RecoverableSignature::from_compact(&[0; 64], RecoveryId::Zero).unwrap();
        assert_eq!(s.recover_ecdsa(&msg, &sig), Err(Error::InvalidSignature));
        // ...but 111..111 is
        let sig = RecoverableSignature::from_compact(&[1; 64], RecoveryId::Zero).unwrap();
        assert!(s.recover_ecdsa(&msg, &sig).is_ok());
    }

    #[test]
    fn test_debug_output() {
        #[rustfmt::skip]
        let sig = RecoverableSignature::from_compact(&[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
            RecoveryId::One).unwrap();
        assert_eq!(&format!("{:?}", sig), "RecoverableSignature(6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e88984c1a971652e0ada880120ef8025e709fff2080c4a39aae068d12eed009b68c8901)");
    }

    #[test]
    fn test_recov_sig_serialize_compact() {
        let recid_in = RecoveryId::One;
        #[rustfmt::skip]
        let bytes_in = &[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89];
        let sig = RecoverableSignature::from_compact(bytes_in, recid_in).unwrap();
        let (recid_out, bytes_out) = sig.serialize_compact();
        assert_eq!(recid_in, recid_out);
        assert_eq!(&bytes_in[..], &bytes_out[..]);
    }

    #[test]
    fn test_recov_id_conversion_between_i32() {
        assert!(RecoveryId::try_from(-1i32).is_err());
        assert!(RecoveryId::try_from(0i32).is_ok());
        assert!(RecoveryId::try_from(1i32).is_ok());
        assert!(RecoveryId::try_from(2i32).is_ok());
        assert!(RecoveryId::try_from(3i32).is_ok());
        assert!(RecoveryId::try_from(4i32).is_err());
        let id0 = RecoveryId::Zero;
        assert_eq!(Into::<i32>::into(id0), 0i32);
        let id1 = RecoveryId::One;
        assert_eq!(Into::<i32>::into(id1), 1i32);
    }
}

#[cfg(bench)]
#[cfg(all(feature = "rand", feature = "std"))] // Currently only a single bench that requires "rand" + "std".
mod benches {
    use test::{black_box, Bencher};

    use super::{Message, Secp256k1};

    #[bench]
    pub fn bench_recover(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();
        let (sk, _) = s.generate_keypair(&mut rand::thread_rng());
        let sig = s.sign_ecdsa_recoverable(&msg, &sk);

        bh.iter(|| {
            let res = s.recover_ecdsa(&msg, &sig).unwrap();
            black_box(res);
        });
    }
}
