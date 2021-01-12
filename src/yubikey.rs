use std::cell::RefCell;

use yubikey_piv::Readers;
use zeroize::Zeroizing;
use signature::{Signer, Signature};
use rpassword::read_password_from_tty;
use sha2::{Sha256,Digest};

pub struct YubiKey(RefCell<yubikey_piv::YubiKey>);

impl YubiKey {
    pub fn open() -> Result<YubiKey, yubikey_piv::Error> {
        let mut readers = Readers::open()?;
        let readers_iter = readers.iter()?;
        for reader in readers_iter {
            match reader.open() {
                Ok(yk) => return Ok(YubiKey(RefCell::new(yk))),
                Err(_) => continue,
            };
        }

        return Err(yubikey_piv::Error::NotFound)
    }

    pub fn verify_pin_from_tty(&mut self) -> Result<(), yubikey_piv::Error> {
        loop {
            let pw = zeroize::Zeroizing::new(read_password_from_tty(Some("Pin: ")).expect("Could not read pin").into_bytes());
            match self.0.borrow_mut().verify_pin(&pw) {
                Ok(()) => return Ok(()),
                Err(yubikey_piv::Error::WrongPin{..}) => continue, // retry if user makes mistake
                Err(e) => return Err(e),        // any other errors cannot be recovered here
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YubiKeySignature(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for YubiKeySignature {
    fn as_ref(&self) -> &[u8] {
        return &self.0;
    }
}

impl Signature for YubiKeySignature {
    fn from_bytes(bytes: &[u8]) -> Result<YubiKeySignature, signature::Error> {
        return Ok(YubiKeySignature(Zeroizing::new(bytes.to_vec())));
    }

    fn as_bytes(&self) -> &[u8] {
        return &self.0;
    }
}

// Make YubiKey act as Signer implementing RS256 signing
impl Signer<YubiKeySignature> for YubiKey {
    fn try_sign(&self, msg: &[u8]) -> Result<YubiKeySignature, signature::Error> {
        // Encoding based on code in RustCrypto

        // Magic bytes needed per spec of EMSA_PKCS1v1.5-ENCODE
        const SHA256_ASN1_PREFIX: &[u8] = &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];

        let hash_len: usize = 32;
        let t_len = SHA256_ASN1_PREFIX.len() + hash_len;
        let k: usize = 256;

        let hashed = Sha256::digest(msg);

        // EM = 0x00 || 0x01 || PS || 0x00 || T
        let mut em = vec![0xff; k];
        em[0] = 0;
        em[1] = 1;
        em[k - t_len - 1] = 0;
        em[k - t_len..k - hash_len].copy_from_slice(&SHA256_ASN1_PREFIX);
        em[k - hash_len..k].copy_from_slice(&hashed);
        
        let result = match yubikey_piv::key::sign_data(
            &mut self.0.borrow_mut(), 
            &em, 
            yubikey_piv::key::AlgorithmId::Rsa2048, 
            yubikey_piv::key::SlotId::Authentication) {
                Ok(res) => res,
                _ => return Err(signature::Error::new()),
            };

        return Ok(YubiKeySignature(result));
    }
}