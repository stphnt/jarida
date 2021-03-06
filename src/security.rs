use super::uuid::Uuid;
use once_cell::sync::Lazy;
use ring::{self, aead, digest, pbkdf2, rand};
use std::num::NonZeroU32;

/// The size of an encryption key, which must match the encryption algorithm
const KEY_LEN: usize = digest::SHA256_OUTPUT_LEN;
/// The encryption key type
pub type Key = [u8; KEY_LEN];
/// The database portion of a salt used for deriving keys from username and passwords.
pub type DbSalt = [u8; 16];

pub static SYSTEM_RNG: Lazy<rand::SystemRandom> = Lazy::new(rand::SystemRandom::new);

/// An intentionally ambiguous error
#[derive(Debug)]
pub struct UnspecifiedError {}

impl std::fmt::Display for UnspecifiedError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Unspecified security error")
    }
}

impl std::convert::From<ring::error::Unspecified> for UnspecifiedError {
    fn from(_: ring::error::Unspecified) -> Self {
        UnspecifiedError {}
    }
}

impl std::error::Error for UnspecifiedError {}

/// A source of Nonces (numbers that you only use once).
#[derive(Debug, Clone)]
pub struct Nonce(u128);

impl Nonce {
    /// Generate a new, random source for Nonces.
    pub fn random() -> Result<Nonce, UnspecifiedError> {
        use rand::SecureRandom as _;
        let mut buf = [0u8; Self::len()];
        SYSTEM_RNG.fill(&mut buf)?;
        Ok(Nonce(u128::from_le_bytes(buf)))
    }

    /// Encoded the present nonce value as a little-endian array of bytes.
    pub fn to_le_bytes(&self) -> [u8; Self::len()] {
        self.0.to_le_bytes()
    }

    /// Decode a Nonce for a little-endian array of bytes.
    pub fn from_le_bytes(bytes: [u8; Self::len()]) -> Self {
        Nonce(u128::from_le_bytes(bytes))
    }

    /// The number of bytes needed to represent the Nonce.
    pub const fn len() -> usize {
        std::mem::size_of::<u128>()
    }
}

impl aead::NonceSequence for Nonce {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        use std::convert::TryInto as _;
        let nonce = aead::Nonce::assume_unique_for_key(
            (&self.to_le_bytes()[..12])
                .try_into()
                .map_err(|_| ring::error::Unspecified)?,
        );
        self.0 += 1;
        Ok(nonce)
    }
}

impl aead::NonceSequence for &mut Nonce {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        (*self).advance()
    }
}

/// Generate a random value that can be used when salting for encryption. The
/// value should be associated with the database and be constant. It does not
/// need to be a secret, though it should be unique to the database.
pub fn generate_db_salt() -> Result<DbSalt, UnspecifiedError> {
    use rand::SecureRandom as _;
    let mut salt: DbSalt = [0u8; 16];
    SYSTEM_RNG.fill(&mut salt)?;
    Ok(salt)
}

/// Derive a key suitable for encrypt based on the database's salt and the
/// user's name and password.
fn derive_key_from_credentials(db_salt: &DbSalt, username: &str, password: &str) -> Key {
    // Generate a salt based on the database's unique salt and the user's name.
    let mut salt = Vec::with_capacity(db_salt.len() + username.as_bytes().len());
    salt.extend(db_salt);
    salt.extend(username.as_bytes());

    // Derive key suitable for encryption/decryption
    let mut key: Key = [0; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(100_000).unwrap(),
        &salt,
        password.as_bytes(),
        &mut key,
    );
    key
}

/// Get an UnboundKey suitable for encrypt/decryption
fn unbound_key(key: &Key) -> Result<aead::UnboundKey, UnspecifiedError> {
    aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| UnspecifiedError {})
}

/// Encrypt the plaintext in place using the specified key and incorporate the
/// associated data (which is not encrypted). The plaintext is consumed during
/// this process, even if it fails.
fn seal_in_place<A: AsRef<[u8]>>(
    key: &Key,
    aad: aead::Aad<A>,
    mut plaintext: Vec<u8>,
) -> Result<(Nonce, Vec<u8>), UnspecifiedError> {
    use aead::BoundKey as _;
    let nonce = Nonce::random()?;
    let mut key = aead::SealingKey::new(unbound_key(key)?, nonce.clone());
    key.seal_in_place_append_tag(aad, &mut plaintext)
        .map_err(|_| UnspecifiedError {})?;
    Ok((nonce, plaintext))
}

/// Decrypt the ciphertext with the given key, associated data, and nonce in
/// place. The ciphertext is consumed in this process, even if it fails.
fn open_in_place<A: AsRef<[u8]>>(
    key: &Key,
    aad: aead::Aad<A>,
    mut nonce: Nonce,
    mut ciphertext: Vec<u8>,
) -> Result<Vec<u8>, UnspecifiedError> {
    use aead::BoundKey as _;
    let mut key = aead::OpeningKey::new(unbound_key(key)?, &mut nonce);
    let size = key
        .open_in_place(aad, &mut ciphertext)
        .map_err(|_| UnspecifiedError {})?
        .len();
    ciphertext.truncate(size);
    Ok(ciphertext)
}

/// A type used to verify the username and password used to secure the database.
#[derive(Debug)]
pub struct CredentialGuard {
    /// The database's unique salt
    salt: DbSalt,
    /// The key derived from the user's name and password.
    credential_key: Key,
}

impl CredentialGuard {
    /// Generate a new CredentialGuard from the database's unique salt and the user's name
    /// and password.
    pub fn new(salt: DbSalt, username: &str, password: &str) -> CredentialGuard {
        let key = derive_key_from_credentials(&salt, username, password);
        CredentialGuard {
            salt,
            credential_key: key,
        }
    }

    /// Update the user's name and password
    pub fn update_credentials(&mut self, username: &str, password: &str) {
        self.credential_key = derive_key_from_credentials(&self.salt, username, password);
    }

    /// Try to decrypt the key using the current user's name and password. If
    /// successful, this CredentialGuard is consumed and a DataGuard is
    /// returned, which can be used to encrypt/decrypt data.
    /// Upon failure, this guard is returned and the guard's credentials should
    /// be updated before calling this function again.
    pub fn try_decrypt_key(self, mut encrypted_key: Vec<u8>) -> Result<DataGuard, Self> {
        // If we can decrypt the key, the credentials are valid.
        use std::convert::TryInto as _;
        // Split the encrypted data from the nonce at the end.
        let nonce_bytes = encrypted_key.split_off(encrypted_key.len() - Nonce::len());
        let nonce = Nonce::from_le_bytes(nonce_bytes.try_into().unwrap());
        if let Ok(key) = open_in_place(
            &self.credential_key,
            aead::Aad::empty(),
            nonce,
            encrypted_key,
        ) {
            // Replace the key derived from the user's credentials with the key
            // we just decrypted. All further encryption should be done with
            // this key.
            Ok(DataGuard {
                guard: self,
                key: key.try_into().unwrap(),
            })
        } else {
            Err(self)
        }
    }

    /// Generate a randome symmetric encryption key for securing data. The key
    /// is encrypted using the user's name and password and, as such, can be
    /// public.
    pub fn generate_encrypted_key(&self) -> Result<Vec<u8>, UnspecifiedError> {
        // Generate a random key to use for encrypted data and encrypt it using
        // the current credentials.
        use rand::SecureRandom as _;
        let mut buf = vec![0u8; KEY_LEN];
        SYSTEM_RNG.fill(&mut buf)?;
        assert!(buf.len() == KEY_LEN);
        let (nonce, mut encrypted_key) =
            seal_in_place(&self.credential_key, aead::Aad::empty(), buf)?;
        // Append the nonce to the end
        encrypted_key.extend_from_slice(&nonce.to_le_bytes());
        Ok(encrypted_key)
    }
}

/// A type used to encrypt/decrypt the contents of a database. It can only be
/// created from a CredentialGuard who's username and password have been verified.
#[derive(Debug)]
pub struct DataGuard {
    guard: CredentialGuard,
    key: Key,
}

impl DataGuard {
    /// Encrypt the plaintext associated with the Uuid in place using the
    /// specified key. The plaintext is consumed during this process, even if it
    /// fails.
    pub fn seal_in_place(
        &mut self,
        uuid: Uuid,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, UnspecifiedError> {
        let (nonce, mut encrypted_data) =
            seal_in_place(&self.key, aead::Aad::from(uuid.to_bytes()), plaintext)?;
        // Append the nonce to the end
        encrypted_data.extend_from_slice(&nonce.to_le_bytes()[..]);
        Ok(encrypted_data)
    }

    /// Decrypt the ciphertext with the given key, associated Uuid, and nonce in
    /// place. The ciphertext is consumed in this process, even if it fails.
    pub fn open_in_place(
        &mut self,
        uuid: Uuid,
        mut ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, UnspecifiedError> {
        use std::convert::TryInto as _;
        // Split the encrypted data from the nonce at the end.
        let nonce_bytes = ciphertext.split_off(ciphertext.len() - Nonce::len());
        let nonce = Nonce::from_le_bytes(nonce_bytes.try_into().unwrap());
        open_in_place(
            &self.key,
            aead::Aad::from(uuid.to_bytes()),
            nonce,
            ciphertext,
        )
    }
}

/// A type that can be encrypted
pub trait Seal: Sized {
    fn into_bytes(self) -> Vec<u8>;

    fn seal(self, uuid: Uuid, guard: &mut DataGuard) -> Result<Vec<u8>, UnspecifiedError> {
        guard.seal_in_place(uuid, self.into_bytes())
    }
}

/// A type that can be decrypted
pub trait Open: Sized {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, UnspecifiedError>;

    fn open(
        uuid: Uuid,
        ciphertext: Vec<u8>,
        guard: &mut DataGuard,
    ) -> Result<Self, UnspecifiedError> {
        let plaintext = guard.open_in_place(uuid, ciphertext)?;
        Open::from_bytes(plaintext)
    }
}

impl Seal for Vec<u8> {
    fn into_bytes(self) -> Vec<u8> {
        self
    }
}

impl Open for Vec<u8> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, UnspecifiedError> {
        Ok(bytes)
    }
}

impl Seal for String {
    fn into_bytes(self) -> Vec<u8> {
        String::into_bytes(self)
    }
}

impl Open for String {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, UnspecifiedError> {
        Ok(String::from_utf8(bytes).unwrap())
    }
}

impl Seal for chrono::DateTime<chrono::Utc> {
    fn into_bytes(self) -> Vec<u8> {
        self.to_rfc3339().into_bytes()
    }
}

impl Open for chrono::DateTime<chrono::Utc> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, UnspecifiedError> {
        Ok(
            chrono::DateTime::parse_from_rfc3339(std::str::from_utf8(&bytes).unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn seal_and_open() {
        let message = b"Hello, World";
        let username = "username";
        let password = "password";
        let salt = generate_db_salt().unwrap();
        let credential_key = derive_key_from_credentials(&salt, username, password);

        let data = message.to_vec();
        let (nonce, ciphertext) = seal_in_place(&credential_key, aead::Aad::empty(), data).unwrap();
        let extracted =
            open_in_place(&credential_key, aead::Aad::empty(), nonce, ciphertext).unwrap();
        assert_eq!(message, &*extracted);
    }
}
