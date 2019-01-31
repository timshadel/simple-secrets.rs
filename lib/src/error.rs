use block_modes::{block_padding::UnpadError, BlockModeError};
use data_encoding::DecodeError;
use failure::Fail;

// TODO: explain the data items inside the error tuples

#[derive(Debug, Fail)]
pub enum SimpleSecretsError {
    /// There was a problem decoding text data into bytes.
    /// Examples include the hex master key or the websafe packet values.
    #[fail(display = "The data for the {} could not be understood.", _0)]
    TextDecodingError {
        /// The purpose of the item we were decoding
        role: &'static str,

        /// The underlying error
        #[fail(cause)]
        cause: DecodeError,
    },

    /// The data is has been corrupted to the point where it is unrecoverable.
    /// The kind contains more detail.
    #[fail(display = "The packet has been corrupted because {}.", _0)]
    CorruptPacket(CorruptPacketKind),

    /// The data was verified and decrypted, but could not be deserialized into a Rust data type.
    /// Contains the underlying error.
    #[fail(
        display = "The data was successfully decrypted, but could not be understood by this program."
    )]
    DeserializingError(#[fail(cause)] rmp_serde::decode::Error),

    /// The master key data must contain exactly 32 bytes, but it did not.
    /// Contains the actual number of bytes found.
    #[fail(
        display = "The master key must contain 32 bytes to make a 256-bit key. Found {} bytes.",
        _0
    )]
    InvalidKeyLength(usize),

    /// The system's source of secure randomness is not available for use.
    /// Contains the underlying error.
    #[fail(display = "The is not ready to encrypt data.")]
    RandomSourceUnavailable(rand_os::rand_core::Error),

    /// The Rust data type could not be prepared for encryption by serializing it into bytes.
    /// Contains the underlying error.
    #[fail(
        display = "The data used in this program could not be converted to a form suitable for encryption."
    )]
    SerializingError(#[fail(cause)] rmp_serde::encode::Error),

    /// The packet was encrypted with a another key.
    #[fail(
        display = "The packet is encrypted with a different key ({}) than expected ({}).",
        actual_id, expected_id
    )]
    UnknownKey {
        /// The key id mentioned in the packet header. 6 bytes (12 hex chars).
        expected_id: String,
        /// The key id provided by the application. 6 bytes (12 hex chars).
        actual_id: String,
    },
}

/// Reasons why the packet data has been corrupted to the point where it is unrecoverable.
#[derive(Debug)]
pub enum CorruptPacketKind {
    /// The packet has been corrupted because it is too short to contain both
    /// data and verifying information.
    TooShort,

    /// The packet has been corrupted because while the data was originally validated
    /// with the expected master key, it has been altered in some way since then.
    NotAuthentic,

    /// The packet has been corrupted because its data is identical to what was
    /// originally created, but the sender's encryption is flawed.
    IncorrectlyEncrypted,
}

impl std::fmt::Display for CorruptPacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let reason = match self {
            CorruptPacketKind::TooShort => {
                "it is too short to contain both data and verifying information"
            }
            CorruptPacketKind::NotAuthentic => {
                "while the data was originally validated with the expected master key, \
                 it has been altered in some way since then"
            }
            CorruptPacketKind::IncorrectlyEncrypted => {
                "its data is identical to what was originally created, but the \
                 sender's encryption is flawed"
            }
        };
        write!(f, "{}", reason)
    }
}

impl Into<SimpleSecretsError> for CorruptPacketKind {
    fn into(self) -> SimpleSecretsError {
        SimpleSecretsError::CorruptPacket(self)
    }
}

impl From<BlockModeError> for SimpleSecretsError {
    /// Occurs only when the encrypted data has been damaged. This should probably not be seen in
    /// practice since both the key and the data integrity are checked before decryption.
    fn from(_err: BlockModeError) -> Self {
        SimpleSecretsError::CorruptPacket(CorruptPacketKind::IncorrectlyEncrypted)
    }
}

impl From<UnpadError> for SimpleSecretsError {
    /// Occurs only when the encrypted data has been damaged. This should probably not be seen in
    /// practice since both the key and the data integrity are checked before decryption.
    fn from(_err: UnpadError) -> Self {
        SimpleSecretsError::CorruptPacket(CorruptPacketKind::IncorrectlyEncrypted)
    }
}

impl From<rmp_serde::decode::Error> for SimpleSecretsError {
    fn from(err: rmp_serde::decode::Error) -> Self {
        SimpleSecretsError::DeserializingError(err)
    }
}

impl From<rmp_serde::encode::Error> for SimpleSecretsError {
    fn from(err: rmp_serde::encode::Error) -> Self {
        SimpleSecretsError::SerializingError(err)
    }
}

impl From<rand_os::rand_core::Error> for SimpleSecretsError {
    fn from(err: rand_os::rand_core::Error) -> Self {
        SimpleSecretsError::RandomSourceUnavailable(err)
    }
}
