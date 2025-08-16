use aes::cipher::{BlockDecryptMut,  BlockEncryptMut};
use hmac::digest::Update;
use sha2::Digest;
type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;
type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub fn make_key() -> [u8; 32] {
    let application_bytes = super::id::APPLICATION.to_le_bytes();
    let hash = sha2::Sha256::digest(&application_bytes);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}
pub fn encrypt(src: &[u8]) -> Vec<u8> {
    let key = make_key();
    let cipher = <Aes256EcbEnc as aes::cipher::KeyInit>::new(&key.into());
    let mut buf = src.to_vec();
    let pt_len = buf.len();
    buf.resize(pt_len + 16, 0);
    cipher
        .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf, pt_len)
        .unwrap();
    buf
}

pub fn decrypt(src: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let key = make_key();
    let cipher = <Aes256EcbDec as aes::cipher::KeyInit>::new(&key.into());
    let mut buf = src.to_vec();
    let decrypted = cipher.decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Decryption failed: {}", e),
        )
    })?;
    Ok(decrypted.to_vec())
}
pub fn checksum(payload: &[u8], byte: &[u8]) -> Result<[u8; 32], std::io::Error> {
    let key = make_key();
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&key).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Hmac verification error: {}", e),
        )
    })?;
    mac.update(&payload);
    let checksum = hmac::Mac::finalize(mac).into_bytes();
    let checksum_array: [u8; 32] = checksum
        .as_slice()
        .try_into()
        .expect("HMAC output is always 32 bytes");
    if &byte[..32] != checksum_array.as_slice() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "checksum mismatch: {:02x?} != {:02x?}",
                &payload,
                checksum.as_slice()
            ),
        ));
    }
    Ok(checksum_array)
}
pub fn hmac_sha256(payload: &[u8]) -> [u8; 32] {
    let key = make_key();
    let mut mac =  <HmacSha256 as hmac::Mac>::new_from_slice(&key).unwrap();
    mac.update(payload);
    hmac::Mac::finalize(mac).into_bytes().try_into().unwrap()
}
