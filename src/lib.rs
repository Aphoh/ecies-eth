#![deny(unused_crate_dependencies)]
use cipher::{KeyIvInit, StreamCipher};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ToEncodedPoint},
    AffineXCoordinate,
};
use generic_array::GenericArray;
use hmac::{Hmac, Mac};
use k256::{PublicKey as SecpPk, SecretKey as SecpSk};
use rand::{CryptoRng, RngCore};
use sha2::{digest::Update, Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("ConcatKdf error")]
    ConcatKdf(u8),
    #[error("AES error")]
    AESError,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid pubkey")]
    InvalidPk,
}

fn generate_shared(sk: &SecpSk, pk: &SecpPk) -> [u8; 32] {
    let z = (pk.to_projective() * (*sk.to_nonzero_scalar())).to_affine();
    z.x().try_into().expect("32 bytes in each point")
}

fn derive_keys(secret: &[u8; 32], s1: &[u8]) -> ([u8; 16], [u8; 32]) {
    // concat kdf the key
    let mut key = [0u8; 32];
    concat_kdf::derive_key_into::<Sha256>(secret, s1, &mut key).unwrap();

    let ke: [u8; 16] = key[..16].try_into().unwrap();
    // use last 16 bytes as mac seed
    let mac_seed: [u8; 16] = key[16..].try_into().unwrap();

    // hash the mac seed to get 32 byte mac
    let mut digest = Sha256::new();
    Update::update(&mut digest, &mac_seed);

    (ke, digest.finalize().into())
}

fn message_tag(km: &[u8; 32], em: &[u8], s2: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(km).expect("Hmac can take key of any size");
    Mac::update(&mut mac, em);
    Mac::update(&mut mac, s2);
    mac.finalize().into_bytes().into()
}

type Aes128Ctr32BE = ctr::Ctr32BE<aes::Aes128>;

const R_SIZE: usize = 65;
const IV_SIZE: usize = 16;
const MAC_SIZE: usize = 32;

pub fn encrypt(
    mut rand: impl RngCore + CryptoRng,
    pk: &SecpPk,
    m: &[u8],
    s1: &[u8],
    s2: &[u8],
) -> Result<Vec<u8>, Error> {
    let eph_sk = SecpSk::random(&mut rand);

    let z = generate_shared(&eph_sk, pk);
    let (ke, km) = derive_keys(&z, s1);

    let iv = <Aes128Ctr32BE as KeyIvInit>::generate_iv(&mut rand);
    let mut cipher = Aes128Ctr32BE::new(&ke.into(), &iv);

    // OUTPUT FORMAT: [64 byte uncompressed pubkey : 16 byte IV : encrypted message : 32 byte mac]
    let r_end = R_SIZE;
    let iv_end = r_end + IV_SIZE;
    let msg_end = iv_end + m.len();
    let mac_end = msg_end + MAC_SIZE;

    // populate encrypted message and iv
    let mut out = vec![0; mac_end];
    cipher
        .apply_keystream_b2b(m, &mut out[iv_end..msg_end])
        .map_err(|_| Error::AESError)?;
    out[r_end..iv_end].copy_from_slice(&iv);

    // HMAC the 16 byte iv : encrypted message
    dbg!(&out[r_end..msg_end]);
    let d = message_tag(&km, &out[r_end..msg_end], s2);
    let pk = eph_sk.public_key().to_encoded_point(false);

    debug_assert_eq!(pk.as_bytes().len(), R_SIZE);
    debug_assert_eq!(d.len(), mac_end - msg_end);

    out[0..r_end].copy_from_slice(pk.as_bytes());
    out[msg_end..mac_end].copy_from_slice(&d);

    Ok(out)
}

pub fn decrypt(sk: &SecpSk, c: &[u8], s1: &[u8], s2: &[u8]) -> Result<Vec<u8>, Error> {
    if c.len() <= R_SIZE + IV_SIZE + MAC_SIZE {
        return Err(Error::InvalidMessage);
    }

    let enc_pt = k256::EncodedPoint::from_bytes(&c[..R_SIZE]).map_err(|_| Error::InvalidPk)?;
    let maybe_pk_aff: Option<k256::AffinePoint> =
        k256::AffinePoint::from_encoded_point(&enc_pt).into();
    let pk_aff = maybe_pk_aff.ok_or(Error::InvalidPk)?;
    let pk: SecpPk = pk_aff.try_into().map_err(|_| Error::InvalidPk)?;

    let z = generate_shared(sk, &pk);
    let (ke, km) = derive_keys(&z, s1);

    // OUTPUT FORMAT: [64 byte uncompressed pubkey : 16 byte IV : encrypted message : 32 byte mac]
    let r_end = R_SIZE;
    let iv_end = r_end + IV_SIZE;
    let mac_end = c.len();
    let msg_end = mac_end - MAC_SIZE;

    dbg!(&c[r_end..msg_end]);
    let d = message_tag(&km, &c[r_end..msg_end], s2);

    if d.ct_eq(&c[msg_end..mac_end]).unwrap_u8() != 1 {
        return Err(Error::InvalidMessage);
    }

    let mut out = vec![0; msg_end - iv_end];
    let mut cipher = Aes128Ctr32BE::new(&ke.into(), GenericArray::from_slice(&c[r_end..iv_end]));
    cipher
        .apply_keystream_b2b(&c[iv_end..msg_end], &mut out)
        .map_err(|_| Error::AESError)?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    const MSG: &[u8] = b"Hello, world";
    const SK: [u8; 32] = hex!("eb2766b1ec61c2f377675819d1146ed9347c21834852a8ae4c1d8a2fe73fbc78");
    const ENC: [u8; 125] = hex!("04b4aa7defba74951fdeca544386b095c8a9c9418913b6bbf5a89c2a2cb7b6bbc2a00f33a27489b7a221ed14765f1bcc8390344234f75a43d80fd50e043918f14e44f5ca357a90d99ad831e53c9b0ba5f015dba3a477c3c52c53bd002d5061c7263cdf87c00ef452902a6589a2d77dd160377bc2ac80f9a4213b5cad05");

    #[test]
    fn it_works() {
        let mut r = rand::thread_rng();
        let sk = SecpSk::random(&mut r);
        let pk = sk.public_key();

        let enc = encrypt(&mut r, &pk, MSG, &[], &[]).unwrap();
        let res = decrypt(&sk, &enc, &[], &[]).unwrap();

        assert_eq!(MSG, res);
    }

    #[test]
    fn consistent_with_eth() {
        let sk = SecpSk::from_be_bytes(&SK).unwrap();
        let res = decrypt(&sk, &ENC, &[], &[]).unwrap();

        assert_eq!(res, MSG);
    }
}
