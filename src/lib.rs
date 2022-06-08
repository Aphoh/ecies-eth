use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr32BE;
use elliptic_curve::AffineXCoordinate;
use k256::{PublicKey as SecpPk, SecretKey as SecpSk};
use rand::{CryptoRng, RngCore};
use sha2::{digest::Update, Digest, Sha256};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("ConcatKdf error")]
    ConcatKdf(u8),
}

pub struct PublicKey {
    pk: SecpPk,
}

pub struct PrivateKey {
    sk: SecpSk,
}

struct Shared {}

impl PrivateKey {
    fn generate(mut rand: impl CryptoRng + RngCore) -> Self {
        let sk = SecpSk::random(&mut rand);
        Self { sk }
    }

    fn public(&self) -> PublicKey {
        PublicKey {
            pk: self.sk.public_key(),
        }
    }

    fn generate_shared(&self, pk: &PublicKey) -> [u8; 32] {
        let z = (pk.pk.to_projective() * (*self.sk.to_nonzero_scalar())).to_affine();
        z.x().try_into().expect("32 bytes in each point")
    }
}

fn derive_keys(secret: &[u8; 32], s1: &[u8]) -> ([u8; 16], [u8; 32]) {
    // concat kdf the key
    let key = [0u8; 32];
    concat_kdf::derive_key_into::<Sha256>(secret, &s1, &mut key).unwrap();

    let ke: [u8; 16] = key[..16].try_into().unwrap();
    // use last 16 bytes as mac seed
    let mac_seed: [u8; 16] = key[16..].try_into().unwrap();

    // hash the mac seed to get 32 byte mac
    let digest = Sha256::new();
    Update::update(&mut digest, &mac_seed);

    (ke, digest.finalize().into())
}

type Aes128Ctr32BE = ctr::Ctr32BE<aes::Aes128>;

pub fn encrypt(
    mut rand: impl RngCore + CryptoRng,
    pk: &PublicKey,
    m: &mut [u8],
    s1: &[u8],
    s2: &[u8],
) -> Result<Vec<u8>, Error> {
    let eph_sk = PrivateKey::generate(&mut rand);

    let z = eph_sk.generate_shared(pk);

    let (key, mac) = derive_keys(&z, s1);

    let mut iv = [0u8; 16];
    rand.fill_bytes(&mut iv);
    let mut cipher = Aes128Ctr32BE::new(&key.into(), &iv.into());

    cipher.apply_keystream(m);
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
