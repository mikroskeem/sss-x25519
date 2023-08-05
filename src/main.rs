#![allow(clippy::manual_strip)]

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::Context;
use crypto_box::{
    aead::{generic_array::GenericArray, Aead},
    SalsaBox,
};
use ed25519_compact::x25519::KeyPair;
use rand::RngCore;

#[gf256::shamir::shamir]
pub mod shamir {}

pub type Error = Box<dyn std::error::Error + Send + Sync>;

fn main() {
    if let Err(err) = entrypoint() {
        panic!("uncaught error: {:?}", err);
    }
}

fn rotate_sss(
    shares_dir: impl AsRef<Path>,
    n: usize,
    k: usize,
    existing_keypair: Option<KeyPair>,
) -> Result<KeyPair, Error> {
    let keypair = match existing_keypair {
        Some(kp) => kp,
        None => KeyPair::generate(),
    };

    if let Err(e) = fs::remove_dir_all(shares_dir.as_ref()) {
        if e.kind() != ErrorKind::NotFound {
            return Err(e.into());
        }
    }

    // Write public key
    fs::create_dir_all(&shares_dir)?;
    fs::write(
        shares_dir.as_ref().join("pubkey"),
        hex::encode(keypair.pk.to_vec()),
    )?;

    // Write checksum of the private key
    let sk = &keypair.sk;

    let sk_sum = sha256::digest(&sk.to_vec());
    fs::write(shares_dir.as_ref().join("sum"), sk_sum)?;

    // Write private key shares
    let shares = shamir::generate(&sk.to_vec(), n, k);
    for (i, share) in shares.iter().enumerate() {
        let encoded = hex::encode(share);

        fs::write(shares_dir.as_ref().join(format!("share_{}", i)), encoded)?;
    }

    Ok(keypair)
}

#[inline]
fn new_salsabox(kp: &KeyPair) -> SalsaBox {
    SalsaBox::new(
        &crypto_box::PublicKey::from_bytes(*kp.pk),
        &crypto_box::SecretKey::from_bytes(*kp.sk),
    )
}

fn decrypt_box(
    path: impl AsRef<Path>,
    nonce_path: impl AsRef<Path>,
    kp: &KeyPair,
) -> Result<Vec<u8>, Error> {
    let nonce_raw = fs::read(nonce_path.as_ref())?;
    let nv: [u8; 24] = nonce_raw.try_into().unwrap();

    let nonce = GenericArray::from(nv);
    let ciphertext = fs::read(path.as_ref())?;
    new_salsabox(kp)
        .decrypt(&nonce, &*ciphertext)
        .map_err(|e| e.into())
}

fn entrypoint() -> Result<(), Error> {
    let shares_dir = PathBuf::from("./shares");

    if fs::metadata(&shares_dir).is_err() {
        rotate_sss(&shares_dir, 1, 1, None)?;
    }

    // Collect shares
    let mut available_shares: Vec<Vec<u8>> = vec![];
    for entry in fs::read_dir(&shares_dir).context("failed to read shares dir")? {
        let share_file = entry?;
        if !share_file.file_type()?.is_file() {
            continue;
        }

        if !share_file
            .file_name()
            .into_string()
            .unwrap()
            .starts_with("share_")
        {
            continue;
        }

        let share = hex::decode(fs::read(share_file.path())?)?;
        available_shares.push(share);
    }
    println!("found n={} shares", available_shares.len());

    // Read public key from file
    let expected_pubkey = hex::decode(fs::read(shares_dir.join("pubkey"))?)?;
    let expected_checksum = String::from_utf8(fs::read(shares_dir.join("sum"))?)?;

    // Reconstruct key
    let mut reconstructed_sk: Vec<u8>;
    let mut used_shares: Vec<Vec<u8>> = vec![];

    let mut i = 0;
    loop {
        // Try reconstructing with current shares
        reconstructed_sk = shamir::reconstruct::<Vec<u8>>(&used_shares);

        // If we've got valid secret key, we're good
        if sha256::digest(&reconstructed_sk) == expected_checksum {
            println!(
                "used n={} shares out of m={}",
                i,
                available_shares.len() + used_shares.len()
            );
            break;
        }

        if available_shares.is_empty() {
            return Err(Error::from(format!("need more shares! n={}", i)));
        }

        // Grab more shares
        used_shares.push(available_shares.remove(0));
        i += 1;
    }

    // Grab public key from private
    let sk = ed25519_compact::x25519::SecretKey::from_slice(&reconstructed_sk)?;
    let kp = ed25519_compact::x25519::KeyPair {
        pk: sk.recover_public_key()?,
        sk,
    };

    println!("expected pubkey={}", hex::encode(expected_pubkey));
    println!("reconstr pubkey={}", hex::encode(kp.pk.to_vec()));

    if fs::metadata(shares_dir.join("box")).is_err() {
        let payload = br#"
        {
            "key": "11-22-33-44-55"
        }
        "#;

        let mut nonce = vec![0; 24];
        rand::thread_rng().fill_bytes(&mut nonce);

        fs::write(shares_dir.join("box.nonce"), &nonce)?;
        let nv: [u8; 24] = nonce.try_into().unwrap();

        let nonce = GenericArray::from(nv);
        let encrypted = new_salsabox(&kp)
            .encrypt(&nonce, &payload[..])
            .context("failed to encrypt data")?;

        fs::write(shares_dir.join("box"), encrypted)?;
    }

    let decrypted = decrypt_box(shares_dir.join("box"), shares_dir.join("box.nonce"), &kp)?;
    println!("encrypted data={}", String::from_utf8(decrypted)?);

    if i < 10 {
        rotate_sss(&shares_dir, i + 2 + 3, i + 2, Some(kp))?;
    } else {
        rotate_sss(&shares_dir, i, i - 3, Some(kp))?;
    }

    Ok(())
}
