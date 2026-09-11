//! De quoi fabriquer un jeton Play Integrity, pour éprouver ce qui l'ouvre.
//!
//! # POURQUOI FABRIQUER
//!
//! Un jeton réel est signé par Google et chiffré vers une clé de la Play
//! Console ; on n'en a pas. Comme pour App Attest, le vérificateur prend les
//! clés EN PARAMÈTRE : en production ce sont celles de Google et de la Console,
//! ici ce sont les nôtres, et on signe et chiffre ce qu'on veut. C'est ce qui
//! rend les refus éprouvables — une signature fausse, une mauvaise clé, une
//! enveloppe d'un autre algorithme.
//!
//! **Ce que cela ne prouve pas** : que la forme employée ici — `A256KW`,
//! `A256GCM`, ES256, la disposition du verdict — est bien celle de Google. Cela
//! vient de la documentation. Un vrai jeton tranchera.

#![allow(dead_code)]

extern crate alloc;

use aes::Aes256;
use aes::cipher::array::Array;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, Nonce};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

/// base64url sans remplissage.
pub fn b64(source: &[u8]) -> alloc::string::String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = alloc::string::String::new();
    let (mut m, mut b) = (0_u32, 0_u32);
    for octet in source {
        m = m << 8 | u32::from(*octet);
        b = b.saturating_add(8);
        while b >= 6 {
            b = b.saturating_sub(6);
            s.push(char::from(
                A[usize::try_from((m >> b) & 0x3F).expect("six bits")],
            ));
        }
    }
    if b > 0 {
        let reste = 6_u32.saturating_sub(b);
        s.push(char::from(
            A[usize::try_from((m << reste) & 0x3F).expect("six bits")],
        ));
    }
    s
}

/// Les clés du banc : la KEK (déchiffrement) et la paire de signature (Google).
pub struct Banc {
    /// La clé AES-256 de « déchiffrement », côté Play Console.
    pub kek: [u8; 32],
    /// La clé de signature « de Google ».
    pub signature: SigningKey,
}

impl Banc {
    pub fn nouveau() -> Self {
        Self::nouveau_avec(0x51)
    }

    pub fn nouveau_avec(graine: u8) -> Self {
        Self {
            kek: [0x4B; 32],
            signature: SigningKey::from_bytes(&[graine; 32].into()).expect("un scalaire"),
        }
    }

    /// La clé de vérification, en SPKI DER — ce que la Console donnerait.
    ///
    /// Bâti à la main : le préfixe SPKI d'une clé P-256 est fixe, et le point
    /// non compressé le complète. Cela évite d'exiger d'`asl-play` un encodeur
    /// qu'il n'a pas besoin d'avoir pour la production.
    pub fn verification_spki(&self) -> alloc::vec::Vec<u8> {
        const PREFIXE: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let point = self.signature.verifying_key().to_sec1_point(false);
        let mut der = PREFIXE.to_vec();
        der.extend_from_slice(point.as_bytes());
        der
    }

    /// Fabrique un jeton complet à partir d'un verdict JSON.
    pub fn jeton(&self, verdict: &[u8]) -> alloc::string::String {
        let jws = self.signer(verdict);
        self.envelopper(jws.as_bytes(), &self.kek)
    }

    /// Fabrique le JWS signé (ES256) autour d'un verdict.
    pub fn signer(&self, verdict: &[u8]) -> alloc::string::String {
        self.signer_avec_entete(br#"{"alg":"ES256"}"#, verdict)
    }

    /// Fabrique un JWS avec un en-tête choisi.
    pub fn signer_avec_entete(&self, entete_json: &[u8], verdict: &[u8]) -> alloc::string::String {
        let entete = b64(entete_json);
        let charge = b64(verdict);
        let signe = alloc::format!("{entete}.{charge}");
        let signature: Signature = self.signature.sign(signe.as_bytes());
        alloc::format!("{signe}.{}", b64(&signature.to_bytes()))
    }

    /// Un JWS dont la signature n'a pas la bonne longueur.
    pub fn jws_signature_courte(&self, verdict: &[u8]) -> alloc::string::String {
        let entete = b64(br#"{"alg":"ES256"}"#);
        let charge = b64(verdict);
        alloc::format!("{entete}.{charge}.{}", b64(&[0x00_u8; 10]))
    }

    /// Enveloppe un contenu dans un JWE `A256KW` + `A256GCM`, avec cette KEK.
    pub fn envelopper(&self, contenu: &[u8], kek: &[u8; 32]) -> alloc::string::String {
        self.envelopper_avec_entete(br#"{"alg":"A256KW","enc":"A256GCM"}"#, contenu, kek)
    }

    /// Enveloppe avec un en-tête choisi (pour éprouver les refus d'enveloppe).
    pub fn envelopper_avec_entete(
        &self,
        entete_json: &[u8],
        contenu: &[u8],
        kek: &[u8; 32],
    ) -> alloc::string::String {
        let entete = b64(entete_json);
        let cek = [0x2E_u8; 32];
        let emballee = emballer(kek, &cek);
        let iv = [0x77_u8; 12];

        let mut chiffre = contenu.to_vec();
        let cipher = Aes256Gcm::new_from_slice(&cek).expect("clé");
        let nonce = Nonce::<Aes256Gcm>::try_from(&iv[..]).expect("iv");
        let tag = cipher
            .encrypt_inout_detached(&nonce, entete.as_bytes(), (&mut chiffre[..]).into())
            .expect("chiffrement");

        alloc::format!(
            "{entete}.{}.{}.{}.{}",
            b64(&emballee),
            b64(&iv),
            b64(&chiffre),
            b64(&tag)
        )
    }
}

/// AES-256 Key Wrap (RFC 3394 §2.2.1), l'emballage. Le pendant du déballage de
/// `asl-play`, écrit ici pour le banc.
pub fn emballer(kek: &[u8; 32], cle: &[u8; 32]) -> [u8; 40] {
    let chiffre = Aes256::new(&Array::from(*kek));
    let n = 4;
    let mut a: [u8; 8] = [0xA6; 8];
    let mut r = [[0_u8; 8]; 4];
    for (bloc, morceau) in r.iter_mut().zip(cle.as_chunks::<8>().0) {
        bloc.copy_from_slice(morceau);
    }
    for j in 0..6 {
        for (i, bloc_r) in r.iter_mut().enumerate() {
            let mut bloc = [0_u8; 16];
            bloc[..8].copy_from_slice(&a);
            bloc[8..].copy_from_slice(bloc_r);
            let mut chiffrement = Array::from(bloc);
            chiffre.encrypt_block(&mut chiffrement);
            a.copy_from_slice(&chiffrement[..8]);
            bloc_r.copy_from_slice(&chiffrement[8..]);
            let t = (n * j + i + 1) as u64;
            for (k, octet) in t.to_be_bytes().iter().enumerate() {
                a[k] ^= octet;
            }
        }
    }
    let mut sortie = [0_u8; 40];
    sortie[..8].copy_from_slice(&a);
    for (i, bloc) in r.iter().enumerate() {
        sortie[8 + i * 8..16 + i * 8].copy_from_slice(bloc);
    }
    sortie
}
