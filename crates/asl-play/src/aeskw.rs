//! Déballage d'une clé emballée en AES-256 Key Wrap (RFC 3394).
//!
//! # POURQUOI CE CODE EXISTE
//!
//! Un jeton Play Integrity « standard » chiffre son contenu avec une clé de
//! session (la CEK), et emballe cette CEK avec la clé AES-256 que l'exploitant
//! tient de la Play Console — c'est l'algorithme `A256KW` de l'en-tête JWE.
//! Déballer, c'est appliquer RFC 3394 à l'envers.
//!
//! **C'est vingt lignes sur un chiffrement par blocs, pas une dépendance.** Le
//! même choix que le CBOR d'`asl-attest` et le base64url d'`asl-jwt` : `aes`
//! donne le bloc, et l'enrobage tient ici.
//!
//! On ne SAIT PAS emballer ici — seulement déballer. Personne, en production,
//! n'emballe une clé : c'est Google qui le fait. L'emballage vit au banc.

use aes::Aes256;
use aes::cipher::array::Array;
use aes::cipher::{BlockCipherDecrypt, KeyInit};

/// La taille d'une clé déballée (la CEK d'AES-256-GCM).
pub const CLE_OCTETS: usize = 32;

/// La taille de la clé EMBALLÉE : la CEK plus le demi-bloc de contrôle.
pub const EMBALLEE_OCTETS: usize = CLE_OCTETS + 8;

/// La valeur initiale par défaut de RFC 3394 §2.2.3.1 : le témoin d'intégrité.
const IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// Ce qui empêche de déballer une clé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// La clé emballée ne fait pas [`EMBALLEE_OCTETS`] octets.
    Longueur {
        /// Ce qui a été reçu.
        obtenue: usize,
    },
    /// Le témoin d'intégrité ne vaut pas ce qu'il doit : mauvaise clé, ou
    /// données modifiées.
    TemoinFaux,
}

/// Déballe `emballee` avec la clé `kek`, dans `sortie`.
///
/// # Erreurs
///
/// [`Faute::Longueur`] si l'entrée n'a pas la bonne taille, [`Faute::TemoinFaux`]
/// si le déballage ne restitue pas le témoin d'intégrité — ce qui arrive quand
/// la clé est fausse ou les octets modifiés.
pub fn deballer(
    kek: &[u8; CLE_OCTETS],
    emballee: &[u8],
    sortie: &mut [u8; CLE_OCTETS],
) -> Result<(), Faute> {
    if emballee.len() != EMBALLEE_OCTETS {
        return Err(Faute::Longueur {
            obtenue: emballee.len(),
        });
    }
    let chiffre = Aes256::new(&Array::from(*kek));

    // RFC 3394 §2.2.2. `n` demi-blocs de données ; ici quatre (32 octets).
    let n = CLE_OCTETS / 8;
    // `a` est le registre d'intégrité, `r[i]` les demi-blocs de données.
    let mut a = [0_u8; 8];
    a.copy_from_slice(&emballee[..8]);
    let mut r = [[0_u8; 8]; 4];
    for (i, bloc) in r.iter_mut().enumerate() {
        let debut = 8usize.saturating_mul(i.saturating_add(1));
        bloc.copy_from_slice(&emballee[debut..debut.saturating_add(8)]);
    }

    // Six tours, à l'envers (RFC 3394 §2.2.2).
    for j in (0..6).rev() {
        for i in (0..n).rev() {
            // t = n*j + (i+1)
            let t = n.saturating_mul(j).saturating_add(i.saturating_add(1));
            // A ^= t, sur les huit octets de poids fort d'un compteur 64 bits.
            let compteur = (t as u64).to_be_bytes();
            let mut bloc = [0_u8; 16];
            for (k, place) in bloc.iter_mut().enumerate().take(8) {
                *place = a[k] ^ compteur[k];
            }
            bloc[8..].copy_from_slice(&r[i]);
            let mut chiffrement = Array::from(bloc);
            chiffre.decrypt_block(&mut chiffrement);
            a.copy_from_slice(&chiffrement[..8]);
            r[i].copy_from_slice(&chiffrement[8..]);
        }
    }

    // Le registre d'intégrité doit valoir l'IV, en temps constant.
    let mut ecart = 0_u8;
    for (octet, attendu) in a.iter().zip(IV.iter()) {
        ecart |= octet ^ attendu;
    }
    if ecart != 0 {
        return Err(Faute::TemoinFaux);
    }
    for (i, bloc) in r.iter().enumerate() {
        let debut = 8usize.saturating_mul(i);
        sortie[debut..debut.saturating_add(8)].copy_from_slice(bloc);
    }
    Ok(())
}
