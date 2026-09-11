//! **Cible : l'ouverture d'un jeton Play Integrity** — des octets quelconques,
//! avec des clés fixes, vers un verdict ou un refus.
//!
//! # POURQUOI ELLE COMPTE
//!
//! Ce jeton vient d'un appareil Android qu'on n'a pas choisi, sur le chemin qui
//! crée un compte, avant toute authentification. Il traverse trois couches
//! cryptographiques — déballage de clé, déchiffrement authentifié, signature —,
//! et chacune peut être nourrie de n'importe quoi.
//!
//! # LES PROPRIÉTÉS
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **Un refus est toujours nommé.**
//! 3. **L'OUVERTURE EST STABLE** : deux fois les mêmes octets, le même verdict.
//! 4. **AUCUN `Ok` NE SORT DE RIEN** : sans la bonne clé de déchiffrement ET la
//!    bonne signature, il n'y a pas de verdict. libFuzzer ne fabriquera pas un
//!    jeton valide par hasard — mais si jamais il en sortait un, ce serait une
//!    faille, et l'assertion la dirait.

#![no_main]

use libfuzzer_sys::fuzz_target;

use asl_play::{Clefs, Refus, ouvrir};

// Des clés FIXES, sans rapport avec quoi que ce soit que le fuzzer pourrait
// deviner : aucun jeton tiré au hasard ne s'ouvrira sous elles.
const KEK: [u8; 32] = [0x4B; 32];

// Un SPKI de clé P-256 bien formé (préfixe + point non compressé). La clé
// privée correspondante n'existe pas ici, donc aucune signature ne vérifiera —
// ce qui est exactement le point.
const SPKI: [u8; 91] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1,
    0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D,
    0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE,
    0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B,
    0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];

fn nomme(refus: &Refus) {
    assert!(matches!(
        refus,
        Refus::TropLong { .. }
            | Refus::Jwe(_)
            | Refus::Jws(_)
            | Refus::EnveloppeInattendue
            | Refus::IvInvalide
            | Refus::EtiquetteInvalide
            | Refus::Deballage(_)
            | Refus::Dechiffrement
            | Refus::SignatureInattendue
            | Refus::CleIllisible
            | Refus::SignatureFausse
    ));
}

fuzz_target!(|octets: &[u8]| {
    let clefs = Clefs {
        dechiffrement: &KEK,
        verification: &SPKI,
    };
    let verdict = ouvrir(octets, &clefs);
    assert_eq!(
        ouvrir(octets, &clefs),
        verdict,
        "l'ouverture n'est pas stable"
    );
    match verdict {
        Ok(_) => panic!("CONTREFAÇON : un jeton s'est ouvert sans la clé privée de signature"),
        Err(refus) => nomme(&refus),
    }
});
