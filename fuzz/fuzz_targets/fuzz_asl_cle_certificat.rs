//! **Cible : le lecteur de certificat d'identité** (`asl_cle::cle_du_certificat`).
//!
//! # POURQUOI ELLE EXISTE
//!
//! Ces octets sont **le certificat qu'un serveur présente** à la poignée de
//! main : n'importe qui, avant qu'aucune identité ne soit prouvée. Le lecteur
//! est écrit à la main (décision 55), et c'est précisément ce qu'un fuzz sert à
//! garder : une longueur crue, un index d'un cran de trop.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, sur n'importe quels octets.
//! 2. **Un certificat frappé se relit**, et rend la clé frappée.
//! 3. **Un certificat frappé, altéré d'un octet dans la clé, ne rend jamais la
//!    clé d'origine** : le lecteur lit ce qui est écrit, rien d'autre.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asl_cle::{CleSecrete, certificat_d_identite, cle_du_certificat};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Des octets quelconques, pris pour un certificat.
    der: Vec<u8>,
    /// L'entropie d'une clé qu'on frappe.
    entropie: [u8; 32],
    /// Où altérer la clé frappée, et par quoi.
    rang: u8,
    masque: u8,
}

fuzz_target!(|entree: Entree| {
    // 1. Rien ne panique.
    let _ = cle_du_certificat(&entree.der);

    // 2. La frappe se relit.
    let secrete = CleSecrete::depuis_entropie(entree.entropie);
    let certificat = certificat_d_identite(&secrete);
    assert_eq!(cle_du_certificat(&certificat), Ok(secrete.publique()));

    // 3. Une clé altérée n'est plus la clé frappée. Les trente-deux octets de
    //    la clé commencent à 4 + 3 + 5 + 18 + 7 + 41 + 34 + 41 + 12 = 165.
    if entree.masque != 0 {
        let mut altere = certificat;
        let rang = 165 + usize::from(entree.rang % 32);
        altere[rang] ^= entree.masque;
        assert_ne!(cle_du_certificat(&altere), Ok(secrete.publique()));
    }
});
