//! De quoi assembler une attestation depuis les pièces du banc.
//!
//! Les certificats, le défi et les données d'authentificateur viennent de
//! `fixtures/`, fabriqués par `fabriquer.py` et COMMITÉS : un essai ne dépend
//! pas d'un `openssl` présent. Ce module les lit et les emballe en CBOR.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

/// Le 1er juin 2026 : dans la validité des certificats du banc.
pub const PENDANT: u64 = 1_780_272_000;

/// L'identifiant d'app que `fabriquer.py` a condensé dans `authData`.
pub const IDENTIFIANT_APP: &str = "ABCDE12345.ch.narro.essai";

/// Lit une pièce du banc.
pub fn piece(nom: &str) -> Vec<u8> {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("tests/fixtures");
    chemin.push(nom);
    fs::read(&chemin).unwrap_or_else(|faute| panic!("pièce {chemin:?} illisible : {faute}"))
}

fn tete(majeur: u8, valeur: usize) -> Vec<u8> {
    let haut = majeur << 5;
    if valeur < 24 {
        return vec![haut | u8::try_from(valeur).expect("moins de 24")];
    }
    if valeur <= usize::from(u8::MAX) {
        return vec![haut | 24, u8::try_from(valeur).expect("un octet")];
    }
    let mut sortie = vec![haut | 25];
    sortie.extend_from_slice(&u16::try_from(valeur).expect("deux octets").to_be_bytes());
    sortie
}

fn texte(s: &str) -> Vec<u8> {
    let mut sortie = tete(3, s.len());
    sortie.extend_from_slice(s.as_bytes());
    sortie
}

fn octets(o: &[u8]) -> Vec<u8> {
    let mut sortie = tete(2, o.len());
    sortie.extend_from_slice(o);
    sortie
}

/// Un objet d'attestation : `fmt`, `attStmt { x5c, receipt }`, `authData`.
pub fn attestation(chaine: &[&[u8]], auth: &[u8]) -> Vec<u8> {
    let mut sortie = tete(5, 3);
    sortie.extend_from_slice(&texte("fmt"));
    sortie.extend_from_slice(&texte("apple-appattest"));
    sortie.extend_from_slice(&texte("attStmt"));
    sortie.extend_from_slice(&tete(5, 2));
    sortie.extend_from_slice(&texte("x5c"));
    sortie.extend_from_slice(&tete(4, chaine.len()));
    for der in chaine {
        sortie.extend_from_slice(&octets(der));
    }
    sortie.extend_from_slice(&texte("receipt"));
    sortie.extend_from_slice(&octets(b"recu"));
    sortie.extend_from_slice(&texte("authData"));
    sortie.extend_from_slice(&octets(auth));
    sortie
}

/// La chaîne canonique du banc : feuille, puis intermédiaire.
pub struct Banc {
    pub racine: Vec<u8>,
    pub intermediaire: Vec<u8>,
    pub feuille: Vec<u8>,
    pub auth: Vec<u8>,
    pub defi: Vec<u8>,
    pub cle: Vec<u8>,
}

impl Banc {
    pub fn charger() -> Self {
        Self {
            racine: piece("racine.der"),
            intermediaire: piece("intermediaire.der"),
            feuille: piece("feuille.der"),
            auth: piece("auth-data.bin"),
            defi: piece("defi.bin"),
            cle: piece("cle-feuille.bin"),
        }
    }

    /// L'objet complet et cohérent.
    pub fn objet(&self) -> Vec<u8> {
        attestation(&[&self.feuille, &self.intermediaire], &self.auth)
    }
}

/// Un élément DER : où commence son contenu, et où il finit.
///
/// Sert à trouver, dans un certificat, l'endroit exact d'une signature ou
/// d'une clé — pour l'abîmer.
pub fn der(octets: &[u8], depuis: usize) -> (usize, usize) {
    let a = |n: usize| depuis.checked_add(n).expect("dans les octets");
    let premier = octets[a(1)];
    let (longueur, apres) = match premier {
        0..=0x7F => (usize::from(premier), 2),
        0x81 => (usize::from(octets[a(2)]), 3),
        0x82 => (
            usize::from(u16::from_be_bytes([octets[a(2)], octets[a(3)]])),
            4,
        ),
        _ => panic!("longueur DER inattendue {premier:#04x}"),
    };
    let debut = a(apres);
    (debut, debut.checked_add(longueur).expect("dans les octets"))
}

/// Les trois enfants d'un certificat : `(tbs, algorithme, signature)`, chacun
/// comme `(début du contenu, fin)`.
pub fn enfants_du_certificat(cert: &[u8]) -> [(usize, usize); 3] {
    let (debut, _) = der(cert, 0);
    let tbs = der(cert, debut);
    let (_, fin_tbs) = tbs;
    let algorithme = der(cert, fin_tbs);
    let signature = der(cert, algorithme.1);
    [tbs, algorithme, signature]
}

/// Où commence, dans le certificat, le point public — l'octet `04` du point
/// non compressé, derrière `03 <longueur> 00`.
pub fn debut_du_point(cert: &[u8]) -> usize {
    let [(debut, fin), _, _] = enfants_du_certificat(cert);
    (debut..fin)
        .find(|&i| {
            matches!(
                cert.get(i..i.saturating_add(4)),
                Some([0x03, 0x42 | 0x62, 0x00, 0x04])
            )
        })
        .map(|i| i.saturating_add(3))
        .expect("un point public")
}

/// Encode une longueur DER.
pub fn longueur_der(n: usize) -> Vec<u8> {
    match n {
        0..=0x7F => vec![u8::try_from(n).expect("court")],
        0x80..=0xFF => vec![0x81, u8::try_from(n).expect("un octet")],
        _ => {
            let mut v = vec![0x82];
            v.extend_from_slice(&u16::try_from(n).expect("deux octets").to_be_bytes());
            v
        }
    }
}

/// Réemballe `(tbs, algorithme, signature)` en un certificat.
pub fn certificat(tbs_contenu: &[u8], algorithme: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut tbs = vec![0x30];
    tbs.extend_from_slice(&longueur_der(tbs_contenu.len()));
    tbs.extend_from_slice(tbs_contenu);
    let mut corps = tbs;
    corps.extend_from_slice(algorithme);
    corps.extend_from_slice(signature);
    let mut sortie = vec![0x30];
    sortie.extend_from_slice(&longueur_der(corps.len()));
    sortie.extend_from_slice(&corps);
    sortie
}
