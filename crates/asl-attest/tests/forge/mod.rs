//! De quoi ÉCRIRE du CBOR, pour éprouver ce qui le lit.
//!
//! # POURQUOI UN ENCODEUR ICI ET PAS DANS LA CRATE
//!
//! Rien, dans ce produit, n'émet d'attestation : c'est l'appareil qui en
//! fabrique une, et le serveur qui la lit. Un encodeur livré serait du code que
//! la production n'appelle jamais, et qu'il faudrait pourtant couvrir.
//!
//! Celui-ci vit donc dans les essais, et il est VOLONTAIREMENT NAÏF : il écrit
//! ce qu'on lui dit, y compris des têtes non minimales et des types que le
//! lecteur refuse. C'est tout l'intérêt — un encodeur correct ne saurait pas
//! fabriquer ce qu'on veut voir refusé.

#![allow(dead_code)]

/// Une tête CBOR : un type majeur et l'entier qu'elle porte, en forme minimale.
#[must_use]
pub fn tete(majeur: u8, valeur: u64) -> Vec<u8> {
    let haut = majeur << 5;
    if valeur < 24 {
        return vec![haut | u8::try_from(valeur).expect("moins de 24")];
    }
    if valeur <= u64::from(u8::MAX) {
        return vec![haut | 24, u8::try_from(valeur).expect("tient sur un octet")];
    }
    if valeur <= u64::from(u16::MAX) {
        let mut octets = vec![haut | 25];
        octets.extend_from_slice(&u16::try_from(valeur).expect("deux octets").to_be_bytes());
        return octets;
    }
    if valeur <= u64::from(u32::MAX) {
        let mut octets = vec![haut | 26];
        octets.extend_from_slice(&u32::try_from(valeur).expect("quatre octets").to_be_bytes());
        return octets;
    }
    let mut octets = vec![haut | 27];
    octets.extend_from_slice(&valeur.to_be_bytes());
    octets
}

/// Une tête d'une largeur IMPOSÉE, minimale ou non.
///
/// `largeur` vaut 1, 2, 4 ou 8. C'est ce qui fabrique un encodage non minimal.
#[must_use]
pub fn tete_large(majeur: u8, valeur: u64, largeur: usize) -> Vec<u8> {
    let haut = majeur << 5;
    let info = match largeur {
        1 => 24,
        2 => 25,
        4 => 26,
        _ => 27,
    };
    let mut octets = vec![haut | info];
    let brut = valeur.to_be_bytes();
    octets.extend_from_slice(&brut[brut.len().saturating_sub(largeur)..]);
    octets
}

/// Un entier non signé.
#[must_use]
pub fn entier(valeur: u64) -> Vec<u8> {
    tete(0, valeur)
}

/// Une chaîne d'octets.
#[must_use]
pub fn octets(contenu: &[u8]) -> Vec<u8> {
    let mut sortie = tete(2, u64::try_from(contenu.len()).expect("une longueur"));
    sortie.extend_from_slice(contenu);
    sortie
}

/// Une chaîne de texte.
#[must_use]
pub fn texte(contenu: &str) -> Vec<u8> {
    let mut sortie = tete(3, u64::try_from(contenu.len()).expect("une longueur"));
    sortie.extend_from_slice(contenu.as_bytes());
    sortie
}

/// L'en-tête d'un tableau de `combien` éléments.
#[must_use]
pub fn tableau(combien: u64) -> Vec<u8> {
    tete(4, combien)
}

/// L'en-tête d'une carte de `combien` couples.
#[must_use]
pub fn carte(combien: u64) -> Vec<u8> {
    tete(5, combien)
}

/// Concatène.
#[must_use]
pub fn suite(morceaux: &[Vec<u8>]) -> Vec<u8> {
    let mut sortie = Vec::new();
    for morceau in morceaux {
        sortie.extend_from_slice(morceau);
    }
    sortie
}

/// Les données d'authentificateur, à la disposition de WebAuthn.
///
/// `cle` porte `(aaguid, identifiant, clé COSE)` quand le drapeau ATTESTE est
/// levé. **Rien ici ne vérifie la cohérence** : on veut pouvoir lever le
/// drapeau sans mettre la clé, et l'inverse.
#[must_use]
pub fn donnees_auth(
    empreinte: &[u8],
    drapeaux: u8,
    compteur: u32,
    cle: Option<(&[u8], &[u8], &[u8])>,
) -> Vec<u8> {
    let mut sortie = empreinte.to_vec();
    sortie.push(drapeaux);
    sortie.extend_from_slice(&compteur.to_be_bytes());
    if let Some((aaguid, identifiant, cose)) = cle {
        sortie.extend_from_slice(aaguid);
        let longueur = u16::try_from(identifiant.len()).expect("un identifiant court");
        sortie.extend_from_slice(&longueur.to_be_bytes());
        sortie.extend_from_slice(identifiant);
        sortie.extend_from_slice(cose);
    }
    sortie
}

/// Un objet d'attestation, dont chaque morceau se remplace.
pub struct Attestation {
    /// La valeur de `fmt`.
    pub format: Option<String>,
    /// Les certificats de `x5c`, ou aucun tableau du tout.
    pub chaine: Option<Vec<Vec<u8>>>,
    /// Le reçu.
    pub recu: Option<Vec<u8>>,
    /// Les octets bruts d'`authData`.
    pub auth: Option<Vec<u8>>,
    /// Des couples de plus, écrits tels quels dans la carte du dessus.
    pub en_plus: Vec<Vec<u8>>,
}

impl Default for Attestation {
    fn default() -> Self {
        Self {
            format: Some("apple-appattest".to_owned()),
            chaine: Some(vec![vec![0xaa; 4], vec![0xbb; 4]]),
            recu: Some(vec![0xcc; 3]),
            auth: Some(donnees_auth(
                &[0x11; 32],
                0x40,
                0,
                Some((&[0x22; 16], &[0x33; 32], &[0xa5])),
            )),
            en_plus: Vec::new(),
        }
    }
}

impl Attestation {
    /// Écrit l'objet.
    #[must_use]
    pub fn ecrire(&self) -> Vec<u8> {
        let mut declaration = Vec::new();
        let mut couples_decl = 0_u64;
        if let Some(chaine) = &self.chaine {
            couples_decl = couples_decl.saturating_add(1);
            declaration.extend_from_slice(&texte("x5c"));
            declaration.extend_from_slice(&tableau(
                u64::try_from(chaine.len()).expect("une chaîne courte"),
            ));
            for der in chaine {
                declaration.extend_from_slice(&octets(der));
            }
        }
        if let Some(recu) = &self.recu {
            couples_decl = couples_decl.saturating_add(1);
            declaration.extend_from_slice(&texte("receipt"));
            declaration.extend_from_slice(&octets(recu));
        }

        let mut sortie = Vec::new();
        let mut couples = u64::try_from(self.en_plus.len()).expect("peu de couples");
        let mut corps = Vec::new();
        if let Some(format) = &self.format {
            couples = couples.saturating_add(1);
            corps.extend_from_slice(&texte("fmt"));
            corps.extend_from_slice(&texte(format));
        }
        couples = couples.saturating_add(1);
        corps.extend_from_slice(&texte("attStmt"));
        corps.extend_from_slice(&carte(couples_decl));
        corps.extend_from_slice(&declaration);
        if let Some(auth) = &self.auth {
            couples = couples.saturating_add(1);
            corps.extend_from_slice(&texte("authData"));
            corps.extend_from_slice(&octets(auth));
        }
        for couple in &self.en_plus {
            corps.extend_from_slice(couple);
        }
        sortie.extend_from_slice(&carte(couples));
        sortie.extend_from_slice(&corps);
        sortie
    }
}
