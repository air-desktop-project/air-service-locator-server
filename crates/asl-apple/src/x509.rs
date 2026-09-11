//! Ce qu'on lit dans la feuille, et que `webpki` ne rend pas.
//!
//! `webpki` vérifie la chaîne et s'arrête là : il n'expose ni la clé publique
//! de la feuille, ni ses extensions. Or c'est là que vit ce qu'Apple atteste —
//! la clé, et le nonce dans l'extension `1.2.840.113635.100.8.2`.
//!
//! # UN MARCHEUR DER, PAS UN ANALYSEUR X.509
//!
//! On ne décode pas un certificat. On DESCEND dans un DER dont la forme est
//! connue (RFC 5280 §4.1) jusqu'à deux endroits, et on refuse tout ce qui n'a
//! pas la forme attendue. C'est le même choix que le lecteur CBOR
//! d'`asl-attest`, pour la même raison : ce graphe porte assez de paquets.
//!
//! **CE MARCHEUR NE FAIT CONFIANCE À RIEN** : il tourne sur un certificat dont
//! `webpki` vient de vérifier la signature, mais un certificat bien signé peut
//! être mal formé là où `webpki` ne regarde pas. Toute borne est vérifiée.

use crate::Refus;

/// `1.2.840.113635.100.8.2`, encodé : l'extension d'Apple qui porte le nonce.
const OID_NONCE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x08, 0x02];

/// `1.2.840.10045.2.1`, encodé : `id-ecPublicKey`.
const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// `1.2.840.10045.3.1.7`, encodé : `prime256v1`, la courbe P-256.
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

const SEQUENCE: u8 = 0x30;
const ENTIER: u8 = 0x02;
const OCTETS: u8 = 0x04;
const OID: u8 = 0x06;
const BITS: u8 = 0x03;
const VERSION: u8 = 0xA0;
const EXTENSIONS: u8 = 0xA3;
const CONTEXTE_1: u8 = 0xA1;

/// La taille d'un point P-256 non compressé : `04 ‖ x ‖ y`.
pub const POINT_OCTETS: usize = 65;

/// Ce qu'on tire de la feuille.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feuille<'a> {
    /// Le point public P-256, non compressé, [`POINT_OCTETS`] octets.
    pub cle: &'a [u8],
    /// Le nonce, 32 octets, s'il y est.
    pub nonce: Option<&'a [u8]>,
}

/// Un élément DER : sa balise et son contenu.
#[derive(Debug, Clone, Copy)]
struct Element<'a> {
    balise: u8,
    contenu: &'a [u8],
}

/// Lit un élément en tête de `octets`, et rend ce qui suit.
///
/// Balises sur un octet, longueurs sur au plus trois : c'est tout ce qu'un
/// certificat emploie, et le reste est refusé.
fn element(octets: &[u8]) -> Result<(Element<'_>, &[u8]), Refus> {
    let balise = *octets.first().ok_or(Refus::CertificatIllisible)?;
    let premier = *octets.get(1).ok_or(Refus::CertificatIllisible)?;
    let (longueur, apres): (usize, usize) = match premier {
        0..=0x7F => (usize::from(premier), 2),
        0x81 => (
            usize::from(*octets.get(2).ok_or(Refus::CertificatIllisible)?),
            3,
        ),
        0x82 => {
            let haut = *octets.get(2).ok_or(Refus::CertificatIllisible)?;
            let bas = *octets.get(3).ok_or(Refus::CertificatIllisible)?;
            (usize::from(u16::from_be_bytes([haut, bas])), 4)
        }
        _ => return Err(Refus::CertificatIllisible),
    };
    // L'en-tête vient d'être lu, donc `apres` est dans les octets : ce qui
    // peut manquer, c'est le CONTENU, et c'est le seul point de refus.
    let (contenu, reste) = octets
        .get(apres..)
        .unwrap_or(&[])
        .split_at_checked(longueur)
        .ok_or(Refus::CertificatIllisible)?;
    Ok((Element { balise, contenu }, reste))
}

/// Lit un élément et exige sa balise.
fn attendu(octets: &[u8], balise: u8) -> Result<(&[u8], &[u8]), Refus> {
    let (lu, reste) = element(octets)?;
    if lu.balise != balise {
        return Err(Refus::CertificatIllisible);
    }
    Ok((lu.contenu, reste))
}

/// Descend dans la feuille jusqu'à sa clé et son nonce.
///
/// # Erreurs
///
/// [`Refus::CertificatIllisible`] si la forme n'est pas celle de RFC 5280,
/// [`Refus::CleInattendue`] si la clé n'est pas un point P-256.
pub fn lire(der: &[u8]) -> Result<Feuille<'_>, Refus> {
    let (certificat, _) = attendu(der, SEQUENCE)?;
    let (tbs, _) = attendu(certificat, SEQUENCE)?;

    // version [0] EXPLICIT, facultative : absente, c'est un certificat v1, et
    // le premier élément est déjà le numéro de série.
    let (premier, apres_version) = element(tbs)?;
    let reste = if premier.balise == VERSION {
        apres_version
    } else {
        tbs
    };
    let (_, reste) = attendu(reste, ENTIER)?; // serialNumber
    let (_, reste) = attendu(reste, SEQUENCE)?; // signature
    let (_, reste) = attendu(reste, SEQUENCE)?; // issuer
    let (_, reste) = attendu(reste, SEQUENCE)?; // validity
    let (_, reste) = attendu(reste, SEQUENCE)?; // subject
    let (spki, mut reste) = attendu(reste, SEQUENCE)?; // subjectPublicKeyInfo

    let cle = cle_p256(spki)?;

    // issuerUniqueID [1], subjectUniqueID [2], extensions [3] : on cherche [3].
    let mut nonce = None;
    while !reste.is_empty() {
        let (lu, suite) = element(reste)?;
        if lu.balise == EXTENSIONS {
            nonce = nonce_des_extensions(lu.contenu)?;
        }
        reste = suite;
    }

    Ok(Feuille { cle, nonce })
}

/// Le point public, si l'algorithme est bien EC sur P-256.
fn cle_p256(spki: &[u8]) -> Result<&[u8], Refus> {
    let (algorithme, reste) = attendu(spki, SEQUENCE)?;
    let (famille, parametres) = attendu(algorithme, OID)?;
    let (courbe, _) = attendu(parametres, OID)?;
    if famille != OID_EC || courbe != OID_P256 {
        return Err(Refus::CleInattendue);
    }
    let (bits, _) = attendu(reste, BITS)?;
    // Un BIT STRING commence par le nombre de bits inutilisés : zéro ici.
    let (inutilises, point) = bits.split_first().ok_or(Refus::CertificatIllisible)?;
    if *inutilises != 0 || point.len() != POINT_OCTETS || point.first() != Some(&0x04) {
        return Err(Refus::CleInattendue);
    }
    Ok(point)
}

/// Parcourt `SEQUENCE OF Extension` et rend le nonce de l'extension d'Apple.
fn nonce_des_extensions(contexte: &[u8]) -> Result<Option<&[u8]>, Refus> {
    let (mut liste, _) = attendu(contexte, SEQUENCE)?;
    while !liste.is_empty() {
        let (extension, suite) = attendu(liste, SEQUENCE)?;
        liste = suite;
        let (identifiant, reste) = attendu(extension, OID)?;
        if identifiant != OID_NONCE {
            continue;
        }
        // critical BOOLEAN, facultatif
        let (lu, apres_critique) = element(reste)?;
        let reste = if lu.balise == 0x01 {
            apres_critique
        } else {
            reste
        };
        let (valeur, _) = attendu(reste, OCTETS)?;
        // SEQUENCE { [1] { OCTET STRING nonce } }
        let (sequence, _) = attendu(valeur, SEQUENCE)?;
        let (explicite, _) = attendu(sequence, CONTEXTE_1)?;
        let (nonce, _) = attendu(explicite, OCTETS)?;
        if nonce.len() != 32 {
            return Err(Refus::CertificatIllisible);
        }
        return Ok(Some(nonce));
    }
    Ok(None)
}
