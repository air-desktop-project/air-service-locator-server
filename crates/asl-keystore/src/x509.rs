//! Ce qu'on lit dans la feuille, et que `webpki` ne rend pas.
//!
//! `webpki` vérifie la chaîne et s'arrête là : il n'expose ni la clé publique
//! de la feuille, ni ses extensions. Or c'est là que vit ce que le Keystore
//! atteste — la clé, et la `KeyDescription` dans l'extension
//! `1.3.6.1.4.1.11129.2.1.17`.
//!
//! # UN MARCHEUR DER, PAS UN ANALYSEUR X.509
//!
//! Le même que celui d'`asl-apple`, sur le lecteur de [`crate::der`] : on
//! DESCEND dans un DER dont la forme est connue (RFC 5280 §4.1) jusqu'à deux
//! endroits, et on refuse tout ce qui n'a pas la forme attendue.
//!
//! **CE MARCHEUR NE FAIT CONFIANCE À RIEN** : il tourne sur un certificat dont
//! `webpki` vient de vérifier la signature, mais un certificat bien signé peut
//! être mal formé là où `webpki` ne regarde pas. Toute borne est vérifiée.

use crate::Refus;
use crate::der::{self, BITS, BOOLEEN, Balise, OCTETS, OID, SEQUENCE};

/// `1.3.6.1.4.1.11129.2.1.17`, encodé : l'extension d'attestation de clé
/// d'Android.
const OID_DESCRIPTION: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11];

/// `1.2.840.10045.2.1`, encodé : `id-ecPublicKey`.
const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// `1.2.840.10045.3.1.7`, encodé : `prime256v1`, la courbe P-256.
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// `version [0] EXPLICIT`.
const VERSION: Balise = Balise::contextuelle(0);
/// `extensions [3] EXPLICIT`.
const EXTENSIONS: Balise = Balise::contextuelle(3);

/// La taille d'un point P-256 non compressé : `04 ‖ x ‖ y`.
pub const POINT_OCTETS: usize = 65;

/// Ce qu'on tire de la feuille.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feuille<'a> {
    /// Le point public P-256, non compressé, [`POINT_OCTETS`] octets.
    pub cle: &'a [u8],
    /// La `KeyDescription`, en DER, telle que l'extension la porte — si elle
    /// y est. C'est [`crate::description::lire`] qui la lit.
    pub description: Option<&'a [u8]>,
}

impl From<der::Faute> for Refus {
    fn from(_: der::Faute) -> Self {
        Self::CertificatIllisible
    }
}

/// Descend dans la feuille jusqu'à sa clé et son extension d'attestation.
///
/// # Erreurs
///
/// [`Refus::CertificatIllisible`] si la forme n'est pas celle de RFC 5280,
/// [`Refus::CleInattendue`] si la clé n'est pas un point P-256.
pub fn lire(der: &[u8]) -> Result<Feuille<'_>, Refus> {
    let (certificat, _) = der::attendu(der, SEQUENCE)?;
    let (tbs, _) = der::attendu(certificat, SEQUENCE)?;

    // version [0] EXPLICIT, facultative : absente, c'est un certificat v1, et
    // le premier élément est déjà le numéro de série.
    let (premier, apres_version) = der::element(tbs)?;
    let reste = if premier.balise == VERSION {
        apres_version
    } else {
        tbs
    };
    let (_, reste) = der::attendu(reste, der::ENTIER)?; // serialNumber
    let (_, reste) = der::attendu(reste, SEQUENCE)?; // signature
    let (_, reste) = der::attendu(reste, SEQUENCE)?; // issuer
    let (_, reste) = der::attendu(reste, SEQUENCE)?; // validity
    let (_, reste) = der::attendu(reste, SEQUENCE)?; // subject
    let (spki, mut reste) = der::attendu(reste, SEQUENCE)?; // subjectPublicKeyInfo

    let cle = cle_p256(spki)?;

    // issuerUniqueID [1], subjectUniqueID [2], extensions [3] : on cherche [3].
    let mut description = None;
    while !reste.is_empty() {
        let (lu, suite) = der::element(reste)?;
        if lu.balise == EXTENSIONS {
            description = description_des_extensions(lu.contenu)?;
        }
        reste = suite;
    }

    Ok(Feuille { cle, description })
}

/// Le point public, si l'algorithme est bien EC sur P-256.
fn cle_p256(spki: &[u8]) -> Result<&[u8], Refus> {
    let (algorithme, reste) = der::attendu(spki, SEQUENCE)?;
    let (famille, parametres) = der::attendu(algorithme, OID)?;
    let (courbe, _) = der::attendu(parametres, OID)?;
    if famille != OID_EC || courbe != OID_P256 {
        return Err(Refus::CleInattendue);
    }
    let (bits, _) = der::attendu(reste, BITS)?;
    // Un BIT STRING commence par le nombre de bits inutilisés : zéro ici.
    let (inutilises, point) = bits.split_first().ok_or(Refus::CertificatIllisible)?;
    if *inutilises != 0 || point.len() != POINT_OCTETS || point.first() != Some(&0x04) {
        return Err(Refus::CleInattendue);
    }
    Ok(point)
}

/// Parcourt `SEQUENCE OF Extension` et rend le contenu de l'extension
/// d'attestation — l'OCTET STRING qui enveloppe la `KeyDescription`.
fn description_des_extensions(contexte: &[u8]) -> Result<Option<&[u8]>, Refus> {
    let (mut liste, _) = der::attendu(contexte, SEQUENCE)?;
    while !liste.is_empty() {
        let (extension, suite) = der::attendu(liste, SEQUENCE)?;
        liste = suite;
        let (identifiant, reste) = der::attendu(extension, OID)?;
        if identifiant != OID_DESCRIPTION {
            continue;
        }
        // critical BOOLEAN, facultatif
        let (lu, apres_critique) = der::element(reste)?;
        let reste = if lu.balise == BOOLEEN {
            apres_critique
        } else {
            reste
        };
        let (valeur, _) = der::attendu(reste, OCTETS)?;
        return Ok(Some(valeur));
    }
    Ok(None)
}

/// Compresse un point P-256 non compressé (`04 ‖ x ‖ y`) en sa forme SEC1
/// compressée (`02|03 ‖ x`) — celle que le fil porte pour une clé d'appareil.
///
/// Le préfixe dit la parité de `y` ; `x` est recopié tel quel. Aucune
/// arithmétique de courbe : c'est la clé de la feuille, dont `webpki` vient de
/// vérifier qu'elle est bien celle qu'une chaîne a signée, et l'on compare des
/// octets à des octets.
#[must_use]
pub fn compresser(point: &[u8; POINT_OCTETS]) -> [u8; 33] {
    let mut compresse = [0_u8; 33];
    compresse[0] = 0x02 | (point[POINT_OCTETS - 1] & 0x01);
    compresse[1..].copy_from_slice(&point[1..33]);
    compresse
}
