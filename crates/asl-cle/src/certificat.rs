//! Le certificat d'identité d'un annuaire — `replication.md` décisions 53 à 55.
//!
//! # CE QU'IL EST, ET CE QU'IL N'EST PAS
//!
//! **Une enveloppe.** L'identité d'un annuaire EST sa clé d'identité Ed25519 —
//! celle d'où se déduit son `n-…` ([`identifiant_de_racine`]). TLS 1.3 ne sait
//! transporter une clé qu'à l'intérieur d'un certificat X.509 : RFC 7250 (les
//! clés brutes) ne passe pas par la pile QUIC que ce produit emploie (C15,
//! `annuaires.md` §2 quater). On emballe donc la clé dans le plus petit
//! certificat qui soit, **signé par elle-même**, et le client l'ouvre pour lire
//! la clé — rien d'autre (décision 53).
//!
//! Ce n'est **pas** une autorité, ni un nom, ni une date : le vérificateur
//! ignore l'émetteur, les dates et toute extension (décision 54). La date de
//! fin est la plus lointaine que RFC 5280 §4.1.2.5 sache écrire,
//! `99991231235959Z`, pour que les outils ordinaires ne le disent pas expiré.
//!
//! # POURQUOI UN GABARIT ÉCRIT À LA MAIN
//!
//! Décision 55 : aucune crate de génération X.509 (C4 interdit le C, et chaque
//! dépendance est un audit de plus). Le certificat a une forme **fixe** —
//! mêmes champs, mêmes longueurs pour toute clé —, donc un gabarit DER de
//! 271 octets où l'on pose le numéro de série, le nom `CN=n-…` (deux fois :
//! émetteur et sujet), la clé et la signature. Une forme fixe tient dans un
//! tableau : pas d'allocation, et cette crate reste `no_std` sans `alloc`.
//!
//! # LE LECTEUR EST AUSSI À LA MAIN, ET IL EST ÉTROIT
//!
//! [`cle_du_certificat`] lit N'IMPORTE QUEL certificat qu'un serveur présente
//! — c'est l'entrée d'un inconnu, d'où le fuzz — et n'en tire qu'une chose :
//! la clé publique, **si elle est Ed25519**. Il ne juge rien d'autre ; la
//! poignée de main TLS 1.3 prouve ensuite que le serveur tient cette clé
//! (RFC 8446 §4.4.3), et c'est ce couple qui fait l'identité.

use crate::{CLE_PUBLIQUE_OCTETS, ClePublique, CleSecrete, Faute, identifiant_de_racine};
use ed25519_dalek::Signer as _;

/// La taille, fixe, d'un certificat d'identité en DER.
pub const CERTIFICAT_D_IDENTITE_OCTETS: usize = 271;

/// La taille, fixe, de la clé d'identité en PKCS #8 (RFC 8410 §7).
pub const CLE_PKCS8_OCTETS: usize = 48;

/// L'algorithme Ed25519 (RFC 8410 §3) : `id-Ed25519`, OID 1.3.101.112, sans
/// paramètre — ni pour la clé, ni pour la signature.
const ALGORITHME_ED25519: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// Le début d'un `Name` à un seul `CN` UTF-8 de vingt-huit octets.
const DEBUT_DU_NOM: [u8; 13] = [
    0x30, 0x27, // Name ::= SEQUENCE (39)
    0x31, 0x25, // RelativeDistinguishedName ::= SET (37)
    0x30, 0x23, // AttributeTypeAndValue ::= SEQUENCE (35)
    0x06, 0x03, 0x55, 0x04, 0x03, // id-at-commonName
    0x0c, 0x1c, // UTF8String (28)
];

/// La validité : de 1970 à la fin de l'an 9999 (décision 54).
///
/// `notBefore` en `UTCTime` (RFC 5280 §4.1.2.5 : jusqu'à 2049), `notAfter` en
/// `GeneralizedTime` — la seule forme qui porte l'an 9999.
const VALIDITE: [u8; 34] = [
    0x30, 0x20, // Validity ::= SEQUENCE (32)
    0x17, 0x0d, b'7', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x18,
    0x0f, b'9', b'9', b'9', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5', b'9', b'Z',
];

/// Le début de la clé publique : `SubjectPublicKeyInfo` Ed25519 (RFC 8410 §4).
const DEBUT_DE_LA_CLE: [u8; 12] = [
    0x30, 0x2a, // SubjectPublicKeyInfo ::= SEQUENCE (42)
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier
    0x03, 0x21, 0x00, // BIT STRING (33), aucun bit inutilisé
];

/// La longueur du `TBSCertificate` : 190 octets de contenu, trois d'en-tête.
const TBS_OCTETS: usize = 193;

/// Frappe le certificat d'identité de cette clé.
///
/// Déterministe : Ed25519 signe sans aléa (RFC 8032), et tout le reste se
/// déduit de la clé. Deux démarrages frappent donc le même certificat, octet
/// pour octet — ce qu'un essai tient.
#[must_use]
pub fn certificat_d_identite(cle: &CleSecrete) -> [u8; CERTIFICAT_D_IDENTITE_OCTETS] {
    let publique = cle.publique().octets();
    let nom = identifiant_de_racine(&cle.publique()).texte();
    let nom = nom.as_str().as_bytes();

    let mut tbs = [0_u8; TBS_OCTETS];
    let mut ecrit = 0_usize;
    let mut poser = |octets: &[u8]| {
        for (place, octet) in tbs.iter_mut().skip(ecrit).zip(octets) {
            *place = *octet;
        }
        ecrit = ecrit.saturating_add(octets.len());
    };
    poser(&[0x30, 0x81, 0xbe]); // TBSCertificate ::= SEQUENCE (190)
    poser(&[0xa0, 0x03, 0x02, 0x01, 0x02]); // version [0] EXPLICIT v3
    poser(&[0x02, 0x10]); // serialNumber ::= INTEGER (16)
    poser(&numero_de_serie(&publique));
    poser(&ALGORITHME_ED25519); // signature
    poser(&DEBUT_DU_NOM); // issuer
    poser(nom);
    poser(&VALIDITE);
    poser(&DEBUT_DU_NOM); // subject
    poser(nom);
    poser(&DEBUT_DE_LA_CLE);
    poser(&publique);

    let signature = cle.0.sign(&tbs).to_bytes();

    let mut certificat = [0_u8; CERTIFICAT_D_IDENTITE_OCTETS];
    let mut ecrit = 0_usize;
    let mut poser = |octets: &[u8]| {
        for (place, octet) in certificat.iter_mut().skip(ecrit).zip(octets) {
            *place = *octet;
        }
        ecrit = ecrit.saturating_add(octets.len());
    };
    poser(&[0x30, 0x82, 0x01, 0x0b]); // Certificate ::= SEQUENCE (267)
    poser(&tbs);
    poser(&ALGORITHME_ED25519); // signatureAlgorithm
    poser(&[0x03, 0x41, 0x00]); // signatureValue ::= BIT STRING (65)
    poser(&signature);
    certificat
}

/// Le numéro de série : seize octets tirés de la clé, rendus positifs.
///
/// RFC 5280 §4.1.2.2 veut un entier positif ; DER veut l'écriture la plus
/// courte. Le premier octet forcé dans `0x40..=0x7f` satisfait les deux : bit
/// de signe à zéro, et jamais un zéro de tête.
fn numero_de_serie(cle: &[u8; CLE_PUBLIQUE_OCTETS]) -> [u8; 16] {
    let mut serie = [0_u8; 16];
    for (place, octet) in serie.iter_mut().zip(cle) {
        *place = *octet;
    }
    serie[0] = (serie[0] & 0x3f) | 0x40;
    serie
}

/// La clé d'identité en PKCS #8 (RFC 8410 §7) — ce que `rustls` sait charger.
///
/// **Ce sont les octets SECRETS.** L'appelant les donne au chargeur de clés
/// TLS et ne les garde pas ; ils ne vont jamais sur le disque par cette voie.
#[must_use]
pub fn cle_pkcs8(cle: &CleSecrete) -> [u8; CLE_PKCS8_OCTETS] {
    const DEBUT: [u8; 16] = [
        0x30, 0x2e, // PrivateKeyInfo ::= SEQUENCE (46)
        0x02, 0x01, 0x00, // version 0
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // id-Ed25519
        0x04, 0x22, 0x04, 0x20, // OCTET STRING { OCTET STRING (32) }
    ];
    let mut pkcs8 = [0_u8; CLE_PKCS8_OCTETS];
    for (place, octet) in pkcs8
        .iter_mut()
        .zip(DEBUT.iter().chain(cle.0.to_bytes().iter()))
    {
        *place = *octet;
    }
    pkcs8
}

/// Lit la clé publique Ed25519 d'un certificat X.509 en DER.
///
/// **N'importe quel certificat** : celui qu'un serveur présente, venu de
/// n'importe qui. On descend jusqu'à `subjectPublicKeyInfo` sans juger ce
/// qu'on traverse ; on n'accepte qu'une clé Ed25519 sans paramètre, et un
/// certificat sans octet de trop.
///
/// # Erreurs
///
/// [`Faute::CertificatIllisible`] pour un DER mal formé ou une clé qui n'est pas
/// Ed25519 ; [`Faute::ClePubliqueInvalide`] pour trente-deux octets qui ne sont
/// pas un point de la courbe.
pub fn cle_du_certificat(der: &[u8]) -> Result<ClePublique, Faute> {
    let (certificat, reste) = element(der, 0x30)?;
    if !reste.is_empty() {
        return Err(Faute::CertificatIllisible);
    }
    let (mut tbs, _) = element(certificat, 0x30)?;
    // La version, facultative (v1 l'omet) : `[0] EXPLICIT`.
    if tbs.first() == Some(&0xa0) {
        tbs = element(tbs, 0xa0)?.1;
    }
    // serialNumber, signature, issuer, validity, subject : traversés.
    for etiquette in [0x02, 0x30, 0x30, 0x30, 0x30] {
        tbs = element(tbs, etiquette)?.1;
    }
    let (spki, _) = element(tbs, 0x30)?;
    let (algorithme, cle) = element(spki, 0x30)?;
    if algorithme != &ALGORITHME_ED25519[2..] {
        return Err(Faute::CertificatIllisible);
    }
    let (bits, reste) = element(cle, 0x03)?;
    match (bits.split_first(), reste.is_empty()) {
        (Some((0, octets)), true) => {
            let octets: [u8; CLE_PUBLIQUE_OCTETS] =
                octets.try_into().map_err(|_| Faute::CertificatIllisible)?;
            ClePublique::depuis_octets(octets)
        }
        _ => Err(Faute::CertificatIllisible),
    }
}

/// Un élément DER d'étiquette `etiquette` en tête de `octets` : son contenu, et
/// ce qui le suit.
///
/// **Longueurs courtes, ou longues sur un ou deux octets** — un certificat
/// dépasse rarement quelques kilo-octets, et plus serait une entrée hostile.
/// L'écriture la plus courte est exigée (DER, X.690 §10.1).
fn element(octets: &[u8], etiquette: u8) -> Result<(&[u8], &[u8]), Faute> {
    let (&lue, reste) = octets.split_first().ok_or(Faute::CertificatIllisible)?;
    if lue != etiquette {
        return Err(Faute::CertificatIllisible);
    }
    let (&premier, reste) = reste.split_first().ok_or(Faute::CertificatIllisible)?;
    let (longueur, reste) = match premier {
        court @ 0..=0x7f => (usize::from(court), reste),
        0x81 => match reste.split_first() {
            Some((&un, suite)) if un >= 0x80 => (usize::from(un), suite),
            _ => return Err(Faute::CertificatIllisible),
        },
        0x82 => match reste {
            [haut, bas, suite @ ..] if *haut != 0 => {
                (usize::from(*haut) << 8 | usize::from(*bas), suite)
            }
            _ => return Err(Faute::CertificatIllisible),
        },
        _ => return Err(Faute::CertificatIllisible),
    };
    if reste.len() < longueur {
        return Err(Faute::CertificatIllisible);
    }
    Ok(reste.split_at(longueur))
}

#[cfg(test)]
mod tests {
    use super::{CERTIFICAT_D_IDENTITE_OCTETS, TBS_OCTETS};

    /// La longueur du nom `n-…` : deux lettres et vingt-six caractères.
    const NOM_OCTETS: usize = 28;

    #[test]
    fn les_longueurs_du_gabarit_se_tiennent() {
        // 190 octets de contenu + 3 d'en-tête ; 267 + 4 pour le certificat.
        assert_eq!(
            TBS_OCTETS,
            3 + 5 + 18 + 7 + (13 + NOM_OCTETS) * 2 + 34 + 12 + 32
        );
        assert_eq!(CERTIFICAT_D_IDENTITE_OCTETS, 4 + TBS_OCTETS + 7 + 3 + 64);
    }
}
