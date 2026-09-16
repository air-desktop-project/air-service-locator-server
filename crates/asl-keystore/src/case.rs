//! La case d'attestation de `POST /v1/comptes`, plate-forme `2` : des
//! certificats DER, feuille d'abord, chacun précédé de sa longueur.
//!
//! # LA FORME (`protocole.md` §2.1, décidé le 2026-09-16)
//!
//! ```text
//! longueur₀ (u16 grand-boutien) ‖ DER₀ ‖ longueur₁ ‖ DER₁ ‖ … ‖ longueurₙ ‖ DERₙ
//! ```
//!
//! `DER₀` est la feuille — le certificat de la clé qu'on enrôle. Les suivants
//! remontent vers la racine. **La racine peut être omise** : l'annuaire la tient
//! (`--android-roots`), et la remonter ne lui apprendrait rien ; elle peut aussi
//! être là, telle que `getCertificateChain` la rend, et elle est alors sans
//! effet.
//!
//! # POURQUOI DES LONGUEURS, ALORS QUE LE DER EN PORTE DÉJÀ
//!
//! Un DER dit sa propre taille — on pourrait enchaîner les certificats sans
//! rien entre eux. Mais découper la case exigerait alors de LIRE du DER pour
//! savoir où finit un certificat, et une faute de lecture couperait au mauvais
//! endroit sans qu'on sache lequel des deux, du découpage ou du certificat, a
//! failli. Une longueur devant chaque certificat rend le découpage indépendant
//! de ce qu'il découpe : `webpki` recevra des tranches, et c'est lui qui dira
//! si chacune est un certificat.
//!
//! **Aucune longueur n'est crue** : chacune est confrontée à ce qui reste, et
//! un dépassement est un refus nommé, jamais une lecture au-delà de la case.

use alloc::vec::Vec;

/// Ce qu'une case peut faire, au plus : la borne de `protocole.md` §2.1 bis,
/// égale à `asl_api::corps::ATTESTATION_MAX`. Une chaîne réelle en fait 3 421
/// (capture du 2026-09-16, quatre certificats, racine comprise).
pub const CASE_MAX: usize = 8192;

/// Combien de certificats une case peut porter, au plus.
///
/// `webpki` remonte au plus six intermédiaires ; une feuille, six
/// intermédiaires et une racine font huit. Une chaîne réelle en a quatre.
pub const CERTIFICATS_MAX: usize = 8;

/// Ce qui empêche de découper une case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// La case dépasse [`CASE_MAX`].
    TropLongue {
        /// Ce qu'elle fait.
        obtenue: usize,
    },
    /// Aucun certificat : pas même une longueur.
    Vide,
    /// Une longueur annonce plus d'octets qu'il n'en reste.
    Tronquee {
        /// Le rang du certificat, la feuille en zéro.
        rang: usize,
        /// Ce que la longueur annonce.
        annoncee: usize,
        /// Ce qui reste après elle.
        restant: usize,
    },
    /// Il reste un seul octet : une longueur qui ne tient pas sur ses deux.
    LongueurCoupee {
        /// Le rang du certificat qu'elle précédait.
        rang: usize,
    },
    /// Une longueur de zéro : un certificat vide n'en est pas un.
    CertificatVide {
        /// Son rang.
        rang: usize,
    },
    /// Plus de [`CERTIFICATS_MAX`] certificats.
    TropDeCertificats,
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TropLongue { obtenue } => {
                write!(f, "case de {obtenue} octets, {CASE_MAX} au plus")
            }
            Self::Vide => f.write_str("case vide"),
            Self::Tronquee {
                rang,
                annoncee,
                restant,
            } => write!(
                f,
                "certificat {rang} : {annoncee} octets annoncés, {restant} restants"
            ),
            Self::LongueurCoupee { rang } => {
                write!(f, "certificat {rang} : longueur coupée en deux")
            }
            Self::CertificatVide { rang } => write!(f, "certificat {rang} vide"),
            Self::TropDeCertificats => {
                write!(f, "plus de {CERTIFICATS_MAX} certificats")
            }
        }
    }
}

/// Une case découpée : la feuille, puis ce qui remonte vers la racine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chaine<'a> {
    /// Le certificat de la clé qu'on enrôle — il y en a toujours un.
    pub feuille: &'a [u8],
    /// Les suivants, dans l'ordre de la case : les intermédiaires, et la
    /// racine si l'appareil l'a mise.
    pub intermediaires: Vec<&'a [u8]>,
}

/// Découpe une case en ses certificats, feuille d'abord.
///
/// Chaque tranche rendue est une tranche de `case`, non interprétée.
///
/// # Erreurs
///
/// Une [`Faute`] nommée : la première qui rend le découpage impossible.
pub fn decouper(case: &[u8]) -> Result<Chaine<'_>, Faute> {
    if case.len() > CASE_MAX {
        return Err(Faute::TropLongue {
            obtenue: case.len(),
        });
    }
    if case.is_empty() {
        return Err(Faute::Vide);
    }
    let (feuille, mut reste) = un_certificat(case, 0)?;
    let mut intermediaires = Vec::new();
    while !reste.is_empty() {
        let rang = intermediaires.len().saturating_add(1);
        if rang == CERTIFICATS_MAX {
            return Err(Faute::TropDeCertificats);
        }
        let (der, suite) = un_certificat(reste, rang)?;
        intermediaires.push(der);
        reste = suite;
    }
    Ok(Chaine {
        feuille,
        intermediaires,
    })
}

/// Lit une longueur et le certificat qu'elle annonce ; rend ce qui suit.
fn un_certificat(octets: &[u8], rang: usize) -> Result<(&[u8], &[u8]), Faute> {
    let (longueur, apres) = octets
        .split_at_checked(2)
        .ok_or(Faute::LongueurCoupee { rang })?;
    let annoncee = usize::from(u16::from_be_bytes([longueur[0], longueur[1]]));
    if annoncee == 0 {
        return Err(Faute::CertificatVide { rang });
    }
    apres.split_at_checked(annoncee).ok_or(Faute::Tronquee {
        rang,
        annoncee,
        restant: apres.len(),
    })
}

/// Assemble une case depuis des certificats, feuille d'abord — l'inverse de
/// [`decouper`], pour les essais, les graines de fuzz et l'exemple.
///
/// Rend `None` si un certificat dépasse 65 535 octets ou si l'ensemble dépasse
/// [`CASE_MAX`] : ce qui ne se découperait pas ne s'assemble pas non plus.
#[must_use]
pub fn assembler(certificats: &[&[u8]]) -> Option<Vec<u8>> {
    let mut case = Vec::new();
    for der in certificats {
        let longueur = u16::try_from(der.len()).ok()?;
        case.extend_from_slice(&longueur.to_be_bytes());
        case.extend_from_slice(der);
    }
    (case.len() <= CASE_MAX).then_some(case)
}
