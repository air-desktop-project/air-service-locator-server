//! Ce qu'un jeton Play Integrity PROUVE, une fois ouvert.
//!
//! # LA MÊME PLACE QUE `asl-apple`, POUR L'AUTRE PLATE-FORME
//!
//! `asl-jwt` découpe un jeton (JWS, ou JWE qui l'enveloppe) ; cette crate
//! l'OUVRE : elle déchiffre l'enveloppe, vérifie la signature de Google, et
//! rend les octets du verdict — sans jamais faire d'entrée-sortie. La lecture
//! du verdict et la décision qui s'ensuit viendront à côté.
//!
//! # LE JETON STANDARD, TEL QUE GOOGLE LE FORME
//!
//! Un jeton d'intégrité « standard », déchiffré côté serveur (et non côté
//! Google), est un **JWE** qui enveloppe un **JWS** :
//!
//! 1. Le JWE emballe une clé de session (AES-256 Key Wrap, `A256KW`) avec la
//!    clé de déchiffrement de la Play Console, et chiffre le contenu avec cette
//!    clé de session (AES-256-GCM, `A256GCM`).
//! 2. Le contenu déchiffré est un JWS signé par Google en ES256, dont la charge
//!    est le verdict.
//!
//! # CE QU'ON NE PEUT PAS ENCORE ÉPROUVER
//!
//! **AUCUN JETON RÉEL N'A ÉTÉ LU.** Toute la forme ci-dessus vient de la
//! documentation de Google et de la bibliothèque `jose4j` qu'elle emploie : que
//! l'emballage soit `A256KW` et non `dir`, que le chiffrement soit `A256GCM`,
//! que la signature soit ES256. Les essais éprouvent que le mécanisme est
//! correct sur un jeton qu'on fabrique nous-mêmes, avec nos propres clés. Ils
//! n'éprouvent pas que c'est ce que Google envoie. **Le premier vrai jeton
//! tranchera**, et il dira, par la faute exacte qu'il déclenche, ce qui diffère.

#![no_std]

extern crate alloc;

mod aeskw;
mod jws;

use alloc::vec;
use alloc::vec::Vec;

use asl_jwt::{Jwe, Jws};

pub use aeskw::Faute as FauteDeballage;
pub use jws::CleGoogle;

/// L'`alg` attendu d'un en-tête JWE : AES-256 Key Wrap.
const ALG_JWE: &[u8] = b"A256KW";
/// L'`enc` attendu d'un en-tête JWE : AES-256-GCM.
const ENC_JWE: &[u8] = b"A256GCM";

/// La taille d'un iv d'AES-GCM.
const IV_OCTETS: usize = 12;
/// La taille d'une étiquette d'AES-GCM.
const ETIQUETTE_OCTETS: usize = 16;

/// Le plus long jeton qu'on accepte d'ouvrir.
///
/// Un verdict tient dans quelques centaines d'octets ; huit kibioctets laissent
/// une marge large sans laisser un jeton se déployer sans fin sur le chemin qui
/// crée un compte, avant toute authentification.
pub const JETON_MAX: usize = 8192;

/// De quoi ouvrir un jeton, tel que l'exploitant le tient de la Play Console.
#[derive(Debug, Clone, Copy)]
pub struct Clefs<'a> {
    /// La clé de déchiffrement, 32 octets — celle qui déballe la clé de session.
    pub dechiffrement: &'a [u8; aeskw::CLE_OCTETS],
    /// La clé de vérification de Google, en SPKI DER (ce que la Play Console
    /// donne, base64 décodé).
    pub verification: &'a [u8],
}

/// Ce qui empêche d'ouvrir un jeton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refus {
    /// Le jeton est trop long pour être ouvert.
    TropLong {
        /// Sa taille.
        octets: usize,
    },
    /// Le jeton ne se découpe pas en un JWE.
    Jwe(asl_jwt::Erreur),
    /// Le jeton déchiffré ne se découpe pas en un JWS.
    Jws(asl_jwt::Erreur),
    /// L'en-tête JWE n'annonce pas `A256KW` + `A256GCM`.
    EnveloppeInattendue,
    /// L'iv n'a pas la taille d'un iv d'AES-GCM.
    IvInvalide,
    /// L'étiquette n'a pas la taille d'une étiquette d'AES-GCM.
    EtiquetteInvalide,
    /// La clé de session ne se déballe pas : mauvaise clé, ou jeton modifié.
    Deballage(aeskw::Faute),
    /// Le contenu ne se déchiffre pas, ou son authentification échoue.
    Dechiffrement,
    /// L'en-tête JWS n'annonce pas ES256.
    SignatureInattendue,
    /// La clé de vérification de Google ne se lit pas.
    CleIllisible,
    /// La signature de Google ne vérifie pas sur ce contenu.
    SignatureFausse,
}

impl core::fmt::Display for Refus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TropLong { octets } => write!(f, "jeton de {octets} octets, trop long"),
            Self::Jwe(erreur) => write!(f, "pas un JWE : {erreur}"),
            Self::Jws(erreur) => write!(f, "contenu déchiffré, mais pas un JWS : {erreur}"),
            Self::EnveloppeInattendue => f.write_str("enveloppe autre que A256KW + A256GCM"),
            Self::IvInvalide => f.write_str("iv de taille invalide"),
            Self::EtiquetteInvalide => f.write_str("étiquette de taille invalide"),
            Self::Deballage(faute) => write!(f, "clé de session non déballée : {faute:?}"),
            Self::Dechiffrement => f.write_str("déchiffrement ou authentification en échec"),
            Self::SignatureInattendue => f.write_str("en-tête de signature autre qu'ES256"),
            Self::CleIllisible => f.write_str("clé de vérification de Google illisible"),
            Self::SignatureFausse => f.write_str("signature de Google fausse"),
        }
    }
}

/// Ouvre un jeton Play Integrity et rend les octets de son verdict.
///
/// Déchiffre l'enveloppe JWE avec la clé de déchiffrement, vérifie la signature
/// ES256 du JWS avec la clé de Google, et rend la charge — le verdict JSON,
/// **non encore interprété**.
///
/// # Erreurs
///
/// Un [`Refus`] nommé, au premier pas qui échoue.
pub fn ouvrir(jeton: &[u8], clefs: &Clefs<'_>) -> Result<Vec<u8>, Refus> {
    if jeton.len() > JETON_MAX {
        return Err(Refus::TropLong {
            octets: jeton.len(),
        });
    }
    let jws_octets = dechiffrer(jeton, clefs.dechiffrement)?;
    let jws = Jws::lire(&jws_octets).map_err(Refus::Jws)?;
    if !entete_es256(&jws) {
        return Err(Refus::SignatureInattendue);
    }
    jws::verifier(&jws, clefs.verification)?;
    charge_decodee(&jws).map_err(Refus::Jws)
}

/// Déchiffre l'enveloppe JWE et rend le JWS qu'elle contenait.
fn dechiffrer(jeton: &[u8], kek: &[u8; aeskw::CLE_OCTETS]) -> Result<Vec<u8>, Refus> {
    let jwe = Jwe::lire(jeton).map_err(Refus::Jwe)?;
    if !entete_enveloppe(&jwe) {
        return Err(Refus::EnveloppeInattendue);
    }

    let cle_emballee = decoder(&jwe, JweSegment::Cle)?;
    let mut cek = [0_u8; aeskw::CLE_OCTETS];
    aeskw::deballer(kek, &cle_emballee, &mut cek).map_err(Refus::Deballage)?;

    // Les tailles sont fixées ICI, une fois : la construction du chiffreur ne
    // porte alors plus aucune branche d'erreur, un tableau de la bonne taille ne
    // pouvant pas la manquer.
    let iv: [u8; IV_OCTETS] = decoder(&jwe, JweSegment::Iv)?
        .as_slice()
        .try_into()
        .map_err(|_| Refus::IvInvalide)?;
    let etiquette: [u8; ETIQUETTE_OCTETS] = decoder(&jwe, JweSegment::Etiquette)?
        .as_slice()
        .try_into()
        .map_err(|_| Refus::EtiquetteInvalide)?;
    let mut chiffre = decoder(&jwe, JweSegment::Chiffre)?;

    use aes_gcm::Aes256Gcm;
    use aes_gcm::aead::{AeadInOut, KeyInit};
    // `cek`, `iv` et `etiquette` sont des tableaux de la taille exacte : aucune
    // de ces constructions ne peut échouer.
    let cipher = Aes256Gcm::new(&cek.into());
    let nonce = iv.into();
    let tag = etiquette.into();
    // **L'AAD EST L'EN-TÊTE PROTÉGÉ TEL QU'ÉCRIT** (RFC 7516 §5.1).
    cipher
        .decrypt_inout_detached(&nonce, jwe.entete_b64(), (&mut chiffre[..]).into(), &tag)
        .map_err(|_| Refus::Dechiffrement)?;
    Ok(chiffre)
}

/// Un segment de JWE qu'on décode.
#[derive(Clone, Copy)]
enum JweSegment {
    Cle,
    Iv,
    Chiffre,
    Etiquette,
}

/// Décode un segment de JWE dans un `Vec` de la bonne taille.
fn decoder(jwe: &Jwe<'_>, quel: JweSegment) -> Result<Vec<u8>, Refus> {
    let mut tampon = vec![0_u8; JETON_MAX];
    let ecrits = match quel {
        JweSegment::Cle => jwe.decoder_cle(&mut tampon),
        JweSegment::Iv => jwe.decoder_iv(&mut tampon),
        JweSegment::Chiffre => jwe.decoder_chiffre(&mut tampon),
        JweSegment::Etiquette => jwe.decoder_etiquette(&mut tampon),
    }
    .map_err(Refus::Jwe)?;
    tampon.truncate(ecrits);
    Ok(tampon)
}

/// La charge d'un JWS, décodée.
fn charge_decodee(jws: &Jws<'_>) -> Result<Vec<u8>, asl_jwt::Erreur> {
    let mut tampon = vec![0_u8; JETON_MAX];
    let ecrits = jws.decoder_charge(&mut tampon)?;
    tampon.truncate(ecrits);
    Ok(tampon)
}

/// L'en-tête JWE annonce-t-il l'enveloppe attendue ?
fn entete_enveloppe(jwe: &Jwe<'_>) -> bool {
    let mut tampon = [0_u8; 256];
    let Ok(ecrits) = jwe.decoder_entete(&mut tampon) else {
        return false;
    };
    let entete = &tampon[..ecrits];
    contient_valeur(entete, b"alg", ALG_JWE) && contient_valeur(entete, b"enc", ENC_JWE)
}

/// L'en-tête JWS annonce-t-il ES256 ?
fn entete_es256(jws: &Jws<'_>) -> bool {
    let mut tampon = [0_u8; 256];
    let Ok(ecrits) = jws.decoder_entete(&mut tampon) else {
        return false;
    };
    contient_valeur(&tampon[..ecrits], b"alg", b"ES256")
}

/// L'en-tête JSON porte-t-il `"<champ>":"<valeur>"` ?
///
/// **UNE RECHERCHE DE SOUS-CHAÎNE, ET C'EST ASSEZ ICI** : l'en-tête est un objet
/// JSON plat de deux ou trois champs, sans structure imbriquée où un champ
/// pourrait se cacher. La vérification vraie — la signature — ne dépend pas de
/// cette lecture ; celle-ci ne fait qu'écarter tôt un jeton d'un autre
/// algorithme, avec un message clair.
fn contient_valeur(entete: &[u8], champ: &[u8], valeur: &[u8]) -> bool {
    // Cherche `"champ"` puis `"valeur"` après.
    let mut motif = Vec::with_capacity(champ.len().saturating_add(2));
    motif.push(b'"');
    motif.extend_from_slice(champ);
    motif.push(b'"');
    let Some(apres) = trouver(entete, &motif) else {
        return false;
    };
    let reste = entete.get(apres..).unwrap_or(&[]);
    let mut cible = Vec::with_capacity(valeur.len().saturating_add(2));
    cible.push(b'"');
    cible.extend_from_slice(valeur);
    cible.push(b'"');
    trouver(reste, &cible).is_some()
}

/// La position juste après la première occurrence de `motif`, s'il y est.
fn trouver(foin: &[u8], motif: &[u8]) -> Option<usize> {
    if motif.is_empty() || foin.len() < motif.len() {
        return None;
    }
    let fin = foin.len().saturating_sub(motif.len());
    (0..=fin)
        .find(|&i| foin.get(i..i.saturating_add(motif.len())) == Some(motif))
        .map(|i| i.saturating_add(motif.len()))
}
