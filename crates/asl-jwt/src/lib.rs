//! Ce qu'un jeton JWS compact PORTE, avant qu'on vérifie quoi que ce soit.
//!
//! # CETTE CRATE NE VÉRIFIE AUCUNE SIGNATURE
//!
//! Elle lit. Un JWS compact est trois segments base64url séparés par des
//! points — `en-tête.charge.signature` (RFC 7515 §3.1) —, et c'est tout ce
//! qu'elle en dit. Est-ce que la signature vérifie, est-ce que l'en-tête
//! annonce l'algorithme attendu, est-ce que la charge dit la vérité : autant de
//! questions pour l'étage au-dessus, et elles ne se posent que sur un jeton
//! déjà découpé.
//!
//! C'est le même partage qu'entre `asl-attest` (la grammaire d'une attestation
//! Apple) et `asl-apple` (sa vérification), et pour la même raison : découper
//! un jeton et remonter une signature jusqu'à Google sont deux métiers, et les
//! fondre ferait qu'un jeton mal formé et un jeton non signé rendraient la même
//! faute. Ici, un jeton mal formé est une faute de GRAMMAIRE.
//!
//! # POURQUOI POUR PLAY INTEGRITY
//!
//! Google atteste l'intégrité d'une app et d'un appareil par un **jeton
//! d'intégrité** : un JWS dont la charge est un verdict JSON. La vérification
//! hors ligne de ce jeton — décrypter, vérifier la signature ES256, lire le
//! verdict — commence par le découper et décoder ses segments, et c'est ce que
//! fait cette crate.
//!
//! **RIEN ICI N'EST SPÉCIFIQUE À GOOGLE** : un JWS est un JWS. Ce qui est
//! propre à Play Integrity — quels champs le verdict porte, quelles clés le
//! signent — vit à l'étage au-dessus.
//!
//! # BASE64URL, ÉCRIT ICI
//!
//! Un JWS emploie base64url **sans remplissage** (RFC 7515 §2, RFC 4648 §5) :
//! l'alphabet `A–Z a–z 0–9 - _`, et pas de `=` en queue. Le décodeur est écrit
//! ici plutôt que tiré — trente lignes, pas de dépendance, et le même choix
//! qu'`asl-attest` pour le CBOR. **Il refuse tout le reste** : le `+` et le `/`
//! de base64 ordinaire, le remplissage, et une longueur qui ne peut pas être
//! celle d'un groupe base64url valide.

#![no_std]

mod base64url;
mod jwe;
mod jws;

pub use base64url::{decoder, longueur_decodee};
pub use jwe::Jwe;
pub use jws::Jws;

/// Ce qui empêche de lire un jeton.
///
/// **Ce ne sont pas des refus de sécurité** : un refus se décide ailleurs, sur
/// un jeton bien formé. Ce sont des octets qui ne forment pas un JWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Le jeton n'a pas exactement trois segments séparés par des points.
    PasTroisSegments {
        /// Combien de segments ont été comptés.
        comptes: usize,
    },
    /// Le jeton n'a pas exactement cinq segments séparés par des points.
    PasCinqSegments {
        /// Combien de segments ont été comptés.
        comptes: usize,
    },
    /// Un segment est vide : `a..b` ou `.a.b` n'ont pas d'en-tête, de charge ou
    /// de signature.
    SegmentVide {
        /// Lequel : 0 l'en-tête, 1 la charge, 2 la signature.
        rang: usize,
    },
    /// Un octet qui n'est pas de l'alphabet base64url.
    SymboleInvalide {
        /// Où, dans le jeton entier.
        position: usize,
    },
    /// Une longueur de segment impossible pour du base64url sans remplissage.
    ///
    /// Un groupe base64url fait un, deux, trois ou quatre symboles ; un seul
    /// symbole isolé ne code aucun octet, et c'est le seul reste interdit.
    LongueurImpossible {
        /// Le rang du segment.
        rang: usize,
    },
    /// Le tampon de sortie est trop petit pour le segment décodé.
    TamponTropPetit {
        /// Ce qu'il aurait fallu.
        attendu: usize,
    },
    /// Un symbole de remplissage `=` : base64url n'en porte pas ici.
    RemplissageRefuse {
        /// Où.
        position: usize,
    },
    /// Les bits inutilisés du dernier symbole ne sont pas à zéro.
    ///
    /// # POURQUOI ON LES REFUSE, ET NON PAS SEULEMENT ON LES IGNORE
    ///
    /// Le dernier symbole d'un segment porte deux ou quatre bits qui ne codent
    /// aucun octet. Un décodeur indulgent les jette ; **deux jetons qui ne
    /// diffèrent que par ces bits rendraient alors la même valeur**, et l'un
    /// signerait pour l'autre. C'est la même raison qui fait qu'`asl-attest`
    /// refuse un CBOR non minimal : sur un chemin qui vérifie une signature, une
    /// seule écriture par valeur.
    BitsNonNuls {
        /// Le rang du segment.
        rang: usize,
    },
}

impl core::fmt::Display for Erreur {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PasTroisSegments { comptes } => {
                write!(f, "{comptes} segments, un JWS compact en a trois")
            }
            Self::PasCinqSegments { comptes } => {
                write!(f, "{comptes} segments, un JWE compact en a cinq")
            }
            Self::SegmentVide { rang } => write!(f, "segment {rang} vide"),
            Self::SymboleInvalide { position } => {
                write!(f, "symbole hors base64url en position {position}")
            }
            Self::LongueurImpossible { rang } => {
                write!(f, "longueur base64url impossible au segment {rang}")
            }
            Self::TamponTropPetit { attendu } => {
                write!(f, "tampon trop petit, {attendu} octets nécessaires")
            }
            Self::RemplissageRefuse { position } => {
                write!(f, "remplissage `=` en position {position}")
            }
            Self::BitsNonNuls { rang } => {
                write!(f, "bits de fin non nuls au segment {rang}")
            }
        }
    }
}
