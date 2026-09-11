//! Ce qu'une attestation de plate-forme PORTE, avant qu'on décide quoi que ce
//! soit.
//!
//! # CETTE CRATE NE VÉRIFIE RIEN
//!
//! Elle lit. Elle ne valide aucune chaîne de certificats, ne vérifie aucune
//! signature, ne connaît ni Apple ni Google. Ce qu'elle rend est une STRUCTURE,
//! et c'est à l'étage au-dessus de dire si elle prouve quelque chose.
//!
//! La séparation n'est pas décorative : lire un objet venu du réseau et
//! remonter une chaîne jusqu'à une racine sont deux métiers, et les fondre
//! ferait qu'un objet mal formé et un objet non prouvé rendraient la même
//! faute. Ici, un objet mal formé est une faute de GRAMMAIRE.
//!
//! # POURQUOI UN LECTEUR CBOR ÉCRIT ICI
//!
//! Apple encode son objet d'attestation en CBOR (RFC 8949). Le graphe de ce
//! produit porte déjà cent-dix paquets tiers, et C4 le borne ; y ajouter un
//! analyseur CBOR complet pour lire **cinq types sur huit** serait payer très
//! cher une généralité dont personne n'a besoin.
//!
//! C'est le même choix qu'`asl-proto` a fait pour JSON, et pour la même raison.
//!
//! **CE LECTEUR REFUSE TOUT LE RESTE**, et ne l'ignore pas : les flottants, les
//! étiquettes, les longueurs indéfinies, les entiers négatifs. Un analyseur
//! indulgent accepterait deux encodages du même objet, et deux lecteurs qui ne
//! trancheraient pas pareil liraient deux attestations dans les mêmes octets.

#![no_std]

mod cbor;
mod objet;

pub use cbor::{LONGUEUR_MAX, Lecteur, PROFONDEUR_MAX, Valeur};
pub use objet::{
    AAGUID_OCTETS, AUTH_MINIMUM, Champ, CleAttestee, DRAPEAU_ATTESTE, DRAPEAU_EXTENSIONS,
    DRAPEAU_PRESENCE, DRAPEAU_VERIFIE, DonneesAuth, EMPREINTE_OCTETS, FORMAT, ObjetAttestation,
    X5C_MAX,
};

/// Ce qui empêche de lire une attestation.
///
/// **Ce ne sont pas des refus** : un refus se décide ailleurs, sur un objet
/// bien formé. Ce sont des octets qui ne forment pas une attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Les octets s'arrêtent au milieu d'une valeur.
    Tronque {
        /// Où.
        position: usize,
    },
    /// Un type majeur que ce lecteur ne sert pas.
    ///
    /// **Flottants, étiquettes, entiers négatifs, valeurs simples.** Aucun n'a
    /// sa place dans un objet d'attestation, et les accepter ouvrirait des
    /// encodages que le reste du monde ne produit pas.
    TypeRefuse {
        /// Le type majeur lu (0 à 7).
        majeur: u8,
        /// Où.
        position: usize,
    },
    /// Une longueur indéfinie.
    ///
    /// RFC 8949 §3.2.2 les autorise ; l'encodage canonique de §4.2 ne les
    /// emploie pas. **Deux façons d'écrire la même chose sont une de trop**
    /// quand ce qu'on lit décide d'un accès.
    LongueurIndefinie {
        /// Où.
        position: usize,
    },
    /// Une tête qui emploie l'une des trois valeurs réservées de RFC 8949
    /// (informations additionnelles 28, 29 et 30).
    EnteteReserve {
        /// Où.
        position: usize,
    },
    /// Un entier écrit plus long qu'il n'aurait pu l'être.
    ///
    /// RFC 8949 §4.2.1 impose la forme la plus courte, et CTAP2 aussi. **Deux
    /// façons d'écrire la même chose sont une de trop** quand ce qu'on lit
    /// décide d'un accès.
    EncodageNonMinimal {
        /// Où.
        position: usize,
    },
    /// Une longueur qu'aucune attestation ne porte.
    ///
    /// Bornée par [`LONGUEUR_MAX`]. Le refus est immédiat : sans lui, une
    /// tête de cinq octets ferait travailler le lecteur pour rien.
    LongueurDemesuree {
        /// Ce qui a été annoncé.
        annoncee: u64,
        /// Où.
        position: usize,
    },
    /// Une chaîne de texte qui n'est pas de l'UTF-8.
    TexteInvalide {
        /// Où.
        position: usize,
    },
    /// Une valeur qui n'est pas du type attendu à cette place.
    PasLeBonType {
        /// Où.
        position: usize,
    },
    /// Une imbrication plus profonde que ce qu'un objet d'attestation demande.
    ///
    /// **SANS CETTE BORNE, LA PILE EST LA BORNE.** Un objet fait de dix mille
    /// tableaux ouverts ferait déborder la pile d'un lecteur récursif — c'est
    /// la faute de déni de service la plus classique d'un analyseur, et elle se
    /// tient en comptant.
    TropProfond {
        /// Où.
        position: usize,
    },
    /// Des octets restent après la valeur lue.
    DonneesEnTrop {
        /// Où commence ce qui est en trop.
        position: usize,
    },
    /// Un champ que l'objet doit porter, et qui n'y est pas.
    ChampManquant {
        /// Lequel.
        champ: Champ,
    },
    /// Un champ porté deux fois.
    ///
    /// **CE N'EST PAS UNE CURIOSITÉ.** C'est la place exacte où l'on met un
    /// `authData` que ce lecteur prendra et un autre qu'un second lecteur
    /// prendrait.
    ChampEnDouble {
        /// Lequel.
        champ: Champ,
    },
    /// Le `fmt` n'est pas [`FORMAT`].
    ///
    /// Un autre format d'attestation n'est pas « inconnu » au sens indulgent :
    /// il se vérifie autrement, et le lire avec ces règles-ci n'aurait pas de
    /// sens.
    FormatInconnu,
    /// Une chaîne `x5c` plus longue que [`X5C_MAX`].
    TropDeCertificats {
        /// Combien ont été annoncés.
        annonces: usize,
    },
    /// `authData` est plus court que sa propre disposition ne l'impose.
    AuthDataTronque {
        /// Ce qu'il mesure.
        octets: usize,
    },
}

impl core::fmt::Display for Erreur {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tronque { position } => write!(f, "octets tronqués en position {position}"),
            Self::TypeRefuse { majeur, position } => {
                write!(f, "type majeur {majeur} refusé en position {position}")
            }
            Self::LongueurIndefinie { position } => {
                write!(f, "longueur indéfinie en position {position}")
            }
            Self::EnteteReserve { position } => {
                write!(f, "en-tête réservé en position {position}")
            }
            Self::EncodageNonMinimal { position } => {
                write!(f, "encodage non minimal en position {position}")
            }
            Self::LongueurDemesuree { annoncee, position } => {
                write!(f, "longueur {annoncee} démesurée en position {position}")
            }
            Self::TexteInvalide { position } => {
                write!(f, "texte non UTF-8 en position {position}")
            }
            Self::PasLeBonType { position } => {
                write!(f, "valeur d'un autre type en position {position}")
            }
            Self::TropProfond { position } => {
                write!(f, "imbrication trop profonde en position {position}")
            }
            Self::DonneesEnTrop { position } => {
                write!(f, "octets en trop à partir de {position}")
            }
            Self::ChampManquant { champ } => write!(f, "champ `{}` manquant", champ.nom()),
            Self::ChampEnDouble { champ } => write!(f, "champ `{}` en double", champ.nom()),
            Self::FormatInconnu => write!(f, "format d'attestation inconnu"),
            Self::TropDeCertificats { annonces } => {
                write!(f, "{annonces} certificats annoncés, {X5C_MAX} au plus")
            }
            Self::AuthDataTronque { octets } => {
                write!(f, "`authData` tronqué à {octets} octets")
            }
        }
    }
}
