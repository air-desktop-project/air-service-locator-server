//! L'écho — `asl-echo` et `asl ping` (`protocole.md` §3 quater, décisions 89
//! à 91).
//!
//! # CE QUE CETTE CRATE EST
//!
//! **Le codec** (C1) : les trois datagrammes de l'écho et le jeton qu'une
//! racine délivre, écrits et lus, et leur **vérification hors ligne** — ce que
//! l'écho décide sans appeler personne, ce que le sondeur vérifie de la
//! réponse. Aucune socket, aucun fichier, aucune horloge : l'heure est un
//! paramètre, l'aléa du défi vient de l'appelant, et la mémoire des défis vus
//! (l'anti-rejeu) est un ÉTAT, tenu par qui écoute.
//!
//! # LE FORMAT, VERSION 1
//!
//! **Tout est de longueur fixe, en octets de réseau, sans champ facultatif** :
//! un décodeur qui n'a rien à décider n'a rien à mal décider.
//!
//! | Genre | Qui l'envoie | Longueur |
//! |---|---|---|
//! | [`GENRE_SONDE_ANNUAIRE`] | L'annuaire qui tient le bail, ou une racine | [`REQUETE_OCTETS`], bourrés de zéros |
//! | [`GENRE_SONDE_JETON`] | `asl ping` | [`REQUETE_OCTETS`], bourrés de zéros |
//! | [`GENRE_REPONSE`] | L'écho | [`REPONSE_OCTETS`] |
//!
//! Chaque datagramme commence par [`VERSION`] (`0x0A`), puis le genre. Les
//! identifiants sont leurs seize octets, jamais leur texte — leur genre se lit
//! de leur PLACE. Les adresses sont seize octets (une IPv4 s'écrit
//! `::ffff:a.b.c.d`) suivis du port sur deux.
//!
//! **Pas d'amplification, et c'est une règle de format** : une requête fait
//! 384 octets, une réponse 132. Une requête d'une autre longueur, ou dont le
//! bourrage n'est pas fait de zéros, est refusée — un octet libre serait un
//! canal.
//!
//! # CE QUI EST SIGNÉ, ET SOUS QUEL SÉPARATEUR
//!
//! Les quatre séparateurs vivent dans `asl-cle` ([`asl_cle::DomaineEcho`]),
//! avec tous les autres : c'est là qu'on vérifie qu'aucun préfixe n'est celui
//! d'un autre. Ici, le contenu qui les suit, toujours de longueur fixe :
//!
//! - **sonde d'annuaire** : l'en-tête et tout ce qui précède la signature ;
//! - **sonde munie d'un jeton** : le défi ‖ le jeton entier ;
//! - **réponse** : le défi ‖ la machine ‖ l'adresse observée du sondeur ‖
//!   l'identité du sondeur — **sans l'heure** (décision 90 ; E3) ;
//! - **jeton** : tout ce qui précède la signature.
//!
//! # CE QUI N'EST PAS ICI
//!
//! Le débit par source, la mémoire des défis vus, la liste des racines
//! embarquées et la clé de l'annuaire du bail : ce sont des états ou des
//! réglages de qui écoute. Les vérifications les reçoivent en paramètre
//! (`cle_de`), pour que la règle — « une racine embarquée, ou l'annuaire du
//! bail » — reste écrite une fois, chez l'appelant qui la connaît.

#![no_std]

mod jeton;
mod octets;
mod reponse;
mod sonde;

pub use jeton::{JETON_HEX_OCTETS, Jeton, JetonHex, RefusJeton};
pub use reponse::{RefusReponse, Reponse};
pub use sonde::{RefusRequete, RefusSonde, SondeAcceptee, SondeAnnuaire, SondeJeton, accepter};

use asl_id::Genre;
use core::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Le nom du service que l'écho annonce — celui que `POST /v1/echo/jetons`
/// résout comme `GET /v1/ou/{m}/asl-echo`, sous la même décision
/// (décision 91).
pub const NOM_SERVICE: &str = "asl-echo";

/// Le premier octet d'un datagramme d'écho, version 1.
///
/// `0x0B` à `0x0F` sont gardés pour les versions suivantes, `0x04` à `0x09`
/// réservés : une plage que ni QUIC (bit `0x40` toujours posé), ni STUN, ni
/// DTLS, ni RTP n'emploient (RFC 7983 §7, RFC 9443). Un seul octet trie la
/// socket du bail — voir [`est_de_l_echo`].
pub const VERSION: u8 = 0x0A;

/// Le genre d'une sonde d'annuaire.
pub const GENRE_SONDE_ANNUAIRE: u8 = 0x01;

/// Le genre d'une sonde munie d'un jeton.
pub const GENRE_SONDE_JETON: u8 = 0x02;

/// Le genre d'une réponse.
pub const GENRE_REPONSE: u8 = 0x81;

/// La longueur d'une requête — l'une ou l'autre sonde —, bourrage compris.
///
/// 384 octets passent tout lien IPv6 (1 280 au moins) sans se fragmenter.
pub const REQUETE_OCTETS: usize = 384;

/// La longueur d'une réponse : plus petite que la requête, donc aucune
/// amplification.
pub const REPONSE_OCTETS: usize = 132;

/// La longueur d'un défi — seize octets tirés par le sondeur.
pub const DEFI_OCTETS: usize = 16;

/// La longueur d'une adresse sur le fil : seize octets, puis le port sur deux.
pub const ADRESSE_OCTETS: usize = 18;

/// La longueur d'un jeton.
pub const JETON_OCTETS: usize = 193;

/// La version du jeton, son premier octet.
pub const VERSION_JETON: u8 = 0x01;

/// La tolérance d'horloge de l'écho : **deux minutes**, dans les deux sens.
///
/// Une sonde d'annuaire datée hors de cette fenêtre, un jeton expiré depuis
/// plus longtemps, sont refusés : une machine dont l'horloge dérive de plus de
/// deux minutes ne répond à aucune sonde (`protocole.md` §3 quater).
pub const FENETRE_HORLOGE_MS: u64 = 120_000;

/// La durée d'un jeton : **soixante secondes** (décision 91 ; E5).
///
/// L'écho refuse un jeton dont la validité serait plus longue : une racine
/// n'en délivre pas, et un jeton qui durerait davantage prolongerait un droit
/// retiré.
pub const DUREE_JETON_MS: u64 = 60_000;

/// Ce premier octet est-il celui d'un datagramme d'écho, de quelque version ?
///
/// **C'est le tri de la socket du bail** (décision 90 ; E2) : la même socket
/// UDP porte la connexion QUIC vers l'annuaire et les sondes de l'écho. Un
/// paquet QUIC v1 a toujours le bit `0x40` posé (RFC 9000 §17) ; l'écho
/// commence par un octet de `0x04` à `0x0F`. Ce qui est vrai ici n'est pas
/// encore LISIBLE — une version future ou réservée sera refusée par les
/// lecteurs —, mais ce n'est jamais du QUIC.
#[must_use]
pub const fn est_de_l_echo(premier: u8) -> bool {
    matches!(premier, 0x04..=0x0F)
}

/// Un défi : seize octets tirés par le sondeur, jamais réutilisés.
///
/// **Il n'est jamais tiré ici** : l'aléa vient de l'appelant. C'est lui qui
/// fait la fraîcheur d'une réponse — elle ne vaut que pour la sonde qui l'a
/// demandée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DefiEcho([u8; DEFI_OCTETS]);

impl DefiEcho {
    /// Depuis seize octets d'aléa.
    #[must_use]
    pub const fn depuis_octets(octets: [u8; DEFI_OCTETS]) -> Self {
        Self(octets)
    }

    /// Les octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8; DEFI_OCTETS] {
        &self.0
    }
}

/// Une adresse telle que l'écho l'a observée : seize octets et un port.
///
/// **Une IPv4 s'écrit `::ffff:a.b.c.d`**, et se relit en IPv4 : il n'y a
/// qu'une écriture par adresse. Le port nul est refusé à la lecture — aucune
/// source ne l'a.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Adresse {
    /// L'adresse, en IPv6 (une IPv4 y est enfouie).
    ip: Ipv6Addr,
    /// Le port.
    port: u16,
}

impl Adresse {
    /// Depuis la source d'un datagramme reçu.
    ///
    /// L'identifiant de portée et l'étiquette de flux d'une IPv6 ne sont pas
    /// écrits : ils ne voyagent pas, et l'adresse signée est celle qu'un tiers
    /// peut reconnaître.
    #[must_use]
    pub const fn depuis_source(source: SocketAddr) -> Self {
        let ip = match source.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        Self {
            ip,
            port: source.port(),
        }
    }

    /// L'adresse, une IPv4 enfouie rendue comme telle.
    #[must_use]
    pub fn source(&self) -> SocketAddr {
        let ip = self
            .ip
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(self.ip), IpAddr::V4);
        SocketAddr::new(ip, self.port)
    }

    /// Les dix-huit octets du fil.
    #[must_use]
    pub fn octets(&self) -> [u8; ADRESSE_OCTETS] {
        let mut sortie = [0_u8; ADRESSE_OCTETS];
        let mut ecrivain = octets::Ecrivain::nouveau(&mut sortie);
        ecrivain.poser(&self.ip.octets());
        ecrivain.poser(&self.port.to_be_bytes());
        sortie
    }

    /// Relit dix-huit octets du fil.
    ///
    /// # Erreurs
    ///
    /// [`Refus::PortNul`] : aucune source n'a le port zéro.
    pub fn depuis_octets(octets: &[u8; ADRESSE_OCTETS]) -> Result<Self, Refus> {
        let mut lecteur = octets::Lecteur::nouveau(octets);
        let ip = Ipv6Addr::from(lecteur.prendre::<16>());
        let port = u16::from_be_bytes(lecteur.prendre::<2>());
        if port == 0 {
            return Err(Refus::PortNul);
        }
        Ok(Self { ip, port })
    }
}

/// Pourquoi des octets ne sont pas un datagramme d'écho (ou un jeton) lisible.
///
/// **Côté écho, tout refus est un silence** : aucun n'est renvoyé au fil. La
/// raison sert au journal et aux essais — et à `asl ping`, qui dit « réponse
/// illisible » plutôt que « pas de réponse ».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Une longueur autre que celle du genre annoncé.
    Longueur {
        /// Ce qui était attendu.
        attendue: usize,
        /// Ce qui a été reçu.
        obtenue: usize,
    },
    /// Le premier octet n'est pas de l'écho (voir [`est_de_l_echo`]).
    PasDeLEcho {
        /// L'octet lu.
        premier: u8,
    },
    /// Un datagramme d'écho d'une version que ce codec ne lit pas : suivante
    /// (`0x0B` à `0x0F`) ou réservée (`0x04` à `0x09`).
    Version {
        /// L'octet lu.
        premier: u8,
    },
    /// Un genre inconnu, ou qui n'est pas celui qu'on lit ici.
    Genre {
        /// L'octet lu.
        genre: u8,
    },
    /// Un octet de bourrage n'est pas nul.
    Bourrage,
    /// Un jeton d'une version que ce codec ne lit pas.
    VersionDeJeton {
        /// L'octet lu.
        version: u8,
    },
    /// Trente-deux octets qui ne sont pas un point de la courbe.
    CleInvalide,
    /// Un jeton en hexadécimal : un caractère qui n'est pas un chiffre
    /// hexadécimal.
    Hexadecimal,
    /// Une adresse au port zéro.
    PortNul,
}

/// Une composition refusée : un identifiant du mauvais genre à une place qui
/// n'en admet qu'un.
///
/// **Le genre ne voyage pas** — seize octets, et la place dit le genre. Écrire
/// un `u-…` là où l'on attend un `m-…` produirait un datagramme qui se relit
/// en autre chose que ce qu'on a écrit ; c'est refusé ici, pas découvert au
/// bout du fil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MauvaisGenre {
    /// Le genre fourni.
    pub obtenu: Genre,
}

/// L'identifiant a-t-il ce genre ?
fn exiger(identifiant: asl_id::Identifiant, genre: Genre) -> Result<(), MauvaisGenre> {
    if identifiant.genre() == genre {
        Ok(())
    } else {
        Err(MauvaisGenre {
            obtenu: identifiant.genre(),
        })
    }
}

/// L'en-tête d'un datagramme : la version, puis le genre attendu.
///
/// **L'ordre des refus est celui de la lecture** : le premier octet, puis le
/// genre, puis la longueur. Une raison rendue doit s'appliquer vraiment — une
/// longueur fausse sur un paquet QUIC est d'abord un paquet QUIC.
fn lire_en_tete(datagramme: &[u8], genre: u8, longueur: usize) -> Result<(), Refus> {
    let trop_court = Refus::Longueur {
        attendue: longueur,
        obtenue: datagramme.len(),
    };
    let [premier, reste @ ..] = datagramme else {
        return Err(trop_court);
    };
    if !est_de_l_echo(*premier) {
        return Err(Refus::PasDeLEcho { premier: *premier });
    }
    if *premier != VERSION {
        return Err(Refus::Version { premier: *premier });
    }
    let [second, ..] = reste else {
        return Err(trop_court);
    };
    if *second != genre {
        return Err(Refus::Genre { genre: *second });
    }
    if datagramme.len() != longueur {
        return Err(trop_court);
    }
    Ok(())
}

/// Les instants, en millisecondes d'époque, sont-ils à moins de la fenêtre
/// l'un de l'autre ?
const fn dans_la_fenetre(un: u64, autre: u64) -> bool {
    un.abs_diff(autre) <= FENETRE_HORLOGE_MS
}
