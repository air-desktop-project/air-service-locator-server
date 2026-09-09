//! La grammaire du protocole d'**annonce** : ce qu'un daemon dit à l'annuaire,
//! et ce que l'annuaire lui répond.
//!
//! # Ce que cette crate fait, et ce qu'elle ne fait pas
//!
//! Des octets vers des messages, et retour. Elle ne connaît ni socket, ni
//! horloge, ni fichier (contrainte C1). Le message « j'écoute en TCP sur le port
//! 49152 » y est une valeur ; DÉCIDER si cette annonce est recevable appartient
//! à `asl-annuaire`, et l'ÉMETTRE appartient à `asl-loop-tokio`.
//!
//! `core::net` fournit les types d'adresses. **Ce n'est pas une entrée-sortie** :
//! une `IpAddr` est une valeur, pas une socket — et la réimplémenter serait
//! réécrire un analyseur d'IPv6 pour le plaisir d'en avoir un à nous.
//!
//! # CE QUI EST ÉCRIT, ET CE QUI NE L'EST PAS
//!
//! **Écrit** : les VALEURS et leurs invariants — protocoles, ports, noms de
//! service, points d'écoute, candidats d'adresse —, le message d'ANNONCE avec sa
//! validation, et son CADRAGE JSON dans les deux sens ([`cadrage`]).
//!
//! **Écrit aussi** : le message de RÉPONSE — bail, `vu_depuis`, `derriere_nat`,
//! verdicts de joignabilité — avec son cadrage.
//!
//! **Pas écrit** : le retrait, qui n'a pas de corps, et la poussée d'un verdict
//! de sonde arrivée après la réponse (`docs/protocole.md` §1.1, `en_cours`).
//!
//! # C6 EST ÉCRITE DANS LES TYPES DE LA RÉPONSE
//!
//! La contrainte dit que l'annuaire n'affirme jamais ce qu'il n'a pas mesuré.
//! Trois endroits la rendent impossible à enfreindre plutôt que déconseillée :
//!
//! - [`Verdict::Joignable`] porte sa date et son candidat **dans la variante** :
//!   il n'existe aucune façon d'affirmer « joignable » sans dire depuis quand ni
//!   par où ;
//! - [`VerdictNat`] a **trois** états, parce qu'un booléen forcerait à répondre
//!   « non » quand le daemon n'a annoncé aucune adresse à comparer ;
//! - un point UDP ne peut être **ni** `joignable` **ni** `injoignable`, et
//!   [`Reponse::nouvelle`] le refuse.
//!
//! # La frontière entre valeurs et cadrage
//!
//! Elle n'est pas une commodité de découpage : c'est celle que §4.3 du même
//! document désigne comme la seule qui bougera si l'on passe un jour à un
//! cadrage binaire. Les valeurs, elles, ne bougeront pas — ce sont elles que
//! `asl-annuaire` manipule et que `asl-client` expose à cinq langages.
//!
//! C'est pourquoi le cadrage est un module à part, et non un jeu de méthodes
//! posées sur les types.
//!
//! # La règle qui gouverne tout ce fichier
//!
//! **Les octets viennent du réseau, donc d'un inconnu.** Une longueur annoncée
//! ne sert jamais à allouer avant d'avoir été bornée, et un numéro de port hors
//! de `1..=65535` **se refuse — il ne se tronque pas** (contrainte C3).
//!
//! Les lints `deny` du workspace voient une conversion douteuse ; ils ne voient
//! jamais une borne oubliée. C'est le fuzz qui l'attrape.
//!
//! # Une seule écriture par valeur
//!
//! Partout où un texte peut s'écrire de deux façons, **une seule est acceptée**.
//! Pas de zéro en tête sur un port, pas de majuscule dans un nom de service. La
//! raison n'est pas l'esthétique : deux écritures d'un même service, ce sont
//! deux services pour l'annuaire et un seul pour l'humain qui les lit.

#![no_std]

pub mod cadrage;

pub use cadrage::{MESSAGE_MAX, Tampons, TamponsReponse};

use core::fmt;
use core::net::IpAddr;
use core::num::NonZeroU16;

use asl_id::{Genre, Identifiant};

// ── Les bornes ──────────────────────────────────────────────────────────────

/// La longueur maximale d'un nom de service, en octets.
pub const NOM_MAX: usize = 64;

/// Le nombre maximal de points d'écoute dans une annonce.
///
/// **Une borne existe parce que le compte vient du réseau.** Huit suffit
/// largement à un daemon qui sert en TCP et en UDP sur quelques ports ; un
/// daemon qui en annoncerait cinq cents est cassé ou hostile, et dans les deux
/// cas l'annuaire n'a pas à lui faire de la place.
pub const POINTS_MAX: usize = 8;

/// Le nombre maximal d'adresses locales dans une annonce.
///
/// Même raison. Une machine ordinaire en a deux ou trois — une IPv6 globale, une
/// IPv4 privée, parfois une seconde interface.
pub const ADRESSES_MAX: usize = 8;

// ── Les erreurs ─────────────────────────────────────────────────────────────

/// Ce qui peut clocher dans une valeur du protocole.
///
/// Chaque variante porte de quoi **désigner la faute** : un daemon tiers lira
/// ces refus dans son journal, et « annonce invalide » n'aide personne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Le texte ne désigne aucun protocole connu.
    ProtocoleInconnu,
    /// Le port vaut zéro. **Ce n'est pas un port**, c'est la demande faite au
    /// noyau d'en choisir un — elle n'a aucun sens dans une annonce.
    PortNul,
    /// Le texte du port n'est pas un nombre décimal.
    PortNonNumerique,
    /// Le port dépasse `65535`. Il se **refuse**, il ne se tronque pas.
    PortHorsBornes,
    /// Le port porte un zéro en tête : `0080` et `80` seraient deux écritures.
    PortNonCanonique,
    /// Le nom de service est vide.
    NomVide,
    /// Le nom de service dépasse [`NOM_MAX`] octets.
    NomTropLong {
        /// La longueur reçue.
        obtenue: usize,
    },
    /// Le nom de service porte un octet hors de l'alphabet autorisé.
    NomSymboleInvalide {
        /// La position de l'octet fautif.
        position: usize,
    },
    /// Le nom de service commence ou finit par `-` ou `.`.
    NomBordInvalide,
    /// L'annonce ne porte aucun point d'écoute.
    AucunPoint,
    /// L'annonce porte plus de [`POINTS_MAX`] points d'écoute.
    TropDePoints {
        /// Le compte reçu.
        obtenu: usize,
    },
    /// Deux points d'écoute désignent le même couple protocole/port.
    PointEnDouble,
    /// L'annonce porte plus de [`ADRESSES_MAX`] adresses locales.
    TropDAdresses {
        /// Le compte reçu.
        obtenu: usize,
    },
    /// L'identifiant fourni n'est pas celui d'une machine.
    PasUneMachine {
        /// Le genre réellement fourni.
        obtenu: Genre,
    },

    // ── Le cadrage ──────────────────────────────────────────────────────────
    /// Le message dépasse [`MESSAGE_MAX`] octets.
    MessageTropLong {
        /// La longueur reçue.
        obtenue: usize,
    },
    /// Le message n'est pas l'identifiant de machine attendu.
    IdentifiantInvalide {
        /// Où il commence.
        position: usize,
    },
    /// Quelque chose d'autre était attendu à cet endroit.
    JsonAttendu {
        /// Où.
        position: usize,
        /// Quoi.
        attendu: &'static str,
    },
    /// Le message est mal formé d'une façon qui ne devrait pas arriver.
    JsonInattendu {
        /// Où.
        position: usize,
    },
    /// Un champ que ce lecteur ne connaît pas.
    ///
    /// **Refusé, et non ignoré** : un champ qu'on ignore est un champ que
    /// l'émetteur croit avoir transmis.
    ChampInconnu {
        /// Où commence sa clé.
        position: usize,
    },
    /// Un champ apparaît deux fois.
    ///
    /// JSON ne l'interdit pas ; deux analyseurs qui ne choisiraient pas le même
    /// gagnant liraient deux messages dans les mêmes octets.
    ChampEnDouble {
        /// Où commence la deuxième clé.
        position: usize,
    },
    /// Un champ obligatoire manque.
    ChampManquant {
        /// Son nom.
        nom: &'static str,
    },
    /// Une chaîne porte un échappement.
    ///
    /// Aucune valeur de ce protocole n'emploie de caractère qui en demande un.
    EchappementRefuse {
        /// Où.
        position: usize,
    },
    /// Une chaîne porte un octet de contrôle ou du non-ASCII.
    CaractereBrutRefuse {
        /// Où.
        position: usize,
    },
    /// Un nombre porte un zéro en tête.
    NombreNonCanonique {
        /// Où il commence.
        position: usize,
    },
    /// Un nombre porte une fraction ou un exposant.
    ///
    /// Aucun champ de ce protocole n'a de sens en virgule flottante.
    NombreNonEntier {
        /// Où il commence.
        position: usize,
    },
    /// Un nombre dépasse ce que son champ peut porter.
    NombreHorsBornes {
        /// Où il commence.
        position: usize,
    },
    /// Une adresse ne se lit ni en IPv6 ni en IPv4.
    AdresseInvalide {
        /// Où.
        position: usize,
    },
    /// Des octets suivent la fin du message.
    ///
    /// Deux messages collés dans un tampon, c'est un lecteur qui en voit un et
    /// un autre qui en voit deux.
    DonneesEnTrop {
        /// Où commence le surplus.
        position: usize,
    },
    /// La tranche de sortie ne suffit pas à écrire le message.
    TamponTropPetit,

    // ── Le message de réponse ───────────────────────────────────────────────
    /// Le keepalive vaut zéro : une cadence nulle n'est pas une cadence.
    KeepaliveNul,
    /// Le keepalive dépasse [`KEEPALIVE_MAX`].
    KeepaliveTropLong {
        /// La valeur reçue.
        obtenu: u16,
    },
    /// Le délai d'inactivité ne laisse pas la place à un keepalive manqué.
    ///
    /// À un pour un, la première perte de paquet tue un daemon sain.
    InactiviteTropCourte {
        /// La valeur reçue.
        obtenue: u16,
        /// Le minimum admis.
        minimum: u16,
    },
    /// Le texte ne désigne aucun verdict de NAT.
    VerdictNatInconnu,
    /// Le texte ne désigne aucune raison de non-sondage.
    RaisonInconnue,
    /// Le texte ne désigne aucun verdict de joignabilité.
    VerdictInconnu,
    /// Le texte ne désigne aucune origine de candidat.
    OrigineInconnue,
    /// L'identifiant fourni n'est pas celui d'un service.
    PasUnService {
        /// Le genre réellement fourni.
        obtenu: Genre,
    },
    /// La réponse ne porte aucun verdict de joignabilité.
    AucuneJoignabilite,
    /// La réponse porte plus de [`POINTS_MAX`] verdicts.
    TropDeJoignabilites {
        /// Le compte reçu.
        obtenu: usize,
    },
    /// Un verdict de mesure porte sur un point qui ne se sonde pas.
    ///
    /// **C'est C6 dans un type** : l'annuaire n'a rien pu mesurer sur un point
    /// UDP, donc il ne peut ni le dire joignable ni le dire injoignable.
    VerdictImpossible,
    /// Un champ qui ne peut pas accompagner ce verdict.
    ///
    /// Une date sur un `en_cours`, un candidat sur un `non_sonde` : l'émetteur
    /// et le lecteur ne parleraient pas du même message.
    ChampHorsPropos {
        /// Où commence sa clé.
        position: usize,
    },
    /// Un couple adresse/port ne se lit pas.
    CandidatInvalide {
        /// Où.
        position: usize,
    },
}

impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocoleInconnu => f.write_str("protocole inconnu (tcp ou udp)"),
            Self::PortNul => f.write_str("le port zéro n'est pas un port d'écoute"),
            Self::PortNonNumerique => f.write_str("le port n'est pas un nombre décimal"),
            Self::PortHorsBornes => f.write_str("le port dépasse 65535"),
            Self::PortNonCanonique => f.write_str("le port porte un zéro en tête"),
            Self::NomVide => f.write_str("nom de service vide"),
            Self::NomTropLong { obtenue } => {
                write!(f, "nom de service de {obtenue} octets, maximum {NOM_MAX}")
            }
            Self::NomSymboleInvalide { position } => {
                write!(f, "octet invalide en position {position} du nom")
            }
            Self::NomBordInvalide => f.write_str("le nom commence ou finit par `-` ou `.`"),
            Self::AucunPoint => f.write_str("aucun point d'écoute annoncé"),
            Self::TropDePoints { obtenu } => {
                write!(f, "{obtenu} points d'écoute, maximum {POINTS_MAX}")
            }
            Self::PointEnDouble => f.write_str("deux points d'écoute identiques"),
            Self::TropDAdresses { obtenu } => {
                write!(f, "{obtenu} adresses locales, maximum {ADRESSES_MAX}")
            }
            Self::PasUneMachine { obtenu } => {
                write!(
                    f,
                    "identifiant de genre {obtenu:?} là où une machine est attendue"
                )
            }
            Self::MessageTropLong { obtenue } => {
                write!(f, "message de {obtenue} octets, maximum {MESSAGE_MAX}")
            }
            Self::IdentifiantInvalide { position } => {
                write!(f, "identifiant de machine invalide en position {position}")
            }
            Self::JsonAttendu { position, attendu } => {
                write!(f, "{attendu} attendu en position {position}")
            }
            Self::JsonInattendu { position } => {
                write!(f, "message mal formé en position {position}")
            }
            Self::ChampInconnu { position } => {
                write!(f, "champ inconnu en position {position}")
            }
            Self::ChampEnDouble { position } => {
                write!(f, "champ répété en position {position}")
            }
            Self::ChampManquant { nom } => write!(f, "champ `{nom}` manquant"),
            Self::EchappementRefuse { position } => {
                write!(f, "échappement refusé en position {position}")
            }
            Self::CaractereBrutRefuse { position } => {
                write!(f, "octet de contrôle ou non-ASCII en position {position}")
            }
            Self::NombreNonCanonique { position } => {
                write!(f, "nombre avec un zéro en tête en position {position}")
            }
            Self::NombreNonEntier { position } => {
                write!(f, "nombre non entier en position {position}")
            }
            Self::NombreHorsBornes { position } => {
                write!(f, "nombre hors bornes en position {position}")
            }
            Self::AdresseInvalide { position } => {
                write!(f, "adresse IP invalide en position {position}")
            }
            Self::DonneesEnTrop { position } => {
                write!(f, "octets en trop après le message, en position {position}")
            }
            Self::TamponTropPetit => f.write_str("tampon de sortie trop petit"),
            Self::KeepaliveNul => f.write_str("un keepalive nul n'est pas une cadence"),
            Self::KeepaliveTropLong { obtenu } => {
                write!(f, "keepalive de {obtenu} s, maximum {KEEPALIVE_MAX}")
            }
            Self::InactiviteTropCourte { obtenue, minimum } => write!(
                f,
                "inactivité de {obtenue} s, minimum {minimum} — un keepalive manqué doit être toléré"
            ),
            Self::VerdictNatInconnu => {
                f.write_str("verdict de NAT inconnu (oui, non, indetermine)")
            }
            Self::RaisonInconnue => f.write_str("raison de non-sondage inconnue"),
            Self::VerdictInconnu => f.write_str("verdict de joignabilité inconnu"),
            Self::OrigineInconnue => {
                f.write_str("origine de candidat inconnue (reflexif, annonce)")
            }
            Self::PasUnService { obtenu } => {
                write!(
                    f,
                    "identifiant de genre {obtenu:?} là où un service est attendu"
                )
            }
            Self::AucuneJoignabilite => f.write_str("aucun verdict de joignabilité"),
            Self::TropDeJoignabilites { obtenu } => {
                write!(f, "{obtenu} verdicts, maximum {POINTS_MAX}")
            }
            Self::VerdictImpossible => {
                f.write_str("un verdict de mesure sur un point qui ne se sonde pas")
            }
            Self::ChampHorsPropos { position } => {
                write!(
                    f,
                    "champ hors de propos pour ce verdict, en position {position}"
                )
            }
            Self::CandidatInvalide { position } => {
                write!(f, "couple adresse/port illisible en position {position}")
            }
        }
    }
}

// ── Le protocole de transport ───────────────────────────────────────────────

/// Le protocole sur lequel un daemon écoute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocole {
    /// TCP. **Le seul que l'annuaire sache sonder** — il a une poignée de main.
    Tcp,
    /// UDP. Ne se sonde pas : une sonde n'y distingue pas « écoute et ignore »
    /// de « rien n'écoute » (`docs/modele.md` §4.3).
    Udp,
}

impl Protocole {
    /// Son écriture sur le fil. Minuscules, toujours.
    #[must_use]
    pub const fn texte(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Se sonde-t-il ?
    ///
    /// **La réponse gouverne l'état rendu** : un point d'écoute UDP reste
    /// `annoncé` et n'est jamais `joignable`, parce que rien ne permet de
    /// l'affirmer (contrainte C6).
    #[must_use]
    pub const fn se_sonde(self) -> bool {
        matches!(self, Self::Tcp)
    }

    /// Lit un protocole.
    ///
    /// **Les majuscules sont refusées**, et non repliées : `TCP` et `tcp`
    /// seraient deux écritures d'une même valeur, et une seule doit exister.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::ProtocoleInconnu`] si le texte n'est ni `tcp` ni `udp`.
    pub fn analyser(texte: &str) -> Result<Self, Erreur> {
        match texte {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(Erreur::ProtocoleInconnu),
        }
    }
}

impl fmt::Display for Protocole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.texte())
    }
}

// ── Le port ─────────────────────────────────────────────────────────────────

/// Un port d'écoute : `1..=65535`.
///
/// **Le zéro n'en est pas un.** Il désigne, dans un appel système, la demande
/// faite au noyau d'en choisir un — c'est ce qu'un daemon fait AVANT de savoir
/// quoi annoncer. L'annoncer reviendrait à publier « connectez-vous nulle part »,
/// et le type l'interdit plutôt que de compter sur la vigilance de l'appelant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Port(NonZeroU16);

impl Port {
    /// Le port `1`.
    ///
    /// Il ne sert qu'à **remplir** les tampons du décodeur (`cadrage`), dont le
    /// contenu initial n'est jamais lu : un tableau de taille fixe doit bien
    /// commencer par quelque chose, et `Port` n'a pas de valeur nulle par
    /// construction.
    pub const UN: Self = match NonZeroU16::new(1) {
        Some(port) => Self(port),
        // Inatteignable : `1` n'est pas zéro. Un `match` plutôt qu'un `unwrap`
        // parce que ce dernier n'est pas `const` sur cette version.
        None => Self(NonZeroU16::MIN),
    };

    /// Depuis un entier.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PortNul`] si la valeur est zéro.
    pub const fn depuis_u16(valeur: u16) -> Result<Self, Erreur> {
        match NonZeroU16::new(valeur) {
            Some(port) => Ok(Self(port)),
            None => Err(Erreur::PortNul),
        }
    }

    /// La valeur.
    #[must_use]
    pub const fn valeur(self) -> u16 {
        self.0.get()
    }

    /// Lit un port écrit en décimal.
    ///
    /// **Une seule écriture par port.** Pas de signe, pas d'espace, pas de zéro
    /// en tête : `0080` est refusé, parce que deux écritures d'un même port
    /// finissent par produire deux entrées là où il devrait y en avoir une.
    ///
    /// **Le débordement se REFUSE**, il ne se tronque pas (contrainte C3). Un
    /// `65536` tronqué vaudrait `0`, c'est-à-dire un service annoncé sur un port
    /// qui n'existe pas — sans qu'aucune erreur soit rendue.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PortNonNumerique`], [`Erreur::PortNonCanonique`],
    /// [`Erreur::PortHorsBornes`], [`Erreur::PortNul`].
    pub fn analyser(texte: &str) -> Result<Self, Erreur> {
        let octets = texte.as_bytes();
        if octets.is_empty() {
            return Err(Erreur::PortNonNumerique);
        }

        // ── L'ORDRE DE CES TROIS CONTRÔLES EST CHOISI, ET IL A ÉTÉ CORRIGÉ ──
        //
        // « Est-ce un nombre ? » passe AVANT « est-il canonique ? ». Dans
        // l'autre sens, `0x50` se voyait refuser pour « zéro en tête » — ce qui
        // est vrai et trompeur : la faute est ailleurs, et le message envoyait
        // chercher au mauvais endroit.
        //
        // Une erreur juste mais qui désigne la mauvaise cause coûte plus cher
        // qu'une erreur vague : elle est crue.
        if !octets.iter().all(u8::is_ascii_digit) {
            return Err(Erreur::PortNonNumerique);
        }
        if octets.len() > 1 && octets[0] == b'0' {
            return Err(Erreur::PortNonCanonique);
        }

        // ── L'ACCUMULATEUR EST UN `u16`, ET C'EST LUI QUI PORTE LA BORNE ────
        //
        // Une première version accumulait en `u32` avec une borne explicite
        // après chaque chiffre. Elle marchait, et elle avait DEUX défauts que la
        // mesure de couverture a révélés :
        //
        //   — le `?` du `checked_*` était INATTEIGNABLE, puisque la borne
        //     explicite arrêtait bien avant qu'un `u32` déborde. Du code mort
        //     sur un chemin de sécurité, c'est-à-dire du code que personne
        //     n'éprouvera jamais et que tout le monde croira éprouvé ;
        //   — il fallait ensuite reconvertir en `u16`, donc un
        //     `cast_possible_truncation` à taire par un `allow`.
        //
        // En `u16`, le débordement de l'accumulateur EST le dépassement de
        // 65535 : `checked_mul` et `checked_add` disent exactement ce qu'on veut
        // savoir, chaque branche est atteignable, et il n'y a plus de conversion
        // ni d'`allow`. La borne n'est plus vérifiée à côté du calcul — elle est
        // le calcul.
        let mut valeur: u16 = 0;
        for &octet in octets {
            valeur = valeur
                .checked_mul(10)
                .and_then(|v| v.checked_add(u16::from(octet.wrapping_sub(b'0'))))
                .ok_or(Erreur::PortHorsBornes)?;
        }

        Self::depuis_u16(valeur)
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.valeur())
    }
}

// ── Le nom de service ───────────────────────────────────────────────────────

/// Le nom qu'un daemon se donne, et que ses clients connaissent.
///
/// **Il emprunte** : cette crate est `no_std` sans allocation, et le nom vit
/// dans le tampon d'où il a été lu.
///
/// # L'alphabet, et pourquoi il est étroit
///
/// Minuscules ASCII, chiffres, `-`, `_`, `.` — et rien d'autre. Trois raisons,
/// dans l'ordre où elles pèsent :
///
/// 1. **Ce nom voyage dans une URL** : `GET /v1/ou?service=…`. Tout ce qui
///    demanderait un échappement ouvrirait deux écritures du même nom.
/// 2. **Les majuscules sont REFUSÉES, et non repliées.** Un nom qui ne diffère
///    que par la casse produirait deux services que l'annuaire distingue et
///    qu'un humain lit comme un seul.
/// 3. **Ni `-` ni `.` aux extrémités** : un nom qui commence par un point se
///    cache dans une liste de fichiers, et un nom qui finit par un tiret se lit
///    mal partout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NomService<'a>(&'a str);

impl<'a> NomService<'a> {
    /// Lit un nom de service.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::NomVide`], [`Erreur::NomTropLong`],
    /// [`Erreur::NomSymboleInvalide`], [`Erreur::NomBordInvalide`].
    pub fn analyser(texte: &'a str) -> Result<Self, Erreur> {
        let octets = texte.as_bytes();
        if octets.is_empty() {
            return Err(Erreur::NomVide);
        }
        if octets.len() > NOM_MAX {
            return Err(Erreur::NomTropLong {
                obtenue: octets.len(),
            });
        }

        for (position, &octet) in octets.iter().enumerate() {
            let permis = octet.is_ascii_lowercase()
                || octet.is_ascii_digit()
                || matches!(octet, b'-' | b'_' | b'.');
            if !permis {
                return Err(Erreur::NomSymboleInvalide { position });
            }
        }

        // Le premier et le dernier octet, qui peuvent être le même sur un nom
        // d'un seul caractère — et un nom réduit à `-` doit être refusé aussi.
        let premier = octets[0];
        let dernier = octets[octets.len().saturating_sub(1)];
        if matches!(premier, b'-' | b'.') || matches!(dernier, b'-' | b'.') {
            return Err(Erreur::NomBordInvalide);
        }

        Ok(Self(texte))
    }

    /// Le nom.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

impl fmt::Display for NomService<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

// ── Le point d'écoute ───────────────────────────────────────────────────────

/// Un couple protocole/port : ce qu'un daemon annonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PointEcoute {
    /// TCP ou UDP.
    pub protocole: Protocole,
    /// Le port, jamais nul.
    pub port: Port,
}

impl PointEcoute {
    /// Construit un point d'écoute.
    #[must_use]
    pub const fn nouveau(protocole: Protocole, port: Port) -> Self {
        Self { protocole, port }
    }
}

impl fmt::Display for PointEcoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.protocole, self.port)
    }
}

// ── Les candidats d'adresse ─────────────────────────────────────────────────

/// D'où vient une adresse.
///
/// La distinction n'est pas documentaire : elle décide de l'ordre d'essai, et
/// elle est ce qui permet à l'annuaire de dire à un daemon qu'il est derrière un
/// NAT (`docs/modele.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origine {
    /// **Observée** par l'annuaire sur la connexion d'annonce.
    ///
    /// Vient en premier : c'est celle qui vaut vue de l'Internet, et la seule
    /// qui puisse valoir quand le daemon est derrière un NAT.
    Reflexif,
    /// **Annoncée** par le daemon. Vraie sur son réseau, souvent fausse ailleurs.
    Annonce,
}

impl Origine {
    /// Son écriture sur le fil.
    #[must_use]
    pub const fn texte(self) -> &'static str {
        match self {
            Self::Reflexif => "reflexif",
            Self::Annonce => "annonce",
        }
    }

    /// Lit une origine.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::OrigineInconnue`] si le texte n'en désigne aucune.
    pub fn analyser(texte: &str) -> Result<Self, Erreur> {
        match texte {
            "reflexif" => Ok(Self::Reflexif),
            "annonce" => Ok(Self::Annonce),
            _ => Err(Erreur::OrigineInconnue),
        }
    }
}

impl fmt::Display for Origine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.texte())
    }
}

/// Une adresse où tenter de joindre un service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidat {
    /// TCP ou UDP.
    pub protocole: Protocole,
    /// L'adresse.
    pub adresse: IpAddr,
    /// Le port.
    pub port: Port,
    /// Observée ou annoncée.
    pub origine: Origine,
}

impl Candidat {
    /// Le rang de préférence : plus petit veut dire « à essayer d'abord ».
    ///
    /// **IPv6 avant IPv4**, et ce n'est pas une préférence esthétique
    /// (`docs/modele.md` §1) : une machine à IPv6 publique n'est derrière aucun
    /// NAT, et son port annoncé est celui par lequel on l'atteint. IPv4 est le
    /// chemin où les problèmes commencent.
    ///
    /// Puis **réflexif avant annoncé**, parce que l'adresse observée est la
    /// seule qui vaille vue de l'extérieur quand les deux diffèrent.
    #[must_use]
    pub const fn rang(&self) -> (u8, u8) {
        let famille = match self.adresse {
            IpAddr::V6(_) => 0,
            IpAddr::V4(_) => 1,
        };
        let origine = match self.origine {
            Origine::Reflexif => 0,
            Origine::Annonce => 1,
        };
        (famille, origine)
    }
}

/// Ordonne des candidats : IPv6 d'abord, réflexif d'abord.
///
/// **Ce n'est pas au client de deviner lequel vaut** (`docs/protocole.md` §3) :
/// l'ordre est une décision, et elle se prend ici — une fois — plutôt que dans
/// chacune des cinq liaisons d'`asl-client`.
///
/// Le tri est *instable* et l'ordre reste pourtant déterministe : la clé
/// comprend l'adresse et le port, donc deux candidats distincts ne sont jamais
/// à égalité.
pub fn ordonner(candidats: &mut [Candidat]) {
    candidats.sort_unstable_by_key(|candidat| {
        let (famille, origine) = candidat.rang();
        (
            famille,
            origine,
            candidat.adresse,
            candidat.port,
            candidat.protocole,
        )
    });
}

impl fmt::Display for Candidat {
    /// **IPv6 entre crochets**, comme partout où une adresse côtoie un port.
    ///
    /// Sans eux, `2001:db8::1:49152` ne se relit pas : le dernier `:` est
    /// indiscernable d'un séparateur de groupe. C'est §3.2.2 de RFC 3986, et
    /// c'est un défaut classique qu'aucune relecture n'attrape parce qu'il ne se
    /// voit qu'en IPv6.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.adresse {
            IpAddr::V6(adresse) => write!(f, "[{adresse}]:{}", self.port),
            IpAddr::V4(adresse) => write!(f, "{adresse}:{}", self.port),
        }
    }
}

// ── Le message d'annonce ────────────────────────────────────────────────────

/// Ce qu'un daemon dit à l'ouverture de sa connexion.
///
/// **Il emprunte ses tranches** : rien n'est alloué ici, et le message vit aussi
/// longtemps que le tampon d'où il a été lu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Annonce<'a> {
    /// La machine qui héberge le daemon.
    pub machine: Identifiant,
    /// Le nom que le daemon se donne.
    pub service: NomService<'a>,
    /// Où il écoute.
    pub points: &'a [PointEcoute],
    /// Ses adresses locales, telles qu'il les voit.
    ///
    /// **Facultatif, et ce n'est pas ce qui sert à le joindre depuis
    /// l'Internet** (`docs/protocole.md` §1.1) : c'est ce qui permet à l'annuaire
    /// de trancher qu'il est derrière un NAT, en comparant avec ce qu'il observe.
    pub adresses_locales: &'a [IpAddr],
}

impl<'a> Annonce<'a> {
    /// Construit une annonce **et la valide**.
    ///
    /// Il n'y a pas d'autre constructeur : une `Annonce` qui existe est une
    /// annonce valide, et aucun appelant n'a à se souvenir d'appeler une
    /// vérification.
    ///
    /// # Ce qui est vérifié, et pourquoi chaque règle
    ///
    /// - **L'identifiant est celui d'une MACHINE.** Un identifiant de service
    ///   placé là passerait autrement pour une machine inconnue, et
    ///   l'administrateur chercherait une machine qu'il n'a jamais déclarée.
    /// - **Au moins un point d'écoute.** Une annonce sans point ne dit rien : le
    ///   daemon existe et on ne peut pas le joindre.
    /// - **Pas plus de [`POINTS_MAX`] ni de [`ADRESSES_MAX`].** Ces comptes
    ///   viennent du réseau (contrainte C3).
    /// - **Aucun doublon parmi les points.** Deux fois `tcp/49152` ne veut rien
    ///   dire, et la sonde le paierait deux fois.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasUneMachine`], [`Erreur::AucunPoint`],
    /// [`Erreur::TropDePoints`], [`Erreur::PointEnDouble`],
    /// [`Erreur::TropDAdresses`].
    pub fn nouvelle(
        machine: Identifiant,
        service: NomService<'a>,
        points: &'a [PointEcoute],
        adresses_locales: &'a [IpAddr],
    ) -> Result<Self, Erreur> {
        if machine.genre() != Genre::Machine {
            return Err(Erreur::PasUneMachine {
                obtenu: machine.genre(),
            });
        }
        if points.is_empty() {
            return Err(Erreur::AucunPoint);
        }
        if points.len() > POINTS_MAX {
            return Err(Erreur::TropDePoints {
                obtenu: points.len(),
            });
        }
        if adresses_locales.len() > ADRESSES_MAX {
            return Err(Erreur::TropDAdresses {
                obtenu: adresses_locales.len(),
            });
        }

        // Comparaison deux à deux : `POINTS_MAX` vaut huit, donc au plus
        // vingt-huit comparaisons. Un tri demanderait un tampon que cette crate
        // n'a pas le droit d'allouer, pour gagner sur un compte qui ne dépassera
        // jamais huit.
        for (rang, point) in points.iter().enumerate() {
            if points
                .iter()
                .skip(rang.saturating_add(1))
                .any(|autre| autre == point)
            {
                return Err(Erreur::PointEnDouble);
            }
        }

        Ok(Self {
            machine,
            service,
            points,
            adresses_locales,
        })
    }

    /// Le daemon annonce-t-il un point que l'annuaire saura sonder ?
    ///
    /// **Un daemon purement UDP ne sera jamais `joignable`**, seulement
    /// `annoncé` — et son administrateur doit l'apprendre de l'annuaire, pas
    /// d'un silence.
    #[must_use]
    pub fn a_un_point_sondable(&self) -> bool {
        self.points.iter().any(|point| point.protocole.se_sonde())
    }
}

// ── L'horodatage ────────────────────────────────────────────────────────────

/// Un instant, en **millisecondes depuis l'époque Unix**.
///
/// # Pourquoi un entier et non une date RFC 3339
///
/// L'exemple de `docs/protocole.md` §1.1 montrait `"2026-09-08T13:02:11Z"`.
/// Trois raisons l'ont écarté, et elles pèsent dans cet ordre :
///
/// 1. **Un analyseur de date est une ferme à bogues** : années bissextiles,
///    longueurs de mois, la soixantième seconde, les décalages. C'est une
///    surface d'analyse entière, exposée au réseau, pour transporter un nombre.
/// 2. **`asl-client` expose ceci à cinq langages**, qui ont chacun leur type de
///    date. Leur rendre un entier est plus honnête que leur rendre une chaîne
///    qu'ils devront analyser eux-mêmes — et chacun d'eux sait convertir un
///    entier d'époque en sa propre date.
/// 3. **Aucune ambiguïté** : pas de fuseau, pas d'heure locale, pas de forme
///    équivalente. C'est la règle « une seule écriture par valeur », appliquée
///    au temps.
///
/// **Le prix** : un humain qui lit le JSON avec `curl` voit `1789217731000` au
/// lieu d'une date. C'est réel, et c'est le travail de l'application ou de
/// l'utilitaire `asl` de l'afficher lisiblement — pas celui du protocole.
///
/// # Ce type ne sait pas quelle heure il est
///
/// Il ne PEUT pas le savoir : cette crate est à l'étage 1 et ne lit aucune
/// horloge (contrainte C1). L'instant vient toujours de l'appelant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Horodatage(u64);

impl Horodatage {
    /// Depuis des millisecondes d'époque.
    #[must_use]
    pub const fn depuis_millisecondes(millisecondes: u64) -> Self {
        Self(millisecondes)
    }

    /// Les millisecondes d'époque.
    #[must_use]
    pub const fn millisecondes(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Horodatage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Le bail ─────────────────────────────────────────────────────────────────

/// La cadence maximale d'un keepalive, en secondes.
///
/// Une heure. Au-delà, un mapping NAT est mort depuis longtemps et l'annuaire
/// mettrait une heure à s'apercevoir d'une coupure.
pub const KEEPALIVE_MAX: u16 = 3_600;

/// Ce que l'annuaire accorde : la cadence attendue et le délai d'inactivité.
///
/// **Les deux valeurs viennent du SERVEUR** (`docs/modele.md` §4.1) et ne sont
/// jamais figées dans le client. Sans cela, changer le delta après la campagne
/// de mesure exigerait de mettre à jour tous les daemons installés chez des
/// tiers — ce qui ne se produira jamais.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bail {
    keepalive_secondes: u16,
    inactivite_secondes: u16,
}

impl Bail {
    /// Construit un bail **et le valide**.
    ///
    /// # L'INVARIANT QUI COMPTE : l'inactivité vaut au moins deux keepalives
    ///
    /// À un pour un, **la première perte de paquet tue un daemon parfaitement
    /// sain**. `docs/modele.md` §4.1 dit exactement pourquoi c'est le mauvais
    /// compromis : une fausse alerte coûte plus cher qu'une détection tardive.
    ///
    /// La politique du produit est de trois pour un ; le type en exige deux.
    /// **Il refuse ce qui est absurde, il n'impose pas ce qui est prudent** — un
    /// type qui figerait la politique interdirait de la mesurer, alors qu'elle
    /// est explicitement en attente d'une campagne.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::KeepaliveNul`], [`Erreur::KeepaliveTropLong`],
    /// [`Erreur::InactiviteTropCourte`].
    pub const fn nouveau(
        keepalive_secondes: u16,
        inactivite_secondes: u16,
    ) -> Result<Self, Erreur> {
        if keepalive_secondes == 0 {
            return Err(Erreur::KeepaliveNul);
        }
        if keepalive_secondes > KEEPALIVE_MAX {
            return Err(Erreur::KeepaliveTropLong {
                obtenu: keepalive_secondes,
            });
        }
        // `saturating_mul` : à `keepalive` proche de `u16::MAX`, le double
        // déborderait — et un débordement rendrait acceptable exactement ce que
        // cette borne refuse.
        let minimum = keepalive_secondes.saturating_mul(2);
        if inactivite_secondes < minimum {
            return Err(Erreur::InactiviteTropCourte {
                obtenue: inactivite_secondes,
                minimum,
            });
        }
        Ok(Self {
            keepalive_secondes,
            inactivite_secondes,
        })
    }

    /// La cadence attendue.
    #[must_use]
    pub const fn keepalive_secondes(self) -> u16 {
        self.keepalive_secondes
    }

    /// Le délai au bout duquel l'annuaire conclut à une coupure.
    #[must_use]
    pub const fn inactivite_secondes(self) -> u16 {
        self.inactivite_secondes
    }
}

// ── Ce que l'annuaire a observé ─────────────────────────────────────────────

/// L'adresse sous laquelle l'annuaire a vu le daemon.
///
/// **Le champ `famille` de l'exemple des specs n'existe pas ici**, et c'est
/// délibéré : il se déduit de l'adresse. Un champ redondant est un champ qui
/// peut CONTREDIRE l'autre — `"famille":"ipv6"` sur une adresse v4 obligerait un
/// lecteur à choisir un gagnant, et deux lecteurs choisiraient différemment.
/// C'est la même faute que les champs en double du cadrage, écrite dans le
/// schéma au lieu du document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VuDepuis {
    /// L'adresse source observée.
    pub adresse: IpAddr,
    /// Le port source observé.
    pub port: Port,
}

impl VuDepuis {
    /// L'observation est-elle en IPv6 ?
    #[must_use]
    pub const fn est_ipv6(&self) -> bool {
        matches!(self.adresse, IpAddr::V6(_))
    }
}

/// Le daemon est-il derrière un NAT ?
///
/// # POURQUOI CE N'EST PAS UN BOOLÉEN (contrainte C6)
///
/// L'annuaire tranche en comparant ce qu'il OBSERVE à ce que le daemon ANNONCE.
/// **Si le daemon n'a annoncé aucune adresse locale, il n'y a rien à comparer**
/// — et un booléen forcerait alors à répondre « non », c'est-à-dire à affirmer
/// une chose qu'on n'a pas mesurée.
///
/// Un daemon derrière un NAT qui lirait « non » chercherait la panne partout
/// sauf là où elle est. C'est exactement ce que C6 existe pour empêcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictNat {
    /// L'adresse observée figure parmi celles que le daemon a annoncées.
    Non,
    /// L'adresse observée ne figure dans aucune de celles annoncées.
    Oui,
    /// **Le daemon n'a annoncé aucune adresse locale : rien à comparer.**
    Indetermine,
}

impl VerdictNat {
    /// Son écriture sur le fil.
    #[must_use]
    pub const fn texte(self) -> &'static str {
        match self {
            Self::Non => "non",
            Self::Oui => "oui",
            Self::Indetermine => "indetermine",
        }
    }

    /// Lit un verdict.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::VerdictNatInconnu`] si le texte n'en désigne aucun.
    pub fn analyser(texte: &str) -> Result<Self, Erreur> {
        match texte {
            "non" => Ok(Self::Non),
            "oui" => Ok(Self::Oui),
            "indetermine" => Ok(Self::Indetermine),
            _ => Err(Erreur::VerdictNatInconnu),
        }
    }
}

impl fmt::Display for VerdictNat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.texte())
    }
}

// ── La joignabilité ─────────────────────────────────────────────────────────

/// Pourquoi un point d'écoute n'a pas été sondé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RaisonNonSonde {
    /// **UDP n'a pas de poignée de main.** Une sonde n'y distingue pas
    /// « écoute et ignore » de « rien n'écoute » : elle ne mesurerait rien, et
    /// rendre un verdict à partir de rien est ce que C6 interdit.
    ProtocoleNonSondable,
}

impl RaisonNonSonde {
    /// Son écriture sur le fil.
    #[must_use]
    pub const fn texte(self) -> &'static str {
        match self {
            Self::ProtocoleNonSondable => "protocole_non_sondable",
        }
    }

    /// Lit une raison.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::RaisonInconnue`] si le texte n'en désigne aucune.
    pub fn analyser(texte: &str) -> Result<Self, Erreur> {
        match texte {
            "protocole_non_sondable" => Ok(Self::ProtocoleNonSondable),
            _ => Err(Erreur::RaisonInconnue),
        }
    }
}

impl fmt::Display for RaisonNonSonde {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.texte())
    }
}

/// Ce que l'annuaire sait de la joignabilité d'un point d'écoute.
///
/// # C6 EST ÉCRITE ICI, DANS LA FORME DU TYPE
///
/// **`Joignable` ne peut pas exister sans sa date et son candidat.** Ce n'est
/// pas une convention de remplissage : les deux sont DANS la variante, donc il
/// n'existe aucune façon d'affirmer « joignable » sans dire depuis quand ni par
/// où.
///
/// `docs/modele.md` §4.2 le demande — « un `joignable` sans date est un mensonge
/// à retardement : il décrit le passé au présent ». Une structure à champs
/// facultatifs aurait laissé quelqu'un l'omettre un jour de hâte ; le type, non.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// L'annuaire a ouvert une connexion vers ce candidat et l'a vue aboutir.
    Joignable {
        /// Par où. **Toujours présent.**
        candidat: Candidat,
        /// Quand. **Toujours présent.**
        a: Horodatage,
    },
    /// L'annuaire a essayé et n'a pas abouti.
    Injoignable {
        /// Quand l'essai a eu lieu.
        a: Horodatage,
    },
    /// Ce point ne se sonde pas.
    NonSonde {
        /// Pourquoi.
        raison: RaisonNonSonde,
    },
    /// **La sonde n'a pas encore rendu son verdict.**
    ///
    /// # Pourquoi cet état existe, et ce qu'il évite
    ///
    /// L'exemple des specs répond à une annonce en portant déjà les verdicts.
    /// Cela suppose que l'annuaire SONDE avant de répondre — donc qu'il fasse
    /// attendre le démarrage d'un daemon le temps d'une connexion TCP vers une
    /// machine qui peut ne jamais répondre. **Un daemon dont le démarrage dépend
    /// d'un délai d'attente réseau est un daemon qui démarre mal.**
    ///
    /// La connexion est TENUE (`docs/protocole.md` §0) : l'annuaire peut donc
    /// répondre tout de suite `en_cours`, sonder, et pousser le verdict ensuite.
    /// C'est précisément ce que le transport a été choisi pour permettre.
    EnCours,
}

impl Verdict {
    /// Son écriture sur le fil.
    #[must_use]
    pub const fn texte(&self) -> &'static str {
        match self {
            Self::Joignable { .. } => "joignable",
            Self::Injoignable { .. } => "injoignable",
            Self::NonSonde { .. } => "non_sonde",
            Self::EnCours => "en_cours",
        }
    }

    /// L'instant de la mesure, s'il y en a eu une.
    #[must_use]
    pub const fn mesure_a(&self) -> Option<Horodatage> {
        match self {
            Self::Joignable { a, .. } | Self::Injoignable { a } => Some(*a),
            Self::NonSonde { .. } | Self::EnCours => None,
        }
    }
}

/// Le verdict rendu pour un point d'écoute donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Joignabilite {
    /// Le point dont on parle.
    pub point: PointEcoute,
    /// Ce qu'on en sait.
    pub verdict: Verdict,
}

// ── Le message de réponse ───────────────────────────────────────────────────

/// Ce que l'annuaire répond à une annonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reponse<'a> {
    /// L'identifiant attribué au service.
    pub service: Identifiant,
    /// La cadence attendue et le délai d'inactivité.
    pub bail: Bail,
    /// Sous quelle adresse l'annuaire a vu le daemon.
    pub vu_depuis: VuDepuis,
    /// Le verdict de NAT, qui peut être indéterminé.
    pub derriere_nat: VerdictNat,
    /// Un verdict par point d'écoute annoncé.
    pub joignabilite: &'a [Joignabilite],
}

impl<'a> Reponse<'a> {
    /// Construit une réponse **et la valide**.
    ///
    /// # Ce qui est vérifié, et pourquoi
    ///
    /// - **L'identifiant est celui d'un SERVICE.** Rendre une machine là où le
    ///   daemon attend son service le ferait s'enregistrer sous un identifiant
    ///   qui en désigne un autre.
    /// - **Au moins un verdict**, et pas plus que [`POINTS_MAX`] : il y en a un
    ///   par point annoncé, et l'annonce était déjà bornée.
    /// - **Aucun point en double** parmi les verdicts. Deux verdicts pour le
    ///   même point, ce sont deux réponses à une seule question.
    /// - **UN POINT UDP N'EST JAMAIS `joignable` NI `injoignable`** (C6) : il ne
    ///   se sonde pas, donc l'annuaire n'a rien mesuré à son sujet. C'est
    ///   l'invariant que ce type existe pour tenir.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::PasUnService`], [`Erreur::AucuneJoignabilite`],
    /// [`Erreur::TropDeJoignabilites`], [`Erreur::PointEnDouble`],
    /// [`Erreur::VerdictImpossible`].
    pub fn nouvelle(
        service: Identifiant,
        bail: Bail,
        vu_depuis: VuDepuis,
        derriere_nat: VerdictNat,
        joignabilite: &'a [Joignabilite],
    ) -> Result<Self, Erreur> {
        if service.genre() != Genre::Service {
            return Err(Erreur::PasUnService {
                obtenu: service.genre(),
            });
        }
        if joignabilite.is_empty() {
            return Err(Erreur::AucuneJoignabilite);
        }
        if joignabilite.len() > POINTS_MAX {
            return Err(Erreur::TropDeJoignabilites {
                obtenu: joignabilite.len(),
            });
        }

        for (rang, entree) in joignabilite.iter().enumerate() {
            if joignabilite
                .iter()
                .skip(rang.saturating_add(1))
                .any(|autre| autre.point == entree.point)
            {
                return Err(Erreur::PointEnDouble);
            }

            // C6 : un point qui ne se sonde pas n'a pas pu être mesuré.
            let mesure = matches!(
                entree.verdict,
                Verdict::Joignable { .. } | Verdict::Injoignable { .. }
            );
            if mesure && !entree.point.protocole.se_sonde() {
                return Err(Erreur::VerdictImpossible);
            }
        }

        Ok(Self {
            service,
            bail,
            vu_depuis,
            derriere_nat,
            joignabilite,
        })
    }

    /// Au moins un point est-il constaté joignable ?
    ///
    /// **Ce n'est pas la même question que « le daemon est-il en ligne »**, et
    /// c'est tout l'objet de C6 : un daemon peut parler à l'annuaire sans être
    /// atteignable par qui que ce soit d'autre.
    #[must_use]
    pub fn un_point_est_joignable(&self) -> bool {
        self.joignabilite
            .iter()
            .any(|entree| matches!(entree.verdict, Verdict::Joignable { .. }))
    }
}
