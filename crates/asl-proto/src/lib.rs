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
//! # DEUX TRANCHES, ET CELLE-CI EST LA PREMIÈRE
//!
//! **Écrite ici** : les VALEURS du protocole et leurs invariants — protocoles,
//! ports, noms de service, points d'écoute, candidats d'adresse — plus le
//! message d'annonce et sa validation.
//!
//! **Pas encore écrit** : le CADRAGE, c'est-à-dire le JSON qui les transporte
//! (`docs/protocole.md` §0).
//!
//! Cette frontière n'est pas une commodité de découpage : c'est celle que §4.3
//! du même document désigne comme la seule qui bougera si l'on passe un jour à
//! un cadrage binaire. Les valeurs, elles, ne bougeront pas — ce sont elles que
//! `asl-annuaire` manipule et que `asl-client` expose.
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
