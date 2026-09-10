//! La grammaire de l'API : **d'une cible HTTP vers une ressource**, et rien de
//! plus.
//!
//! # Ce que cette crate fait, et ce qu'elle ne fait pas
//!
//! Elle ne sert rien. Elle décrit ce qu'une requête DÉSIGNE et ce qu'elle
//! EXIGE ; ce qui la transporte est à l'étage 3, ce qui l'autorise est dans
//! `asl-auth`, et ce que valent les corps est le travail d'une tranche
//! ultérieure.
//!
//! **Écrit ici** : le routage — méthode et cible vers [`Ressource`], avec
//! l'[`Exigence`] que la ressource pose. **Pas écrit** : les CORPS des requêtes
//! et des réponses, en JSON. La frontière est la même que celle qui sépare les
//! valeurs du cadrage dans `asl-proto`.
//!
//! # LE ROUTAGE NE JUGE PAS LE VERBE, ET C'EST UNE PROPRIÉTÉ DE SÉCURITÉ
//!
//! [`resoudre`] rend la ressource **et dit si le verbe est servi**, mais elle
//! n'échoue jamais sur le verbe.
//!
//! Rendre un « méthode non permise » depuis le routage le rendrait AVANT toute
//! vérification d'autorisation — ce qui distinguerait une ressource qui existe
//! d'un chemin qui n'existe pas, exactement la distinction que C9 s'interdit.
//! C'est à la session de rendre ce refus, une fois l'autorisation acquise.
//!
//! # AUCUN POURCENT-ENCODAGE, ET LA RAISON EST CELLE DES ÉCHAPPEMENTS JSON
//!
//! Tout ce qui entre dans un chemin de cette API — identifiants en base32,
//! noms de service, alias — n'emploie **aucun caractère qui demande un
//! encodage**. Un `%75` à la place d'un `u` serait donc soit une deuxième
//! écriture de la même cible, soit une tentative de faire passer un caractère
//! que l'alphabet refuse.
//!
//! **Ce refus ferme d'un coup toute une famille de failles** : la traversée par
//! `%2e%2e`, la double-décodification, et le désaccord entre deux composants qui
//! ne décodent pas au même moment. Une seule écriture par cible, et il n'y a
//! rien à départager.
//!
//! **Et la traversée de chemin est structurellement impossible** : un segment
//! `.` ou `..` n'est ni un identifiant, ni un nom de service — les deux refusent
//! un point en tête ou en queue —, ni un alias. Il n'y a donc aucune règle
//! anti-traversée à écrire ; c'est l'alphabet qui la rend inutile.

#![no_std]

pub mod corps;

use asl_id::{Genre, Identifiant};
use asl_proto::NomService;

/// La longueur maximale d'une cible, en octets.
///
/// **Une borne existe parce que la longueur vient du réseau.** Le plus long
/// chemin de cette API tient dans une centaine d'octets ; 512 laisse de la marge
/// sans laisser de place à un abus.
pub const CIBLE_MAX: usize = 512;

/// La longueur minimale d'un alias.
pub const ALIAS_MIN: usize = 3;

/// La longueur maximale d'un alias.
pub const ALIAS_MAX: usize = 32;

// ── Les méthodes ────────────────────────────────────────────────────────────

/// Le verbe d'une requête.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Methode {
    /// Lire.
    Get,
    /// Créer.
    Post,
    /// Poser ou remplacer.
    Put,
    /// Modifier partiellement.
    Patch,
    /// Retirer.
    Delete,
}

impl Methode {
    /// Modifie-t-elle quelque chose ?
    #[must_use]
    pub const fn modifie(self) -> bool {
        !matches!(self, Self::Get)
    }
}

// ── Ce qu'une ressource exige ───────────────────────────────────────────────

/// Ce qu'il faut prouver pour atteindre une ressource.
///
/// **Ce n'est pas une autorisation, c'est une exigence.** Décider si elle est
/// remplie appartient à `asl-auth` ; nommer laquelle appartient ici, parce que
/// c'est une propriété de la RESSOURCE et non de la requête.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exigence {
    /// Une machine qui porte la capacité `annonce`.
    ///
    /// **ELLE NE SE CONFOND PAS AVEC [`Exigence::MachineLecture`]**, et les
    /// fondre serait la faute : un daemon qui annonce n'a aucune raison de
    /// pouvoir INTERROGER l'annuaire, et une machine qui interroge n'a aucune
    /// raison de pouvoir y écrire. `modele.md` §2.3 sépare les deux capacités
    /// précisément pour qu'on puisse n'en donner qu'une.
    MachineAnnonce,
    /// Une signature d'un appareil enrôlé du compte.
    ///
    /// C'est le cas de presque toute l'API mobile : il n'y a pas de mot de passe
    /// dans ce produit, et un compte est un jeu d'appareils enrôlés.
    Appareil,
    /// Une machine portant la capacité `lecture`.
    MachineLecture,
    /// **Rien.** Trois ressources seulement, et chacune pour une raison écrite.
    Aucune,
}

// ── Les ressources ──────────────────────────────────────────────────────────

/// Ce qu'une requête désigne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ressource<'a> {
    /// `/v1/annonce` — un daemon dit sur quel port il écoute.
    ///
    /// # C'EST LA RAISON D'ÊTRE DU PRODUIT, ET ELLE N'A QU'UN VERBE
    ///
    /// `POST` annonce ou réannonce. **Il n'y a pas de verbe pour RETIRER** :
    /// `protocole.md` §1.3 le dit — fermer la connexion suffit, et c'est
    /// instantané. Un `DELETE` ferait deux façons de dire la même chose, et
    /// l'annuaire devrait décider quoi faire d'un retrait qui croise un
    /// keepalive déjà en vol.
    ///
    /// Il n'y a pas non plus de verbe pour RAFRAÎCHIR : la connexion EST le
    /// bail, et le keepalive de QUIC suffit.
    Annonce,
    /// `/v1/poussees` — **le flux par lequel les verdicts arrivent.**
    ///
    /// # POURQUOI UNE RESSOURCE, ALORS QUE LA RÉPONSE NE VIENT JAMAIS
    ///
    /// `protocole.md` §1.4 : l'annuaire répond souvent `en_cours`, parce qu'il
    /// ne fait pas attendre le démarrage d'un daemon le temps d'une sonde. Le
    /// verdict arrive ensuite, « dans la connexion déjà tenue » — et il fallait
    /// bien un flux pour le porter.
    ///
    /// `GET` ouvre ce flux. **Sa réponse ne se termine pas** : le conducteur la
    /// tient ouverte, et y écrit une poussée à chaque verdict. Un client la lit
    /// à mesure, sans jamais attendre de fin.
    ///
    /// # ELLE EXIGE LA CAPACITÉ D'ANNONCE, ET NON CELLE DE LECTURE
    ///
    /// Un verdict porte sur des services QU'ON ANNONCE. Une machine de lecture
    /// seule n'en a aucun, et lui ouvrir ce flux lui donnerait un flux qui ne
    /// dira jamais rien — en tenant une ressource des deux côtés.
    Poussees,
    /// `/v1/vu` — **d'où l'annuaire voit cette connexion**, sans rien annoncer.
    ///
    /// # POURQUOI UNE ROUTE, ALORS QUE L'ANNONCE REND DÉJÀ CETTE ADRESSE
    ///
    /// La réponse à `POST /v1/annonce` porte le candidat réflexif — mais il
    /// faut avoir annoncé pour l'obtenir, c'est-à-dire avoir la capacité
    /// d'annonce et un service à publier. **Une machine de lecture seule, ou un
    /// daemon qui n'a pas encore ouvert son port, ne peuvent donc pas savoir
    /// comment on les voit.**
    ///
    /// C'est ce qu'il faut pour diagnostiquer : un daemon dont personne
    /// n'arrive à joindre le port veut d'abord savoir sous quelle adresse il
    /// sort, et il n'a aucun moyen de l'apprendre autrement.
    ///
    /// # ELLE N'EXIGE RIEN, ET C'EST DÉLIBÉRÉ
    ///
    /// Elle ne parle QUE de la connexion qui demande. Elle ne dit rien d'un
    /// compte, d'une machine ou d'un service — rien qu'un tiers puisse
    /// apprendre en la posant, sinon sa propre adresse, qu'il obtiendrait de
    /// n'importe quel serveur STUN public.
    ///
    /// **Il n'y a pas non plus d'amplification à craindre** : la poignée de main
    /// QUIC a déjà prouvé un aller-retour vers cette adresse, et la réponse est
    /// plus courte que la requête qui la demande.
    ///
    /// Exiger une clé aurait exclu le cas le plus utile — la machine qu'on est
    /// en train d'installer, qui veut savoir si elle atteint l'annuaire et
    /// comment il la voit, avant même d'avoir un code d'enrôlement.
    Vu,
    /// `/v1/defi` — le défi d'authentification de CETTE connexion.
    ///
    /// # POURQUOI UNE RESSOURCE, ET NON UNE POIGNÉE DE MAIN À PART
    ///
    /// L'authentification est portée par la CONNEXION (`protocole.md` §3), et
    /// elle pourrait donc vivre hors d'HTTP — dans un flux QUIC à nous, par
    /// exemple. La faire passer par l'API ordinaire évite un second cadrage, un
    /// second analyseur, et un second endroit où se tromper.
    ///
    /// `GET` tire un défi ; `POST` rapporte la signature. **Elle n'exige aucune
    /// preuve**, et pour cause : c'est elle qui la produit.
    Defi,
    /// `/v1/comptes` — créer un compte et enrôler son premier appareil.
    Comptes,
    /// `/v1/enrolement` — une MACHINE présente son code et sa clé publique.
    ///
    /// # ELLE MANQUAIT, ET SON ABSENCE ÉTAIT UN TROU DANS LA SPÉCIFICATION
    ///
    /// `protocole.md` §2.2 donnait `POST /v1/machines/{m}/enrolement`, qui ÉMET
    /// un code depuis l'application mobile. Il ne disait nulle part par où la
    /// machine RAPPORTE ce code avec sa clé — et `modele.md` §2.3 décrit
    /// pourtant le geste : « la machine génère sa paire de clés, et présente sa
    /// clé publique avec le code ».
    ///
    /// Les deux verbes sont aux deux bouts du même geste, et **ils n'ont ni le
    /// même public ni la même exigence** : celui-là est parlé par la machine, à
    /// qui l'annuaire ne connaît encore rien. C'est pourquoi il ne peut pas être
    /// un verbe de plus sous `/v1/machines/{m}` — il faudrait nommer la machine
    /// pour l'atteindre, et l'annuaire croirait alors sur parole celui qui la
    /// nomme. **Le code désigne la machine ; personne ne la désigne.**
    Enrolement,
    /// `/v1/utilisateurs/{u}` — **confirmer qu'un identifiant existe**, et rien
    /// d'autre : ni nom, ni machines, ni services.
    Utilisateur {
        /// Le compte visé.
        compte: Identifiant,
    },
    /// `/v1/appareils` — enrôler un appareil de plus.
    Appareils,
    /// `/v1/appareils/{a}` — révoquer.
    Appareil {
        /// L'appareil visé.
        appareil: Identifiant,
    },
    /// `/v1/appareils/{a}/poussee` — déposer un jeton APNs ou FCM.
    PousseeAppareil {
        /// L'appareil visé.
        appareil: Identifiant,
    },
    /// `/v1/machines` — déclarer une machine.
    Machines,
    /// `/v1/machines/{m}` — changer son nom ou ses capacités.
    Machine {
        /// La machine visée.
        machine: Identifiant,
    },
    /// `/v1/machines/{m}/enrolement` — émettre un nouveau code.
    EnrolementMachine {
        /// La machine visée.
        machine: Identifiant,
    },
    /// `/v1/machines/{m}/cle` — révoquer la clé.
    CleMachine {
        /// La machine visée.
        machine: Identifiant,
    },
    /// `/v1/machines/{m}/services` — les services et leur état.
    ServicesMachine {
        /// La machine visée.
        machine: Identifiant,
    },
    /// `/v1/autorisations` — accorder, ou lister dans les deux sens.
    Autorisations,
    /// `/v1/autorisations/{g}` — révoquer.
    Autorisation {
        /// L'autorisation visée.
        autorisation: Identifiant,
    },
    /// `/v1/alias` — enregistrer ou retirer le sien.
    Alias,
    /// `/v1/alias/{alias}` — **la seule ressource publique en lecture**.
    AliasResolu {
        /// L'alias demandé.
        alias: Alias<'a>,
    },
    /// `/v1/expositions` — ce qui est exposé de moi, relation par relation.
    Expositions,
    /// `/v1/expositions/{n}` — m'en retirer.
    Exposition {
        /// L'annuaire pair concerné.
        annuaire: Identifiant,
    },
    /// `/v1/ou/{m}/{service}` — où joindre ce service précis.
    Ou {
        /// La machine qui le porte.
        machine: Identifiant,
        /// Son nom.
        service: NomService<'a>,
    },
    /// `/v1/ou?service={nom}` — **toutes** les instances de ce nom qu'on a le
    /// droit de voir.
    ///
    /// C'est la forme qu'un client emploie en pratique : le scénario du produit
    /// n'est pas « un service » mais « le même daemon sur cinq machines ».
    OuParNom {
        /// Le nom cherché.
        service: NomService<'a>,
    },
}

impl Ressource<'_> {
    /// Les verbes que cette ressource sert.
    #[must_use]
    pub const fn verbes(&self) -> &'static [Methode] {
        match self {
            Self::Annonce => &[Methode::Post],
            Self::Defi => &[Methode::Get, Methode::Post],
            Self::Comptes | Self::Appareils | Self::Machines | Self::Enrolement => &[Methode::Post],
            Self::Utilisateur { .. }
            | Self::Vu
            | Self::Poussees
            | Self::ServicesMachine { .. }
            | Self::Expositions
            | Self::AliasResolu { .. }
            | Self::Ou { .. }
            | Self::OuParNom { .. } => &[Methode::Get],
            Self::Appareil { .. }
            | Self::CleMachine { .. }
            | Self::Autorisation { .. }
            | Self::Exposition { .. } => &[Methode::Delete],
            Self::PousseeAppareil { .. } => &[Methode::Put],
            Self::Machine { .. } => &[Methode::Patch],
            Self::EnrolementMachine { .. } => &[Methode::Post],
            Self::Autorisations => &[Methode::Get, Methode::Post],
            Self::Alias => &[Methode::Put, Methode::Delete],
        }
    }

    /// Sert-elle ce verbe ?
    #[must_use]
    pub fn sert(&self, methode: Methode) -> bool {
        self.verbes().contains(&methode)
    }

    /// Ce qu'il faut prouver pour l'atteindre.
    ///
    /// # LES CINQ RESSOURCES SANS EXIGENCE, ET POURQUOI CHACUNE
    ///
    /// - **`/v1/comptes`** : on n'a pas encore de compte. C'est l'attestation de
    ///   la plate-forme qui protège ce chemin, pas une signature de compte.
    /// - **`/v1/enrolement`** : la machine n'a pas encore de clé — c'est
    ///   justement ce qu'elle vient poser. **Le code d'enrôlement EST le
    ///   justificatif**, et il est nommé comme tel (C14) : à usage unique,
    ///   valable quelques minutes, et il n'ouvre que cette opération-là.
    /// - **`/v1/alias/{alias}`** : l'alias est **public par construction**
    ///   (`docs/modele.md` §2.1). C'est son emploi, et son coût — il rend
    ///   l'espace des alias énumérable, contrairement à tout le reste.
    /// - **`/v1/utilisateurs/{u}`** : il ne rend qu'un booléen, à qui détient
    ///   déjà 128 bits qu'il ne peut pas deviner et qu'il tient de son porteur.
    /// - **`/v1/vu`** : elle ne parle que de la connexion qui demande, et ne
    ///   rend rien qu'un serveur STUN public ne rendrait. Voir [`Ressource::Vu`].
    #[must_use]
    pub const fn exigence(&self) -> Exigence {
        match self {
            Self::Defi
            | Self::Comptes
            | Self::Enrolement
            | Self::AliasResolu { .. }
            | Self::Vu
            | Self::Utilisateur { .. } => Exigence::Aucune,
            Self::Annonce | Self::Poussees => Exigence::MachineAnnonce,
            Self::Ou { .. } | Self::OuParNom { .. } => Exigence::MachineLecture,
            _ => Exigence::Appareil,
        }
    }
}

/// Ce qu'un routage a compris.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolu<'a> {
    /// Ce que la requête désigne.
    pub ressource: Ressource<'a>,
    /// Le verbe reçu.
    pub methode: Methode,
    /// La ressource sert-elle ce verbe ?
    ///
    /// **Le routage ne juge pas le verbe** (voir l'en-tête du module) : il le
    /// rapporte, et c'est la session qui en tire un refus après autorisation.
    pub sert: bool,
    /// Ce qu'il faut prouver.
    pub exigence: Exigence,
}

// ── L'alias ─────────────────────────────────────────────────────────────────

/// Un alias public, celui qu'on donne pour être retrouvé.
///
/// # L'ALPHABET, ET LA RÈGLE QUI L'A FAIT CHOISIR
///
/// Minuscules ASCII, chiffres, `-`, `_`, `.` — le même que celui d'un nom de
/// service, et pour la même raison : il voyage dans une URL, et tout ce qui
/// demanderait un encodage ouvrirait deux écritures du même alias.
///
/// # ET IL NE PEUT PAS RESSEMBLER À UN IDENTIFIANT
///
/// **Un alias dont le deuxième caractère est un tiret est refusé.** Ce n'est pas
/// une coquetterie : dans l'application, un utilisateur tape SOIT un identifiant
/// (`u-…`) SOIT un alias, dans le MÊME champ. Si les deux formes pouvaient se
/// confondre, l'application devrait deviner — et se tromperait un jour sur un
/// alias que quelqu'un aurait choisi exprès.
///
/// Les deux espaces de noms ne se recouvrent donc pas, par construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Alias<'a>(&'a str);

impl<'a> Alias<'a> {
    /// Lit un alias.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::AliasLongueur`], [`Erreur::AliasSymboleInvalide`],
    /// [`Erreur::AliasBordInvalide`], [`Erreur::AliasRessembleAUnIdentifiant`].
    pub fn analyser(texte: &'a str) -> Result<Self, Erreur> {
        let octets = texte.as_bytes();
        if octets.len() < ALIAS_MIN || octets.len() > ALIAS_MAX {
            return Err(Erreur::AliasLongueur {
                obtenue: octets.len(),
            });
        }
        for (position, &octet) in octets.iter().enumerate() {
            let permis = octet.is_ascii_lowercase()
                || octet.is_ascii_digit()
                || matches!(octet, b'-' | b'_' | b'.');
            if !permis {
                return Err(Erreur::AliasSymboleInvalide { position });
            }
        }
        let premier = octets[0];
        let dernier = octets[octets.len().saturating_sub(1)];
        if matches!(premier, b'-' | b'.') || matches!(dernier, b'-' | b'.') {
            return Err(Erreur::AliasBordInvalide);
        }
        if octets.get(1) == Some(&b'-') {
            return Err(Erreur::AliasRessembleAUnIdentifiant);
        }
        Ok(Self(texte))
    }

    /// L'alias.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

// ── Les erreurs ─────────────────────────────────────────────────────────────

/// Ce qui peut clocher dans une cible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// La cible dépasse [`CIBLE_MAX`] octets.
    CibleTropLongue {
        /// La longueur reçue.
        obtenue: usize,
    },
    /// La cible ne commence pas par `/`.
    CibleSansRacine,
    /// La cible n'est pas de l'UTF-8.
    ///
    /// Elle n'a pas à l'être en principe — ce protocole n'emploie que de
    /// l'ASCII — mais un octet hors ASCII doit être refusé, pas interprété.
    CibleNonAscii {
        /// Où.
        position: usize,
    },
    /// Un segment est vide : `//` ou un `/` final de trop.
    SegmentVide {
        /// Son rang dans le chemin.
        rang: usize,
    },
    /// La cible porte un pourcent-encodage.
    ///
    /// **Refusé, jamais décodé** : voir l'en-tête du module.
    EncodageRefuse {
        /// Où.
        position: usize,
    },
    /// Aucune ressource ne correspond à ce chemin.
    RessourceInconnue,
    /// Un identifiant du chemin est mal formé, ou du mauvais genre.
    IdentifiantInvalide {
        /// Le genre attendu à cet endroit.
        attendu: Genre,
    },
    /// Un nom de service du chemin est mal formé.
    NomInvalide,
    /// L'alias est trop court ou trop long.
    AliasLongueur {
        /// La longueur reçue.
        obtenue: usize,
    },
    /// L'alias porte un octet hors de l'alphabet.
    AliasSymboleInvalide {
        /// Sa position.
        position: usize,
    },
    /// L'alias commence ou finit par `-` ou `.`.
    AliasBordInvalide,
    /// L'alias a la forme d'un identifiant.
    AliasRessembleAUnIdentifiant,
    /// La chaîne de requête est mal formée, ou porte autre chose que `service`.
    RequeteInvalide,
}

// ── Le routage ──────────────────────────────────────────────────────────────

/// Sépare le chemin de la chaîne de requête.
///
/// **Ce qui suit le `?` est hors du chemin.** L'y laisser entrer ferait d'un
/// paramètre un nom de ressource.
#[must_use]
pub fn separer_requete(cible: &[u8]) -> (&[u8], &[u8]) {
    match cible.iter().position(|octet| *octet == b'?') {
        Some(coupure) => {
            let chemin = cible.get(..coupure).unwrap_or(&[]);
            let requete = cible.get(coupure.saturating_add(1)..).unwrap_or(&[]);
            (chemin, requete)
        }
        None => (cible, &[]),
    }
}

/// Résout une cible.
///
/// # Erreurs
///
/// Voir [`Erreur`].
pub fn resoudre(methode: Methode, cible: &[u8]) -> Result<Resolu<'_>, Erreur> {
    if cible.len() > CIBLE_MAX {
        return Err(Erreur::CibleTropLongue {
            obtenue: cible.len(),
        });
    }

    let (chemin, requete) = separer_requete(cible);

    for (position, &octet) in chemin.iter().enumerate() {
        if octet == b'%' {
            return Err(Erreur::EncodageRefuse { position });
        }
        if !octet.is_ascii_graphic() {
            return Err(Erreur::CibleNonAscii { position });
        }
    }
    if chemin.first() != Some(&b'/') {
        return Err(Erreur::CibleSansRacine);
    }

    let mut segments = [""; 5];
    let mut nombre = 0_usize;
    for (rang, brut) in chemin
        .get(1..)
        .unwrap_or(&[])
        .split(|octet| *octet == b'/')
        .enumerate()
    {
        if brut.is_empty() {
            return Err(Erreur::SegmentVide { rang });
        }
        // **CE CHEMIN NE PEUT PAS ÉCHOUER** : chaque octet a été vérifié ASCII
        // graphique juste au-dessus. Un `?` aurait posé une branche que rien ne
        // peut atteindre, donc du code que personne n'éprouvera jamais et que
        // tout le monde croirait éprouvé.
        //
        // Le repli est le vide, et il est SÛR : un segment vide ne correspond à
        // aucune ressource, et la table rend `RessourceInconnue`.
        let texte = core::str::from_utf8(brut).unwrap_or("");
        match segments.get_mut(rang) {
            Some(place) => *place = texte,
            None => return Err(Erreur::RessourceInconnue),
        }
        nombre = nombre.saturating_add(1);
    }

    let ressource = router(segments.get(..nombre).unwrap_or(&[]), requete)?;
    Ok(Resolu {
        ressource,
        methode,
        sert: ressource.sert(methode),
        exigence: ressource.exigence(),
    })
}

/// Lit l'identifiant d'un segment, en exigeant son genre.
fn identifiant(segment: &str, attendu: Genre) -> Result<Identifiant, Erreur> {
    Identifiant::analyser_genre(attendu, segment)
        .map_err(|_| Erreur::IdentifiantInvalide { attendu })
}

/// Le nom de service que porte la chaîne de requête, pour `/v1/ou`.
///
/// **Un seul paramètre est admis**, et il s'appelle `service`. Accepter des
/// paramètres inconnus reviendrait à les ignorer, donc à laisser un client croire
/// qu'il a demandé quelque chose que personne n'a lu.
fn service_de_la_requete(requete: &[u8]) -> Result<NomService<'_>, Erreur> {
    let valeur = requete
        .strip_prefix(b"service=")
        .ok_or(Erreur::RequeteInvalide)?;
    let texte = core::str::from_utf8(valeur).map_err(|_| Erreur::RequeteInvalide)?;
    NomService::analyser(texte).map_err(|_| Erreur::NomInvalide)
}

/// La table des chemins.
fn router<'a>(segments: &[&'a str], requete: &'a [u8]) -> Result<Ressource<'a>, Erreur> {
    match segments {
        ["v1", "annonce"] => Ok(Ressource::Annonce),
        ["v1", "defi"] => Ok(Ressource::Defi),
        ["v1", "comptes"] => Ok(Ressource::Comptes),
        ["v1", "enrolement"] => Ok(Ressource::Enrolement),
        ["v1", "utilisateurs", compte] => Ok(Ressource::Utilisateur {
            compte: identifiant(compte, Genre::Utilisateur)?,
        }),
        ["v1", "appareils"] => Ok(Ressource::Appareils),
        ["v1", "appareils", appareil] => Ok(Ressource::Appareil {
            appareil: identifiant(appareil, Genre::Appareil)?,
        }),
        ["v1", "appareils", appareil, "poussee"] => Ok(Ressource::PousseeAppareil {
            appareil: identifiant(appareil, Genre::Appareil)?,
        }),
        ["v1", "machines"] => Ok(Ressource::Machines),
        ["v1", "machines", machine] => Ok(Ressource::Machine {
            machine: identifiant(machine, Genre::Machine)?,
        }),
        ["v1", "machines", machine, "enrolement"] => Ok(Ressource::EnrolementMachine {
            machine: identifiant(machine, Genre::Machine)?,
        }),
        ["v1", "machines", machine, "cle"] => Ok(Ressource::CleMachine {
            machine: identifiant(machine, Genre::Machine)?,
        }),
        ["v1", "machines", machine, "services"] => Ok(Ressource::ServicesMachine {
            machine: identifiant(machine, Genre::Machine)?,
        }),
        ["v1", "poussees"] => Ok(Ressource::Poussees),
        ["v1", "vu"] => Ok(Ressource::Vu),
        ["v1", "autorisations"] => Ok(Ressource::Autorisations),
        ["v1", "autorisations", autorisation] => Ok(Ressource::Autorisation {
            autorisation: identifiant(autorisation, Genre::Autorisation)?,
        }),
        ["v1", "alias"] => Ok(Ressource::Alias),
        ["v1", "alias", alias] => Ok(Ressource::AliasResolu {
            alias: Alias::analyser(alias)?,
        }),
        ["v1", "expositions"] => Ok(Ressource::Expositions),
        ["v1", "expositions", annuaire] => Ok(Ressource::Exposition {
            annuaire: identifiant(annuaire, Genre::Annuaire)?,
        }),
        ["v1", "ou"] => Ok(Ressource::OuParNom {
            service: service_de_la_requete(requete)?,
        }),
        ["v1", "ou", machine, service] => Ok(Ressource::Ou {
            machine: identifiant(machine, Genre::Machine)?,
            service: NomService::analyser(service).map_err(|_| Erreur::NomInvalide)?,
        }),
        _ => Err(Erreur::RessourceInconnue),
    }
}
