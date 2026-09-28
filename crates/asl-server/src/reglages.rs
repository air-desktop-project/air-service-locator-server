//! Ce qu'on lit sur la ligne de commande.
//!
//! # POURQUOI PAS DE BIBLIOTHÈQUE D'ARGUMENTS
//!
//! Il y a une douzaine de réglages, tous de la forme `--nom valeur`. Une bibliothèque
//! apporterait une grammaire complète — sous-commandes, formes courtes,
//! complétion — dont rien ici ne se sert, et une vingtaine d'unités dans un
//! graphe que C4 borne à cent vingt.
//!
//! Le jour où il y aura des sous-commandes, la question se reposera. Elle ne se
//! pose pas aujourd'hui.
//!
//! # ET POURQUOI PAS DE FICHIER DE CONFIGURATION
//!
//! **Parce qu'un fichier de configuration est un second endroit où mettre la
//! vérité.** Un service lancé par systemd a déjà une unité qui porte sa ligne de
//! commande ; y ajouter un fichier ferait deux sources, et l'on chercherait
//! toujours dans la mauvaise.
//!
//! # LA LECTURE NE FAIT AUCUNE ENTRÉE-SORTIE, ET C'EST CE QUI LA REND ÉPROUVABLE
//!
//! [`Reglages::depuis`] prend une suite de chaînes, pas `std::env::args`. Un
//! essai lui donne donc ce qu'il veut, sans lancer de processus.

use std::path::PathBuf;

use asl_proto::PORT_PAR_DEFAUT;

/// Ce qu'un annuaire a besoin de savoir pour démarrer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reglages {
    /// Le fichier de l'entrepôt.
    pub entrepot: PathBuf,
    /// Le port d'écoute.
    pub port: u16,
    /// Combien de connexions vivent en même temps, au plus.
    pub connexions_max: usize,
    /// L'inactivité annoncée aux pairs, en secondes.
    pub inactivite_s: u64,
    /// La cadence de maintien qu'on demande aux daemons, en secondes.
    pub keepalive_s: u64,
    /// La rétention du journal, en jours (C18).
    pub retention_jours: u64,
    /// Ce que l'annuaire exige d'un appareil qui s'enrôle.
    ///
    /// **IL N'Y A PAS DE DÉFAUT, ET C'EST LE SEUL RÉGLAGE DANS CE CAS.**
    ///
    /// `protocole.md` §2.1 tranche : la v1 refuse un enrôlement sans
    /// attestation de plate-forme. **Mais la vérification n'est pas écrite** —
    /// App Attest et Play Integrity demandent les racines d'Apple et de Google,
    /// du CBOR et une chaîne à valider. Exiger l'attestation aujourd'hui, c'est
    /// donc refuser TOUS les enrôlements.
    ///
    /// Les deux postures sont défendables et aucune ne peut être le défaut :
    /// `required` livrerait un annuaire qui ne crée aucun compte, `optional`
    /// livrerait en silence la posture faible. **L'exploitant dit laquelle il
    /// tient**, et l'annuaire ne démarre pas tant qu'il ne l'a pas dit.
    pub politique: asl_auth::Politique,
    /// De quoi vérifier une attestation App Attest, si l'exploitant l'a fournie.
    ///
    /// # POURQUOI OPTIONNEL, ET CE QUE SON ABSENCE VEUT DIRE
    ///
    /// Vérifier une attestation d'Apple demande deux choses que seul
    /// l'exploitant connaît : l'**identifiant de l'app** (`ABCDE12345.ch.narro.app`),
    /// dont l'empreinte doit égaler le `rpIdHash`, et l'**environnement**
    /// attendu — production, ou développement. La racine d'Apple, elle, est la
    /// même pour tous et vit dans `asl_apple::RACINE_APPLE`.
    ///
    /// **Sans ces deux réglages, aucune attestation Apple ne peut être
    /// vérifiée** : un compte qui en déclare une est alors refusé, faute de quoi
    /// la comparer. Un annuaire `optional` sans configuration Apple crée donc
    /// des comptes sans attestation, et refuse ceux qui en présentent une.
    pub apple: Option<ReglageApple>,
    /// De quoi vérifier une attestation de clé Android, si l'exploitant l'a
    /// fournie (`protocole.md` §2.1, décidé le 2026-09-16 ; C19).
    ///
    /// # TROIS RÉGLAGES, ET LA RACINE EN EST UN
    ///
    /// Contrairement à Apple, dont la racine vit dans le binaire, **la racine
    /// d'une attestation Android est un fichier que l'exploitant épingle**
    /// (`--android-roots`, un PEM, répétable) : celle de Google pour les
    /// Android certifiés, celle de GrapheneOS, la sienne. Le dépôt en expédie
    /// en exemple sous `paquet/racines-android/`, et n'en impose aucune. Avec
    /// elle, le paquet de notre app (`--android-app`) et l'empreinte SHA-256
    /// du certificat qui signe la build (`--android-signer`).
    ///
    /// **Sans ces trois réglages, aucune attestation Android ne peut être
    /// vérifiée** : un compte qui en déclare une est alors refusé, comme pour
    /// Apple.
    pub android: Option<ReglageAndroid>,
    /// Le fichier de la clé d'identité Ed25519 de cette racine
    /// (`--identity-key`), si elle en a une.
    ///
    /// # SANS ELLE, LA RACINE TOURNE COMME AVANT — ET LE DIT
    ///
    /// `docs/replication.md` §2.2 : l'identifiant `n-…` d'une racine se
    /// déduit de sa clé d'identité. **Obligatoire depuis 0.34.0** (fin de la
    /// transition, décision 58) : c'est d'elle que l'annuaire frappe le seul
    /// certificat qu'il présente — sans elle, il n'aurait rien à montrer à
    /// la poignée de main. **Une clé ne se génère jamais en silence** (§8) :
    /// `--new-identity-key` l'écrit, et s'arrête.
    pub identite: PathBuf,
    /// L'autre racine — son adresse et sa clé publique —, si l'exploitant
    /// l'a réglée.
    ///
    /// **Les deux vont ensemble** (§8) : `--peer` sans `--peer-key` refuse de
    /// démarrer, parce qu'une adresse seule n'est pas une racine
    /// (`annuaires.md` §2), et une clé seule ne se joint pas.
    pub pair: Option<ReglagePair>,
    /// Le délai de la règle des orphelins (`--orphans`), en jours — zéro
    /// pour jamais.
    ///
    /// `docs/modele.md` §2.1 (2026-09-18) : un compte dont tous les appareils
    /// sont révoqués est effacé par la racine tant de jours après la
    /// révocation du dernier, cause `orphelin`. **Trente par défaut** — la
    /// fenêtre de propagation la plus longue qu'on tolère, et la rétention du
    /// journal d'opérations. `0` : la racine n'efface jamais d'elle-même, et
    /// le dit au démarrage ; tout effacement est alors un acte humain, le
    /// titulaire ou `--forget`. **Les deux racines doivent porter la même
    /// valeur** (`replication.md` §8) : c'est une consigne de déploiement.
    pub orphelins_jours: u64,
    /// La clé publique de l'exploitant (`--operator-key`) : ce contre quoi la
    /// signature de `POST /v1/invitations` se vérifie (`protocole.md` §2.2).
    ///
    /// **Obligatoire sous la posture `invitation`, interdite nulle part** :
    /// une racine qui exige une invitation sans pouvoir en émettre est une
    /// racine où personne n'entre. Sous les autres postures, la ressource
    /// n'existe pas et répond `404`.
    ///
    /// C'est la forme exacte de `--peer-key` : un fichier, trente-deux octets
    /// bruts, une clé PUBLIQUE. La partie privée vit là où l'exploitant émet
    /// ses invitations, jamais sur le banc.
    pub exploitant: Option<PathBuf>,
    /// Ce que vit une invitation (`--invitation-ttl`), en secondes.
    ///
    /// **Vingt-quatre heures par défaut, une semaine au plus** : une
    /// invitation s'envoie à quelqu'un qui n'est pas devant vous, là où les
    /// dix minutes d'un code d'enrôlement supposent l'humain devant ses deux
    /// écrans.
    pub invitation_ttl_s: u64,
    /// Les racines contre lesquelles les serveurs de poussée se vérifient
    /// (`--push-roots`, un PEM) — typiquement le paquet de certificats de la
    /// distribution (`protocole.md` §2.2, « Le client sortant »).
    ///
    /// **SANS ELLES, RIEN NE PART** : ni résolution, ni connexion, et le
    /// démarrage le dit. `GET /v1/nouvelles` reste servi. Épinglées comme
    /// `--android-roots` (C19) : un fichier que l'exploitant désigne, jamais
    /// un magasin lu en silence.
    pub racines_de_poussee: Option<PathBuf>,
    /// **Cet annuaire est un annuaire LOCAL** : les racines vers lesquelles il
    /// fédère (`--federation`, répétable) — `docs/protocole.md` §3 ter,
    /// 0.28.0.
    ///
    /// **Sans ce réglage, il est une racine**, et ne fédère vers personne.
    /// Avec lui, il ouvre une voie vers chacune, prouve sa clé d'identité
    /// (`--identity-key`), tire les machines de ses
    /// domaines et pousse l'état de leurs services. C'est l'annuaire local
    /// qui ouvre : aucun port entrant n'est nécessaire pour cette voie.
    pub federation: Option<ReglageFederation>,
}

/// Les racines vers lesquelles un annuaire local fédère.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglageFederation {
    /// Chaque racine : un locateur `hôte:port`, et l'identité `n-…` qu'on
    /// doit y trouver si elle est dite (`--federation <locateur>=<n-…>`,
    /// décision 58). **Chacune reçoit sa voie** : l'état des services ne se
    /// réplique pas entre racines, et une racine qu'on ne joint pas ne sait
    /// rien de nos services.
    pub racines: Vec<CibleFederee>,
    /// Où l'on joint CET annuaire (`--locator`, répétable, quatre au plus),
    /// publié aux racines à chaque ouverture de sa voie (décision 57). **Vide,
    /// il retire ce qui était publié** : l'adresse déclarée à l'inscription
    /// sert de nouveau.
    pub locateurs: Vec<String>,
}

/// Une racine vers laquelle un annuaire local fédère.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibleFederee {
    /// Où la joindre : `hôte:port` — un locateur, sans valeur de confiance.
    pub adresse: String,
    /// Qui l'on doit y trouver, si c'est dit ; sinon, la liste embarquée des
    /// racines dit qui se trouve au bout de ce locateur (décision 56).
    pub identite: Option<asl_id::Identifiant>,
}

/// Le geste `--forget` : effacer CE compte, hors ligne, et s'arrêter.
///
/// `docs/modele.md` §2.1, `replication.md` §8 : l'exception pour « la clé est
/// perdue et l'on le sait » — un simulateur remis à zéro, une app qui a écrit
/// sa clé au mauvais endroit —, que la règle des orphelins n'attrape pas
/// parce qu'elle ne compte que les révocations (C6). **Un identifiant à la
/// fois, et pas de liste** : c'est un geste qu'on fait en regardant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oubli {
    /// Le compte à effacer.
    pub compte: asl_id::Identifiant,
    /// Le fichier de l'entrepôt (`--store`).
    pub entrepot: PathBuf,
    /// La clé d'identité de cette racine (`--identity-key`), si elle est
    /// donnée : l'opération est alors estampillée sous la bonne racine tout
    /// de suite. Sans elle, sous seize zéros — et le daemon la fera passer
    /// sous son identité au démarrage suivant (`replication.md` §11.4).
    pub identite: Option<PathBuf>,
}

/// Le geste `--invite` : émettre une invitation, et s'arrêter.
///
/// `docs/protocole.md` §2.2 : l'exploitant ouvre une connexion vers un
/// annuaire **EN MARCHE**, signe `genre ‖ défi ‖ liaison` de sa clé, et reçoit
/// un code en clair — une fois. **Rien de commun avec `--forget`**, qui veut
/// l'entrepôt arrêté : ici on ne touche à aucun fichier de la racine, et l'on
/// peut émettre depuis une autre machine que le banc. C'est même ce qu'il faut
/// faire : la partie privée de la clé d'exploitation ne se pose pas sur un
/// banc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// Où joindre l'annuaire : `hôte:port`, une adresse IPv6 entre crochets.
    pub annuaire: String,
    /// La clé PRIVÉE de l'exploitant, trente-deux octets bruts : celle dont
    /// l'annuaire épingle la publique par `--operator-key`.
    pub secrete: PathBuf,
}

/// Le geste `--add-admin` / `--remove-admin` : nommer ou retirer un
/// administrateur des racines, et s'arrêter (`docs/modele.md` §2.12,
/// 2026-09-27).
///
/// **Le même geste que `--invite`** — un annuaire EN MARCHE, la clé privée de
/// l'exploitant, jamais sur le banc —, et un compte de plus : celui qu'on
/// nomme ou qu'on retire. Les deux racines se répliquent : en nommer un chez
/// l'une suffit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Administration {
    /// Où joindre l'annuaire, qui l'on doit y trouver, et la clé qui signe —
    /// ceux de `--invite`.
    pub joindre: Invite,
    /// Le compte nommé ou retiré.
    pub compte: asl_id::Identifiant,
    /// Nommer (`--add-admin`), ou retirer (`--remove-admin`).
    pub nomme: bool,
}

/// Le geste `--register` / `--registration-status` : un annuaire LOCAL se
/// présente aux racines avec sa clé d'identité, ou relit son inscription, et
/// s'arrête (`docs/annuaires.md` §4.1, 0.27.0).
///
/// **La clé est celle d'identité de l'annuaire local** — celle que
/// `--new-identity-key` frappe, dont son `n-…` se déduit —, et elle ne quitte
/// pas la machine : on prouve qu'on la détient, on ne l'envoie pas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inscription {
    /// Où joindre une racine : `hôte:port`.
    pub racine: String,
    /// La clé d'identité de cet annuaire local.
    pub identite: PathBuf,
    /// Le code que l'application a donné — ou rien : relire l'état.
    pub code: Option<String>,
}

/// L'autre racine, telle qu'on la joint et telle qu'on la reconnaît.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglagePair {
    /// Où elle écoute : `hôte:port`, un nom ou une adresse — une adresse
    /// IPv6 entre crochets.
    pub adresse: String,
    /// Le fichier de sa clé d'identité publique (`--peer-key`) : ce contre quoi
    /// sa preuve de racine se vérifie, l'identité que la poignée de main
    /// attend (décision 53), et l'ancre réelle (§2.2).
    pub cle: PathBuf,
}

/// De quoi vérifier une attestation Apple App Attest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglageApple {
    /// L'identifiant de l'app : `<équipe>.<bundle>`.
    pub identifiant_app: String,
    /// L'environnement attendu.
    pub environnement: asl_apple::Environnement,
}

/// De quoi vérifier une attestation de clé Android.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglageAndroid {
    /// Les fichiers PEM des racines épinglées (`--android-roots`), un au
    /// moins ; un fichier peut porter plusieurs certificats.
    pub racines: Vec<PathBuf>,
    /// Le nom du paquet de notre app (`--android-app`).
    pub paquet: String,
    /// L'empreinte SHA-256 du certificat de signature de la build
    /// (`--android-signer`), décodée.
    pub signataire: [u8; 32],
}

/// Ce qui empêche de lire les réglages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Faute {
    /// Un drapeau qu'on ne connaît pas.
    Inconnu(String),
    /// Un drapeau sans sa valeur.
    SansValeur(String),
    /// Une valeur qui n'est pas un nombre, ou qui sort des bornes.
    PasUnNombre {
        /// Le drapeau concerné.
        drapeau: String,
        /// Ce qui a été donné.
        donnee: String,
    },
    /// Un réglage obligatoire qui manque.
    Manque(&'static str),
    /// `--attestation` a reçu autre chose que `required`, `optional` ou
    /// `invitation`.
    AttestationInconnue(String),
    /// `--attestation invitation` sans `--operator-key`.
    InvitationSansCle,
    /// `--invitation-ttl 0` : une invitation qui ne vit pas n'invite personne.
    InvitationTtlNul,
    /// `--invitation-ttl` au-delà d'une semaine.
    InvitationTtlTropLong(u64),
    /// `--apple-environment` a reçu autre chose que `production` ou
    /// `development`.
    EnvironnementInconnu(String),
    /// `--apple-app` et `--apple-environment` ne vont pas l'un sans l'autre.
    AppleIncomplet,
    /// `--android-roots`, `--android-app` et `--android-signer` ne vont pas
    /// les uns sans les autres.
    AndroidIncomplet,
    /// `--android-signer` n'est pas une empreinte SHA-256 en hexadécimal.
    SignataireInvalide(String),
    /// `--peer` et `--peer-key` ne vont pas l'un sans l'autre.
    PairIncomplet,
    /// `--peer` n'a pas la forme `hôte:port`.
    PairInvalide(String),
    /// Pas de `--identity-key` : l'annuaire n'aurait aucun certificat à
    /// présenter (décision 58, fin de la transition).
    SansIdentite,
    /// `--forget` a reçu autre chose qu'un identifiant de compte `u-…`.
    CompteInvalide(String),
    /// `--federation <locateur>=<…>` dont l'identité n'est pas un `n-…`.
    AnnuaireInvalide(String),
    /// `--locator` n'a pas la forme `hôte:port`, ou il y en a plus de quatre,
    /// ou il n'y a pas de `--federation` à qui les publier.
    LocateurInvalide(String),
    /// Un drapeau de l'ancienne grammaire, en français, qui a son
    /// équivalent en anglais.
    ///
    /// **ON LE DIT PLUTÔT QUE DE L'ACCEPTER.** Le tolérer ferait deux
    /// grammaires, dont l'une vieillirait en silence dans les unités systemd
    /// et les scripts ; le refuser en nommant la nouvelle rend le passage
    /// immédiat pour qui tombe dessus.
    Ancien {
        /// Le drapeau tel qu'il était.
        ancien: &'static str,
        /// Celui qui l'a remplacé.
        nouveau: &'static str,
    },
    /// Un réglage de la forme d'hier — une chaîne à servir, une autorité à
    /// croire —, **retiré en 0.34.0** avec la fin de la transition
    /// (décision 58).
    ///
    /// **REFUSÉ, ET NON IGNORÉ** : l'ignorer laisserait croire à l'exploitant
    /// qu'une autorité protège encore une voie que seule la clé protège ; le
    /// refuser en disant quoi faire rend le passage immédiat. Aucun banc
    /// déployé ne le passe plus.
    Retire {
        /// Le drapeau retiré.
        drapeau: &'static str,
        /// Ce qu'il faut faire à la place.
        conseil: &'static str,
    },
}

impl core::fmt::Display for Faute {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inconnu(quoi) => write!(sortie, "drapeau inconnu : {quoi}"),
            Self::SansValeur(quoi) => write!(sortie, "{quoi} attend une valeur"),
            Self::AttestationInconnue(quoi) => {
                write!(
                    sortie,
                    "--attestation attend `required`, `optional` ou `invitation`, et non « {quoi} »"
                )
            }
            Self::InvitationSansCle => sortie.write_str(
                "--attestation invitation exige --operator-key : une racine qui exige une \
                 invitation sans pouvoir en émettre est une racine où personne n'entre",
            ),
            Self::InvitationTtlNul => sortie
                .write_str("--invitation-ttl 0 : une invitation qui ne vit pas n'invite personne"),
            Self::InvitationTtlTropLong(quoi) => {
                write!(
                    sortie,
                    "--invitation-ttl {quoi} : une semaine au plus ({INVITATION_TTL_MAX_S} secondes)"
                )
            }
            Self::PasUnNombre { drapeau, donnee } => {
                write!(
                    sortie,
                    "{drapeau} : « {donnee} » n'est pas un nombre valide"
                )
            }
            Self::EnvironnementInconnu(quoi) => write!(
                sortie,
                "--apple-environment attend `production` ou `development`, et non « {quoi} »"
            ),
            Self::AppleIncomplet => sortie.write_str(
                "--apple-app et --apple-environment se donnent ensemble, ou pas du tout",
            ),
            Self::AndroidIncomplet => sortie.write_str(
                "--android-roots, --android-app et --android-signer se donnent ensemble, \
                 ou pas du tout",
            ),
            Self::SignataireInvalide(quoi) => write!(
                sortie,
                "--android-signer attend une empreinte SHA-256, 64 chiffres hexadécimaux, \
                 et non « {quoi} »"
            ),
            Self::PairIncomplet => {
                sortie.write_str("--peer et --peer-key se donnent ensemble, ou pas du tout")
            }
            Self::PairInvalide(quoi) => write!(
                sortie,
                "--peer attend `hôte:port` (une adresse IPv6 entre crochets), et non « {quoi} »"
            ),
            Self::SansIdentite => sortie.write_str(
                "il manque --identity-key : un annuaire ne présente que son certificat \
                 d'identité (décision 58) — `asl-server --new-identity-key \
                 /etc/asl-server/identite.key` en frappe une",
            ),
            Self::CompteInvalide(quoi) => write!(
                sortie,
                "--forget attend l'identifiant d'un compte, `u-` et 26 caractères, et non « {quoi} »"
            ),
            Self::AnnuaireInvalide(quoi) => write!(
                sortie,
                "--federation <locateur>=<n-…> attend l'identifiant d'un annuaire, `n-` et \
                 26 caractères, et non « {quoi} »"
            ),
            Self::LocateurInvalide(quoi) => write!(
                sortie,
                "--locator attend `hôte:port`, quatre au plus, avec --federation — et non « {quoi} »"
            ),
            Self::Manque(quoi) => write!(sortie, "il manque {quoi}"),
            Self::Ancien { ancien, nouveau } => {
                write!(sortie, "{ancien} n'existe plus : {nouveau}")
            }
            Self::Retire { drapeau, conseil } => write!(
                sortie,
                "{drapeau} est retiré depuis 0.34.0 (fin de la transition, décision 58) : {conseil}"
            ),
        }
    }
}

impl std::error::Error for Faute {}

/// Ce que vit une invitation par défaut : vingt-quatre heures
/// (`protocole.md` §2.2).
pub const INVITATION_TTL_DEFAUT_S: u64 = 24 * 60 * 60;

/// Ce qu'une invitation peut vivre au plus : une semaine.
pub const INVITATION_TTL_MAX_S: u64 = 7 * 24 * 60 * 60;

/// Ce qu'on affiche quand on ne sait pas quoi faire.
pub const USAGE: &str = "\
asl-server — an air-service-locator service directory.

  --store        <path>     the store file                       (required)
  --identity-key <path>     this directory's Ed25519 identity key, 32 raw
                            bytes; its identity certificate is ALL it presents
                                                                 (required)
  --port         <number>   the listening port                   (default: 6630)
  --connections  <number>   concurrent connections, at most      (default: 1024)
  --idle         <seconds>  the idle timeout announced to peers  (default: 30)
  --keepalive    <seconds>  the keepalive cadence requested      (default: 10)
  --retention    <days>     the journal retention                (default: 90)
  --attestation  <required|optional|invitation>                  (required)
  --apple-app    <id>       the Apple app identifier             (with the env.)
  --apple-environment <production|development>                   (with the app)
  --android-roots <path>    a PEM file of pinned Android attestation roots;
                            repeatable, one file may hold several certificates
  --android-app  <package>  the Android package name             (with the roots)
  --android-signer <sha256> the hex SHA-256 of the APK signing certificate
  --peer         <host:port> the other root                      (with --peer-key)
  --peer-key     <path>     the other root's public identity key, 32 raw bytes;
                            the peer is trusted by it, and by nothing else
  --operator-key <path>     the operator's public Ed25519 key, 32 raw bytes;
                            its signature opens POST /v1/invitations and
                            POST/DELETE /v1/administrateurs
                            (REQUIRED with `--attestation invitation`)
  --invitation-ttl <seconds> how long an invitation code lives
                            (default: 86400, one day; one week at most)
  --orphans      <days>     erase an account once ALL its devices have been
                            revoked for that many days; 0 = never (default: 30)
  --federation   <host:port>[=<n-…>]
                            a root this LOCAL directory federates to, and the
                            identity to find there; repeat it for each root;
                            without `=<n-…>`, the locator must be in the
                            embedded roots list; without it, this is a root
  --locator      <host:port> where this LOCAL directory is reached, published
                            to the roots each time its lane opens; repeat it
                            (four at most); none withdraws what was published,
                            and the address declared at registration serves
  --push-roots   <path>     the CAs that validate push servers' TLS certs, PEM
                            — typically /etc/ssl/certs/ca-certificates.crt;
                            without it, NO notification is ever sent
  --new-identity-key <path> write a new identity key there (0600), its
                            `<path>.pub` and its identity certificate
                            `<path>.crt`, print the `n-…` it gives, then exit
  --identity-certificate <path>
                            print the identity certificate (PEM) of that
                            identity key, then exit
  --new-operator-key <path> write a new OPERATOR key there (0600) and its
                            `<path>.pub`, print what to put where, then exit
  --invite --directory <host:port>[=<n-…>] --operator-secret <path>
                            ask that RUNNING directory for an invitation code,
                            print it on stdout — once —, then exit
  --add-admin <u-…> --directory <host:port>[=<n-…>] --operator-secret <path>
                            name that account an administrator of the roots on
                            that RUNNING directory, then exit
  --remove-admin <u-…> --directory <host:port>[=<n-…>] --operator-secret <path>
                            remove it, then exit
  --register <code> --directory <host:port>[=<n-…>] --identity-key <path>
                            present this LOCAL directory to a RUNNING root with
                            the registration code the app gave, print the
                            state of its registration, then exit
  --registration-status --directory <host:port>[=<n-…>] --identity-key <path>
                            print the state of this local directory's
                            registration, then exit
  --forget <u-…> --store <path> [--identity-key <path>]
                            erase THAT account offline — the store must not be
                            held by a running directory —, log what was
                            removed, then exit; one account at a time
  --version                 print the version and commit, then exit
  --help                    this

`--attestation` HAS NO DEFAULT, AND THAT IS DELIBERATE. `required` refuses every
device enrollment unless the matching platform is configured — `--apple-app` and
`--apple-environment` together for App Attest, `--android-roots`, `--android-app`
and `--android-signer` together for the Android key attestation —, and
`optional` lets anyone create an account. Neither can be chosen on your behalf.
No third party is ever called: the Android roots are files you pin.

`invitation` is the third posture, for a root that wants no manufacturer in its
loop at all: nobody opens an account without a code the operator issued through
`POST /v1/invitations`, signed by the key of `--operator-key`. The operator's
PRIVATE key never goes on the bench. Both roots must carry the SAME public key:
invitations replicate, and the alias hands out a root at random.

`--new-operator-key` mints that pair, and `--invite` spends it. Unlike
`--forget`, `--invite` talks to a directory that IS RUNNING — it stops nothing,
opens no store, and belongs on the operator's own machine, where the private key
lives. The code it prints is worth ONE account, lives `--invitation-ttl`
(a day by default, a week at most), and is NEVER shown again: the directory
keeps only its fingerprint. It goes on stdout, alone, so that piping it copies
nothing else; how long it lives goes on stderr.

TRUST IS BY KEY, NOT BY NAME (C20: asl works WITHOUT DNS). A directory presents
ONE certificate, SELF-SIGNED by its `--identity-key` and minted at start; a
client accepts it when the key is the one it expects — the peer's `--peer-key`,
a root of the embedded list, the `=<n-…>` of a locator — and the handshake
proves it. Names, dates and authorities are not judged. `--directory`, `--peer`
and `--federation` are locators: a name is allowed, and only says where to go.
`--certificate`, `--key` and every `--…-ca` were removed in 0.34.0, with the
end of the transition (decision 58): they are refused, with what to do instead.

The socket is DUAL-STACK: IPv6 first, IPv4 accepted on the same socket.
The directory REFUSES to start as root — it needs no privilege at all.

`--peer` and `--peer-key` go together; `--new-identity-key` writes `<path>`
(the private key) and `<path>.pub` (the public key, to carry to the other root
as its `--peer-key`).

`--push-roots` turns notifications on: an authorization granted HERE wakes the
grantee's live devices with an EMPTY POST to the UnifiedPush endpoint each one
deposited. It is the only outbound call a root makes besides its peer: the name
is resolved on every send, any non-global address refuses the send, TLS 1.3
only, five seconds, one attempt. Nothing is downloaded: to reach ntfy.sh, point
it at the distribution's CA bundle. Without it, nothing is resolved nor sent,
and `GET /v1/nouvelles` is still served.

`--orphans` only counts REVOCATIONS, never silence: a phone in a drawer is a
living device. Both roots must carry the same value. `--forget` is the human
exception for a key known to be lost — not a moderation tool; run it as the
directory's user, with the daemon stopped.
";

impl Reglages {
    /// Lit les réglages depuis ces arguments, le nom du programme exclu.
    ///
    /// # Errors
    ///
    /// [`Faute`] si un drapeau est inconnu, sans valeur, mal formé, ou si un
    /// réglage obligatoire manque.
    pub fn depuis<I, S>(arguments: I) -> Result<Self, Faute>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut entrepot = None;
        let mut port = PORT_PAR_DEFAUT;
        // Mille vingt-quatre connexions : quelques dizaines de mébioctets de
        // fenêtres de réassemblage. C'est une borne de MÉMOIRE, et elle se règle.
        let mut connexions_max = 1024_usize;
        // Trente secondes, soit trois keepalives de dix manqués — et c'est
        // aussi ce que le chemin tolère : `bancs/nat/README.md` a mesuré 28 s
        // tenus, 30 s perdus, LE MÊME CHIFFRE en IPv4 et en IPv6. La borne
        // n'est donc pas la traduction d'adresses, c'est le pare-feu à état de
        // la box — et quarante-cinq secondes promettaient une tolérance que le
        // réseau ne rend pas.
        //
        // **ELLE DOIT S'ACCORDER AVEC LE BAIL QUE L'ANNUAIRE ACCORDE**
        // (`asl_loop_tokio::h3::BAIL_PAR_DEFAUT`) : celle-ci ferme la CONNEXION,
        // celle-là fait tomber le BAIL, et `protocole.md` §1.2 promet que les
        // deux sont la même chose. Les laisser diverger ouvrirait une fenêtre où
        // un daemon est désannoncé sans être déconnecté, donc sans rien
        // apprendre.
        let mut inactivite_s = 30_u64;
        let mut retention_jours = 90_u64;
        // Dix secondes, mesurées : `bancs/nat/README.md` a trouvé qu'un chemin
        // résidentiel meurt entre 28 et 30 s de silence. À quinze, **un SEUL
        // maintien perdu faisait trente secondes de silence**, c'est-à-dire
        // exactement la borne : sur un lien qui perd un paquet de temps en
        // temps, l'annonce tombait sans que rien n'ait mal tourné. À dix, il en
        // faut deux d'affilée.
        let mut keepalive_s = 10_u64;
        let mut politique = None;
        let mut apple_app: Option<String> = None;
        let mut apple_env: Option<asl_apple::Environnement> = None;
        let mut android_racines: Vec<PathBuf> = Vec::new();
        let mut android_paquet: Option<String> = None;
        let mut android_signataire: Option<[u8; 32]> = None;
        let mut identite = None;
        // Trente jours : `docs/modele.md` §2.1. Zéro pour jamais.
        let mut orphelins_jours = 30_u64;
        let mut pair_adresse: Option<String> = None;
        let mut pair_cle: Option<PathBuf> = None;
        let mut exploitant: Option<PathBuf> = None;
        let mut invitation_ttl_s = INVITATION_TTL_DEFAUT_S;
        let mut racines_de_poussee: Option<PathBuf> = None;
        let mut federation_racines: Vec<CibleFederee> = Vec::new();
        let mut locateurs: Vec<String> = Vec::new();

        let mut arguments = arguments.into_iter();
        while let Some(drapeau) = arguments.next() {
            let drapeau = drapeau.as_ref();
            let mut valeur = || {
                arguments
                    .next()
                    .ok_or_else(|| Faute::SansValeur(drapeau.to_owned()))
            };
            // `valeur` emprunte `arguments` : on la consomme tout de suite,
            // branche par branche, plutôt que de la garder vivante.
            match drapeau {
                "--store" => entrepot = Some(PathBuf::from(valeur()?.as_ref())),
                "--port" => port = nombre(drapeau, valeur()?.as_ref())?,
                "--connections" => connexions_max = nombre(drapeau, valeur()?.as_ref())?,
                "--idle" => inactivite_s = nombre(drapeau, valeur()?.as_ref())?,
                "--keepalive" => keepalive_s = nombre(drapeau, valeur()?.as_ref())?,
                "--retention" => retention_jours = nombre(drapeau, valeur()?.as_ref())?,
                "--attestation" => {
                    let donnee = valeur()?;
                    politique = Some(match donnee.as_ref() {
                        "required" => asl_auth::Politique::AttestationExigee,
                        "optional" => asl_auth::Politique::AttestationFacultative,
                        "invitation" => asl_auth::Politique::Invitation,
                        autre => return Err(Faute::AttestationInconnue(autre.to_owned())),
                    });
                }
                "--apple-app" => apple_app = Some(valeur()?.as_ref().to_owned()),
                "--apple-environment" => {
                    let donnee = valeur()?;
                    apple_env = Some(match donnee.as_ref() {
                        "production" => asl_apple::Environnement::Production,
                        "development" => asl_apple::Environnement::Developpement,
                        autre => return Err(Faute::EnvironnementInconnu(autre.to_owned())),
                    });
                }
                "--android-roots" => android_racines.push(PathBuf::from(valeur()?.as_ref())),
                "--android-app" => android_paquet = Some(valeur()?.as_ref().to_owned()),
                "--android-signer" => android_signataire = Some(empreinte(valeur()?.as_ref())?),
                "--identity-key" => identite = Some(PathBuf::from(valeur()?.as_ref())),
                "--orphans" => orphelins_jours = nombre(drapeau, valeur()?.as_ref())?,
                "--peer" => pair_adresse = Some(adresse_de_pair(valeur()?.as_ref())?),
                "--peer-key" => pair_cle = Some(PathBuf::from(valeur()?.as_ref())),
                "--operator-key" => exploitant = Some(PathBuf::from(valeur()?.as_ref())),
                "--invitation-ttl" => invitation_ttl_s = nombre(drapeau, valeur()?.as_ref())?,
                "--push-roots" => racines_de_poussee = Some(PathBuf::from(valeur()?.as_ref())),
                "--federation" => federation_racines.push(cible_federee(valeur()?.as_ref())?),
                "--locator" => locateurs.push(locateur(valeur()?.as_ref(), locateurs.len())?),
                autre => return Err(refus(autre)),
            }
        }

        Ok(Self {
            entrepot: entrepot.ok_or(Faute::Manque("--store"))?,
            // **L'IDENTITÉ EST TOUT CE QUE L'ANNUAIRE PRÉSENTE** (décision 58,
            // fin de la transition) : sans elle, rien à montrer à la poignée
            // de main.
            identite: identite.ok_or(Faute::SansIdentite)?,
            port,
            connexions_max,
            inactivite_s,
            keepalive_s,
            retention_jours,
            politique: politique.ok_or(Faute::Manque("--attestation"))?,
            // **LES DEUX VONT ENSEMBLE, OU PAS DU TOUT.** Une app sans
            // environnement ne dit pas où l'attester ; un environnement sans app
            // ne dit pas quoi comparer au `rpIdHash`.
            apple: match (apple_app, apple_env) {
                (Some(identifiant_app), Some(environnement)) => Some(ReglageApple {
                    identifiant_app,
                    environnement,
                }),
                (None, None) => None,
                _ => return Err(Faute::AppleIncomplet),
            },
            // **LES TROIS VONT ENSEMBLE, OU PAS DU TOUT.** Une racine sans app
            // ne dit pas quelle app doit tenir la clé ; une app sans racine
            // ne remonte à rien ; et sans l'empreinte, n'importe quelle build
            // du même nom de paquet passerait.
            android: match (
                android_racines.is_empty(),
                android_paquet,
                android_signataire,
            ) {
                (false, Some(paquet), Some(signataire)) => Some(ReglageAndroid {
                    racines: android_racines,
                    paquet,
                    signataire,
                }),
                (true, None, None) => None,
                _ => return Err(Faute::AndroidIncomplet),
            },
            // **ILS VONT ENSEMBLE** (`replication.md` §8) : une adresse seule
            // n'est pas une racine, une clé seule ne se joint pas.
            pair: match (pair_adresse, pair_cle) {
                (Some(adresse), Some(cle)) => Some(ReglagePair { adresse, cle }),
                (None, None) => None,
                _ => return Err(Faute::PairIncomplet),
            },
            federation: if federation_racines.is_empty() {
                match locateurs.first() {
                    // Une racine ne publie pas ses locateurs ainsi : les
                    // siens sont embarqués (décision 56).
                    Some(premier) => return Err(Faute::LocateurInvalide(premier.clone())),
                    None => None,
                }
            } else {
                Some(ReglageFederation {
                    racines: federation_racines,
                    locateurs,
                })
            },
            orphelins_jours,
            // **LA POSTURE `invitation` EXIGE LA CLÉ** (`protocole.md` §2.2) :
            // sans elle, aucun code ne peut être émis, et une racine où
            // personne n'entre n'est pas une racine — c'est la règle
            // d'`--attestation` sans valeur, appliquée un cran plus loin. Un
            // service voué à échouer ne démarre pas.
            exploitant: match (politique, exploitant) {
                (Some(asl_auth::Politique::Invitation), None) => {
                    return Err(Faute::InvitationSansCle);
                }
                (_, donnee) => donnee,
            },
            // **UNE SEMAINE AU PLUS**, et le refus est net : un plafond qu'on
            // dépasserait en silence ne serait pas un plafond.
            invitation_ttl_s: match invitation_ttl_s {
                0 => return Err(Faute::InvitationTtlNul),
                trop if trop > INVITATION_TTL_MAX_S => {
                    return Err(Faute::InvitationTtlTropLong(trop));
                }
                bon => bon,
            },
            racines_de_poussee,
        })
    }

    /// Le délai de la règle des orphelins en millisecondes, comme la boucle
    /// le veut — `None` pour jamais.
    #[must_use]
    pub const fn orphelins_ms(&self) -> Option<u64> {
        if self.orphelins_jours == 0 {
            None
        } else {
            Some(self.orphelins_jours.saturating_mul(24 * 60 * 60 * 1_000))
        }
    }

    /// Le geste `--forget`, s'il est demandé dans ces arguments.
    ///
    /// **Lu à part des réglages**, comme `--new-identity-key` : c'est un geste,
    /// pas un service, et il ne demande ni certificat, ni clé TLS, ni
    /// posture — seulement l'entrepôt, et l'identité si on l'a. Rend `None`
    /// sans `--forget`.
    ///
    /// # Errors
    ///
    /// [`Faute::SansValeur`] sans identifiant, [`Faute::CompteInvalide`] si ce
    /// n'en est pas un, [`Faute::Manque`] sans `--store`.
    pub fn geste_d_oubli<S: AsRef<str>>(arguments: &[S]) -> Result<Option<Oubli>, Faute> {
        let Some(rang) = arguments
            .iter()
            .position(|quoi| quoi.as_ref() == "--forget")
        else {
            return Ok(None);
        };
        let donnee = arguments
            .get(rang.saturating_add(1))
            .map(AsRef::as_ref)
            .ok_or_else(|| Faute::SansValeur("--forget".to_owned()))?;
        let compte = asl_id::Identifiant::analyser(donnee)
            .ok()
            .filter(|quoi| quoi.genre() == asl_id::Genre::Utilisateur)
            .ok_or_else(|| Faute::CompteInvalide(donnee.to_owned()))?;
        let valeur_de = |drapeau: &str| {
            arguments
                .iter()
                .position(|quoi| quoi.as_ref() == drapeau)
                .map(|rang| {
                    arguments
                        .get(rang.saturating_add(1))
                        .map(|quoi| PathBuf::from(quoi.as_ref()))
                        .ok_or_else(|| Faute::SansValeur(drapeau.to_owned()))
                })
                .transpose()
        };
        let entrepot = valeur_de("--store")?.ok_or(Faute::Manque("--store"))?;
        let identite = valeur_de("--identity-key")?;
        Ok(Some(Oubli {
            compte,
            entrepot,
            identite,
        }))
    }

    /// Le geste `--invite`, s'il est demandé dans ces arguments.
    ///
    /// **Lu à part des réglages**, comme `--forget` et `--new-identity-key` :
    /// c'est un geste, pas un service. Il ne demande ni entrepôt, ni
    /// posture — seulement où joindre l'annuaire, qui l'on doit y trouver, et
    /// la clé qui signe. Rend `None` sans `--invite`.
    ///
    /// # Errors
    ///
    /// [`Faute::SansValeur`] si un drapeau n'a pas sa valeur,
    /// [`Faute::Manque`] si `--directory` ou `--operator-secret` manque,
    /// [`Faute::Retire`] pour `--ca`.
    pub fn geste_d_invitation<S: AsRef<str>>(arguments: &[S]) -> Result<Option<Invite>, Faute> {
        if !arguments.iter().any(|quoi| quoi.as_ref() == "--invite") {
            return Ok(None);
        }
        sans_autorite(arguments)?;
        let valeur_de = |drapeau: &str| {
            arguments
                .iter()
                .position(|quoi| quoi.as_ref() == drapeau)
                .map(|rang| {
                    arguments
                        .get(rang.saturating_add(1))
                        .map(|quoi| quoi.as_ref().to_owned())
                        .ok_or_else(|| Faute::SansValeur(drapeau.to_owned()))
                })
                .transpose()
        };
        let annuaire = valeur_de("--directory")?.ok_or(Faute::Manque("--directory"))?;
        let secrete = valeur_de("--operator-secret")?.ok_or(Faute::Manque("--operator-secret"))?;
        Ok(Some(Invite {
            annuaire,
            secrete: PathBuf::from(secrete),
        }))
    }

    /// Le geste `--add-admin` ou `--remove-admin`, s'il est demandé dans ces
    /// arguments — lu à part des réglages, comme `--invite`, dont il reprend
    /// les trois chemins.
    ///
    /// # Errors
    ///
    /// [`Faute::SansValeur`] si un drapeau n'a pas sa valeur,
    /// [`Faute::CompteInvalide`] si ce n'est pas un `u-…`, [`Faute::Manque`]
    /// si `--directory` ou `--operator-secret` manque, [`Faute::Retire`] pour
    /// `--ca`.
    pub fn geste_d_administration<S: AsRef<str>>(
        arguments: &[S],
    ) -> Result<Option<Administration>, Faute> {
        let trouve = ["--add-admin", "--remove-admin"]
            .into_iter()
            .find_map(|drapeau| {
                arguments
                    .iter()
                    .position(|quoi| quoi.as_ref() == drapeau)
                    .map(|rang| (drapeau, rang))
            });
        let Some((drapeau, rang)) = trouve else {
            return Ok(None);
        };
        sans_autorite(arguments)?;
        let donnee = arguments
            .get(rang.saturating_add(1))
            .map(AsRef::as_ref)
            .ok_or_else(|| Faute::SansValeur(drapeau.to_owned()))?;
        let compte = asl_id::Identifiant::analyser(donnee)
            .ok()
            .filter(|quoi| quoi.genre() == asl_id::Genre::Utilisateur)
            .ok_or_else(|| Faute::CompteInvalide(donnee.to_owned()))?;
        let valeur_de = |nom: &str| {
            arguments
                .iter()
                .position(|quoi| quoi.as_ref() == nom)
                .map(|place| {
                    arguments
                        .get(place.saturating_add(1))
                        .map(|quoi| quoi.as_ref().to_owned())
                        .ok_or_else(|| Faute::SansValeur(nom.to_owned()))
                })
                .transpose()
        };
        let annuaire = valeur_de("--directory")?.ok_or(Faute::Manque("--directory"))?;
        let secrete = valeur_de("--operator-secret")?.ok_or(Faute::Manque("--operator-secret"))?;
        Ok(Some(Administration {
            joindre: Invite {
                annuaire,
                secrete: PathBuf::from(secrete),
            },
            compte,
            nomme: drapeau == "--add-admin",
        }))
    }

    /// Le geste `--register` ou `--registration-status`, s'il est demandé
    /// dans ces arguments — lu à part des réglages, comme `--invite`.
    ///
    /// # Errors
    ///
    /// [`Faute::SansValeur`] si un drapeau n'a pas sa valeur,
    /// [`Faute::Manque`] si `--directory` ou `--identity-key` manque,
    /// [`Faute::Retire`] pour `--ca`.
    pub fn geste_d_inscription<S: AsRef<str>>(
        arguments: &[S],
    ) -> Result<Option<Inscription>, Faute> {
        let present = |drapeau: &str| arguments.iter().any(|quoi| quoi.as_ref() == drapeau);
        if !present("--register") && !present("--registration-status") {
            return Ok(None);
        }
        sans_autorite(arguments)?;
        let valeur_de = |nom: &str| {
            arguments
                .iter()
                .position(|quoi| quoi.as_ref() == nom)
                .map(|place| {
                    arguments
                        .get(place.saturating_add(1))
                        .map(|quoi| quoi.as_ref().to_owned())
                        .ok_or_else(|| Faute::SansValeur(nom.to_owned()))
                })
                .transpose()
        };
        let code = valeur_de("--register")?;
        let racine = valeur_de("--directory")?.ok_or(Faute::Manque("--directory"))?;
        let identite = valeur_de("--identity-key")?.ok_or(Faute::Manque("--identity-key"))?;
        Ok(Some(Inscription {
            racine,
            identite: PathBuf::from(identite),
            code,
        }))
    }

    /// L'inactivité en microsecondes, comme la boucle la veut.
    #[must_use]
    pub const fn inactivite_us(&self) -> u64 {
        self.inactivite_s.saturating_mul(1_000_000)
    }

    /// Le bail qu'on accordera aux annonces.
    ///
    /// # LES DEUX INACTIVITÉS NE PEUVENT PLUS DIVERGER
    ///
    /// Il y en a deux dans ce produit : `--idle` ferme la CONNEXION, et le
    /// bail fait tomber l'ANNONCE. `protocole.md` §1.2 promet que les deux sont
    /// la même chose — « la connexion EST le bail ». Les laisser se régler
    /// séparément ouvrirait une fenêtre où un daemon est désannoncé sans être
    /// déconnecté, donc sans rien apprendre.
    ///
    /// **Ici, le bail est DÉRIVÉ de l'inactivité**, et non posé à côté d'elle.
    ///
    /// # Erreurs
    ///
    /// [`asl_proto::Erreur`] si la cadence est nulle, trop longue, ou si
    /// l'inactivité vaut moins de deux cadences — auquel cas la première perte
    /// de paquet tuerait un daemon parfaitement sain.
    pub fn bail(&self) -> Result<asl_proto::Bail, asl_proto::Erreur> {
        let borne = |secondes: u64| u16::try_from(secondes).unwrap_or(u16::MAX);
        asl_proto::Bail::nouveau(borne(self.keepalive_s), borne(self.inactivite_s))
    }

    /// La rétention en millisecondes, comme le journal la compte.
    #[must_use]
    pub const fn retention_ms(&self) -> u64 {
        self.retention_jours.saturating_mul(24 * 60 * 60 * 1_000)
    }
}

/// Les drapeaux d'avant 0.4.0, en français, et ce qui les a remplacés.
///
/// La grammaire des outils est passée en anglais (0.4.0) ; les messages
/// d'exécution, eux, restent en français. Une unité systemd ou un script
/// écrit pour l'ancienne grammaire tombe ici, et apprend le nouveau nom.
fn ancien(drapeau: &str) -> Option<(&'static str, &'static str)> {
    const TABLE: [(&str, &str); 5] = [
        ("--entrepot", "--store"),
        ("--connexions", "--connections"),
        ("--inactivite", "--idle"),
        ("--apple-environnement", "--apple-environment"),
        ("--aide", "--help"),
    ];
    TABLE.iter().copied().find(|(vieux, _)| *vieux == drapeau)
}

/// Les réglages de la forme d'hier, retirés en 0.34.0 (décision 58), et ce
/// qu'il faut faire à la place. `--certificat` et `--cle`, leurs noms
/// d'avant 0.4.0, y sont aussi : ils mèneraient à un drapeau qui n'existe
/// plus.
fn retire(drapeau: &str) -> Option<(&'static str, &'static str)> {
    const PRESENTER: &str = "l'annuaire ne présente plus que son certificat d'identité, \
         frappé depuis --identity-key — retirez --certificate et --key (et ASL_TLS)";
    const TABLE: [(&str, &str); 7] = [
        ("--certificate", PRESENTER),
        ("--key", PRESENTER),
        ("--certificat", PRESENTER),
        ("--cle", PRESENTER),
        (
            "--peer-ca",
            "le pair est cru par sa clé, --peer-key, et par rien d'autre — retirez --peer-ca",
        ),
        (
            "--federation-ca",
            "chaque racine est crue par son identité — --federation <locateur>=<n-…>, ou un \
             locateur de la liste embarquée — ; retirez --federation-ca",
        ),
        (
            "--ca",
            "l'annuaire est cru par son identité — --directory <locateur>=<n-…>, ou un \
             locateur de la liste embarquée — ; retirez --ca",
        ),
    ];
    TABLE.iter().copied().find(|(vieux, _)| *vieux == drapeau)
}

/// Ce qu'on dit d'un drapeau qu'on ne lit pas : retiré, renommé, ou inconnu.
fn refus(drapeau: &str) -> Faute {
    if let Some((drapeau, conseil)) = retire(drapeau) {
        return Faute::Retire { drapeau, conseil };
    }
    match ancien(drapeau) {
        Some((ancien, nouveau)) => Faute::Ancien { ancien, nouveau },
        None => Faute::Inconnu(drapeau.to_owned()),
    }
}

/// Un geste d'exploitant ne lit que ses drapeaux : un `--ca` d'hier y
/// passerait en silence. **On le refuse**, comme le service le refuse.
fn sans_autorite<S: AsRef<str>>(arguments: &[S]) -> Result<(), Faute> {
    match arguments.iter().find(|quoi| quoi.as_ref() == "--ca") {
        Some(quoi) => Err(refus(quoi.as_ref())),
        None => Ok(()),
    }
}

/// Lit `hôte:port`, ou dit ce qui n'en a pas la forme.
///
/// **Validée, pas résolue** : un nom reste un nom, une adresse une adresse. Une
/// adresse IPv6 se donne entre crochets, comme partout où un port la suit —
/// `2001:db8::1:6630` ne dit pas où l'adresse finit. Le port est un nombre de
/// un à 65535 : zéro n'est pas un port qu'on joint.
fn adresse_de_pair(donnee: &str) -> Result<String, Faute> {
    let invalide = || Faute::PairInvalide(donnee.to_owned());
    let (hote, port) = donnee.rsplit_once(':').ok_or_else(invalide)?;
    let port: u16 = port.parse().map_err(|_| invalide())?;
    if port == 0 || hote.is_empty() {
        return Err(invalide());
    }
    if let Some(entre) = hote.strip_prefix('[') {
        let adresse = entre.strip_suffix(']').ok_or_else(invalide)?;
        adresse
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| invalide())?;
    } else if hote.contains(':') {
        return Err(invalide());
    }
    Ok(donnee.to_owned())
}

/// Lit un `--locator` : la forme d'une adresse déclarée
/// (`asl_registre::Adresse`), et quatre au plus — `deja` sont déjà lus.
fn locateur(donnee: &str, deja: usize) -> Result<String, Faute> {
    if deja >= asl_registre::LOCATEURS_MAX || asl_registre::Adresse::nouvelle(donnee).is_err() {
        return Err(Faute::LocateurInvalide(donnee.to_owned()));
    }
    Ok(donnee.to_owned())
}

/// Lit `<locateur>` ou `<locateur>=<n-…>` — une racine vers laquelle
/// fédérer, et qui l'on doit y trouver (décision 58).
fn cible_federee(donnee: &str) -> Result<CibleFederee, Faute> {
    match donnee.split_once('=') {
        Some((adresse, identite)) => Ok(CibleFederee {
            adresse: adresse_de_pair(adresse)?,
            identite: Some(
                asl_id::Identifiant::analyser(identite)
                    .ok()
                    .filter(|quoi| quoi.genre() == asl_id::Genre::Annuaire)
                    .ok_or_else(|| Faute::AnnuaireInvalide(identite.to_owned()))?,
            ),
        }),
        None => Ok(CibleFederee {
            adresse: adresse_de_pair(donnee)?,
            identite: None,
        }),
    }
}

/// Lit une empreinte SHA-256 en hexadécimal — 64 chiffres, comme `apksigner
/// verify --print-certs` l'imprime, avec ou sans deux-points entre les octets.
fn empreinte(donnee: &str) -> Result<[u8; 32], Faute> {
    let invalide = || Faute::SignataireInvalide(donnee.to_owned());
    let propre: String = donnee.chars().filter(|c| *c != ':').collect();
    if propre.len() != 64 {
        return Err(invalide());
    }
    let mut sortie = [0_u8; 32];
    for (place, paire) in sortie.iter_mut().zip(propre.as_bytes().chunks(2)) {
        let texte = core::str::from_utf8(paire).map_err(|_| invalide())?;
        *place = u8::from_str_radix(texte, 16).map_err(|_| invalide())?;
    }
    Ok(sortie)
}

/// Lit un nombre, ou dit lequel n'en était pas un.
fn nombre<T: core::str::FromStr>(drapeau: &str, donnee: &str) -> Result<T, Faute> {
    donnee.parse().map_err(|_| Faute::PasUnNombre {
        drapeau: drapeau.to_owned(),
        donnee: donnee.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Administration, CibleFederee, Faute, Invite, Oubli, ReglageAndroid, ReglageApple,
        ReglageFederation, ReglagePair, Reglages,
    };

    /// Les trois réglages obligatoires, et rien d'autre.
    fn minimum() -> Vec<String> {
        [
            "--store",
            "/a",
            "--identity-key",
            "/id",
            "--attestation",
            "optional",
        ]
        .iter()
        .map(|quoi| (*quoi).to_owned())
        .collect()
    }

    fn avec(ajouts: &[&str]) -> Vec<String> {
        let mut args = minimum();
        args.extend(ajouts.iter().map(|quoi| (*quoi).to_owned()));
        args
    }

    #[test]
    fn sans_reglage_apple_il_n_y_en_a_pas() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.apple, None);
    }

    #[test]
    fn les_deux_reglages_apple_forment_une_configuration() {
        let lus = Reglages::depuis(avec(&[
            "--apple-app",
            "ABCDE12345.ch.narro.essai",
            "--apple-environment",
            "production",
        ]))
        .expect("une configuration complète");
        assert_eq!(
            lus.apple,
            Some(ReglageApple {
                identifiant_app: "ABCDE12345.ch.narro.essai".to_owned(),
                environnement: asl_apple::Environnement::Production,
            })
        );

        // Et `development` aussi.
        let dev = Reglages::depuis(avec(&[
            "--apple-app",
            "ABCDE12345.ch.narro.essai",
            "--apple-environment",
            "development",
        ]))
        .expect("développement est un environnement");
        assert_eq!(
            dev.apple.map(|a| a.environnement),
            Some(asl_apple::Environnement::Developpement)
        );
    }

    #[test]
    fn une_app_sans_environnement_ou_l_inverse_est_refusee() {
        assert_eq!(
            Reglages::depuis(avec(&["--apple-app", "X.y"])).map(|_| ()),
            Err(Faute::AppleIncomplet)
        );
        assert_eq!(
            Reglages::depuis(avec(&["--apple-environment", "production"])).map(|_| ()),
            Err(Faute::AppleIncomplet)
        );
    }

    #[test]
    fn un_environnement_inconnu_est_refuse() {
        let faute = Reglages::depuis(avec(&[
            "--apple-app",
            "X.y",
            "--apple-environment",
            "bac-a-sable",
        ]))
        .map(|_| ());
        assert_eq!(
            faute,
            Err(Faute::EnvironnementInconnu("bac-a-sable".to_owned()))
        );
        // Et la faute a sa phrase.
        assert!(
            !Faute::EnvironnementInconnu("x".to_owned())
                .to_string()
                .is_empty()
        );
        assert!(!Faute::AppleIncomplet.to_string().is_empty());
    }

    #[test]
    fn sans_push_roots_rien_ne_part_et_avec_le_fichier_est_retenu() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.racines_de_poussee, None);
        let lus = Reglages::depuis(avec(&[
            "--push-roots",
            "/etc/ssl/certs/ca-certificates.crt",
        ]))
        .expect("un fichier de racines");
        assert_eq!(
            lus.racines_de_poussee,
            Some(std::path::PathBuf::from(
                "/etc/ssl/certs/ca-certificates.crt"
            ))
        );
        assert_eq!(
            Reglages::depuis(avec(&["--push-roots"])).map(|_| ()),
            Err(Faute::SansValeur("--push-roots".to_owned()))
        );
    }

    #[test]
    fn sans_reglage_android_il_n_y_en_a_pas() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.android, None);
    }

    #[test]
    fn les_trois_reglages_android_forment_une_configuration() {
        let lus = Reglages::depuis(avec(&[
            "--android-roots",
            "/racines/google.pem",
            "--android-app",
            "org.airdesktop.servicelocator",
            "--android-signer",
            "5ea316f1b50f2ce54b8225aba85ff5cc8238a710b8fae44b4f3a195aadeb5f68",
            "--android-roots",
            "/racines/grapheneos.pem",
        ]))
        .expect("une configuration complète");
        let mut signataire = [0_u8; 32];
        signataire[0] = 0x5e;
        signataire[1] = 0xa3;
        signataire[31] = 0x68;
        let android = lus.android.expect("Android est réglé");
        assert_eq!(
            android.racines,
            vec![
                std::path::PathBuf::from("/racines/google.pem"),
                std::path::PathBuf::from("/racines/grapheneos.pem")
            ]
        );
        assert_eq!(android.paquet, "org.airdesktop.servicelocator");
        assert_eq!(android.signataire[..2], signataire[..2]);
        assert_eq!(android.signataire[31], signataire[31]);
        // L'empreinte s'accepte aussi comme `apksigner` l'imprime, avec des
        // deux-points, et en majuscules.
        let deux_points = Reglages::depuis(avec(&[
            "--android-roots",
            "/r.pem",
            "--android-app",
            "a.b",
            "--android-signer",
            "5E:A3:16:F1:B5:0F:2C:E5:4B:82:25:AB:A8:5F:F5:CC:82:38:A7:10:B8:FA:E4:4B:4F:3A:19:5A:AD:EB:5F:68",
        ]))
        .expect("les deux-points sont ignorés");
        assert_eq!(
            deux_points.android.map(|a| a.signataire),
            Some(android.signataire)
        );
        assert_eq!(
            android,
            ReglageAndroid {
                racines: android.racines.clone(),
                paquet: android.paquet.clone(),
                signataire: android.signataire,
            }
        );
    }

    #[test]
    fn un_reglage_android_sans_les_deux_autres_est_refuse() {
        for incomplet in [
            &["--android-roots", "/r.pem"][..],
            &["--android-app", "a.b"][..],
            &["--android-signer", &"00".repeat(32)][..],
            &["--android-roots", "/r.pem", "--android-app", "a.b"][..],
            &["--android-app", "a.b", "--android-signer", &"00".repeat(32)][..],
        ] {
            assert_eq!(
                Reglages::depuis(avec(incomplet)).map(|_| ()),
                Err(Faute::AndroidIncomplet),
                "{incomplet:?}"
            );
        }
        assert!(!Faute::AndroidIncomplet.to_string().is_empty());
    }

    #[test]
    fn une_empreinte_de_signataire_mal_formee_est_refusee() {
        for mauvaise in [
            "",
            "5ea3",
            &"0".repeat(63),
            &"zz".repeat(32),
            &"é".repeat(64),
        ] {
            assert_eq!(
                Reglages::depuis(avec(&[
                    "--android-roots",
                    "/r.pem",
                    "--android-app",
                    "a.b",
                    "--android-signer",
                    mauvaise,
                ]))
                .map(|_| ()),
                Err(Faute::SignataireInvalide(mauvaise.to_owned())),
                "« {mauvaise} »"
            );
        }
        assert!(
            Faute::SignataireInvalide("x".to_owned())
                .to_string()
                .contains("SHA-256")
        );
    }

    #[test]
    fn l_attestation_n_a_pas_de_defaut() {
        // **AUCUNE DES DEUX POSTURES NE PEUT ÊTRE CHOISIE À LA PLACE DE
        // L'EXPLOITANT** : `required` livre un annuaire qui ne crée aucun compte,
        // `optional` livre en silence la posture faible.
        let sans: Vec<String> = ["--store", "/a", "--identity-key", "/id"]
            .iter()
            .map(|quoi| (*quoi).to_owned())
            .collect();
        assert_eq!(
            Reglages::depuis(sans).map(|_| ()),
            Err(Faute::Manque("--attestation"))
        );
    }

    #[test]
    fn les_deux_postures_se_lisent_et_les_autres_mots_sont_refuses() {
        for (mot, attendue) in [
            ("required", asl_auth::Politique::AttestationExigee),
            ("optional", asl_auth::Politique::AttestationFacultative),
        ] {
            let mut arguments = minimum();
            arguments.pop();
            arguments.push(mot.to_owned());
            let lus = Reglages::depuis(arguments).expect("une posture connue");
            assert_eq!(lus.politique, attendue, "{mot}");
        }

        let mut arguments = minimum();
        arguments.pop();
        arguments.push("peut-etre".to_owned());
        assert_eq!(
            Reglages::depuis(arguments).map(|_| ()),
            Err(Faute::AttestationInconnue("peut-etre".to_owned()))
        );
        // Et la faute se dit à l'humain qui l'a commise.
        assert!(
            Faute::AttestationInconnue("peut-etre".to_owned())
                .to_string()
                .contains("optional")
        );
    }

    #[test]
    fn le_minimum_suffit_et_les_defauts_sont_ceux_annonces() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.port, asl_proto::PORT_PAR_DEFAUT);
        assert_eq!(lus.connexions_max, 1024);
        assert_eq!(lus.inactivite_s, 30);
        assert_eq!(lus.keepalive_s, 10);
        let bail = lus.bail().expect("dix et trente forment un bail");
        assert_eq!(bail.keepalive_secondes(), 10);
        assert_eq!(bail.inactivite_secondes(), 30);
        assert_eq!(lus.retention_jours, 90);
    }

    #[test]
    fn chacun_des_obligatoires_manque_avec_son_nom() {
        for (retire, attendu) in [
            (0_usize, Faute::Manque("--store")),
            (2, Faute::SansIdentite),
            (4, Faute::Manque("--attestation")),
        ] {
            let mut sans = minimum();
            sans.drain(retire..retire + 2);
            assert_eq!(Reglages::depuis(sans), Err(attendu.clone()), "{attendu}");
        }
        // **L'IDENTITÉ EST TOUT CE QUE L'ANNUAIRE PRÉSENTE** (décision 58) :
        // sans elle, la faute dit comment en frapper une.
        assert!(
            Faute::SansIdentite
                .to_string()
                .contains("--new-identity-key")
        );
    }

    #[test]
    fn la_forme_d_hier_est_refusee_avec_ce_qu_il_faut_faire() {
        // **FIN DE LA TRANSITION** (0.34.0, décision 58) : ni chaîne à servir,
        // ni autorité à croire. Chaque drapeau retiré est REFUSÉ — pas ignoré
        // — et la faute dit quoi faire à la place.
        for (drapeau, conseil) in [
            ("--certificate", "--identity-key"),
            ("--key", "--identity-key"),
            ("--certificat", "--identity-key"),
            ("--cle", "--identity-key"),
            ("--peer-ca", "--peer-key"),
            ("--federation-ca", "<n-…>"),
            ("--ca", "--directory"),
        ] {
            let faute = Reglages::depuis(avec(&[drapeau, "/x"])).expect_err("retiré");
            assert!(
                matches!(faute, Faute::Retire { drapeau: lu, .. } if lu == drapeau),
                "{faute:?}"
            );
            let dit = faute.to_string();
            assert!(
                dit.contains(drapeau) && dit.contains(conseil) && dit.contains("0.34.0"),
                "{dit}"
            );
        }
    }

    #[test]
    fn un_drapeau_inconnu_est_nomme() {
        let mut avec = minimum();
        avec.push("--jesaispas".to_owned());
        assert_eq!(
            Reglages::depuis(avec),
            Err(Faute::Inconnu("--jesaispas".to_owned()))
        );
    }

    #[test]
    fn un_drapeau_de_l_ancienne_grammaire_dit_le_nouveau() {
        // **L'ANCIEN NOM N'EST PAS ACCEPTÉ, IL EST TRADUIT.** Une unité systemd
        // écrite avant 0.4.0 échoue avec le nom à mettre à la place.
        for (vieux, neuf) in [
            ("--entrepot", "--store"),
            ("--connexions", "--connections"),
            ("--inactivite", "--idle"),
            ("--apple-environnement", "--apple-environment"),
            ("--aide", "--help"),
        ] {
            let mut avec = minimum();
            avec.push(vieux.to_owned());
            let faute = Reglages::depuis(avec).expect_err("l'ancien nom est refusé");
            assert_eq!(
                faute,
                Faute::Ancien {
                    ancien: vieux,
                    nouveau: neuf,
                }
            );
            let dit = faute.to_string();
            assert!(dit.contains(vieux) && dit.contains(neuf), "{dit}");
        }
    }

    #[test]
    fn un_drapeau_sans_sa_valeur_est_nomme() {
        let mut avec = minimum();
        avec.push("--port".to_owned());
        assert_eq!(
            Reglages::depuis(avec),
            Err(Faute::SansValeur("--port".to_owned()))
        );
    }

    #[test]
    fn une_valeur_qui_n_est_pas_un_nombre_dit_laquelle() {
        let mut avec = minimum();
        avec.extend(["--port".to_owned(), "six-mille".to_owned()]);
        assert_eq!(
            Reglages::depuis(avec),
            Err(Faute::PasUnNombre {
                drapeau: "--port".to_owned(),
                donnee: "six-mille".to_owned(),
            })
        );
    }

    #[test]
    fn un_port_hors_bornes_est_refuse() {
        // **`65536` N'EST PAS UN PORT**, et le refus vient du type : `u16` ne le
        // contient pas. Sans lui, la valeur serait tronquée à zéro.
        let mut avec = minimum();
        avec.extend(["--port".to_owned(), "65536".to_owned()]);
        assert!(matches!(
            Reglages::depuis(avec),
            Err(Faute::PasUnNombre { .. })
        ));
    }

    #[test]
    fn les_conversions_de_temps_sont_celles_qu_on_croit() {
        let mut avec = minimum();
        avec.extend([
            "--idle".to_owned(),
            "45".to_owned(),
            "--retention".to_owned(),
            "90".to_owned(),
        ]);
        let lus = Reglages::depuis(avec).expect("lisible");
        assert_eq!(lus.inactivite_us(), 45_000_000);
        assert_eq!(lus.retention_ms(), 90 * 24 * 60 * 60 * 1_000);
    }

    #[test]
    fn des_valeurs_absurdes_ne_debordent_pas() {
        let mut avec = minimum();
        avec.extend([
            "--idle".to_owned(),
            u64::MAX.to_string(),
            "--retention".to_owned(),
            u64::MAX.to_string(),
        ]);
        let lus = Reglages::depuis(avec).expect("lisible");
        assert_eq!(lus.inactivite_us(), u64::MAX, "la saturation, pas le tour");
        assert_eq!(lus.retention_ms(), u64::MAX);
    }

    #[test]
    fn sans_pair_la_racine_tourne_seule_sous_son_identite() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.identite, std::path::PathBuf::from("/id"));
        assert_eq!(lus.pair, None);
        // **LA DERNIÈRE L'EMPORTE** : l'unité systemd pose la clé en ligne
        // fixe, et un `$ASL_REPLICATION` d'avant 0.34.0 la redonne.
        let redite = Reglages::depuis(avec(&["--identity-key", "/autre"])).expect("redite");
        assert_eq!(redite.identite, std::path::PathBuf::from("/autre"));
    }

    #[test]
    fn les_reglages_de_la_voie_vont_ensemble() {
        // **`replication.md` §8** : `--peer` et `--peer-key` se donnent
        // ensemble — la clé du pair est l'identité qu'on attend de lui.
        let lus = Reglages::depuis(avec(&[
            "--peer",
            "argon.air-desktop.org:6630",
            "--peer-key",
            "/argon.pub",
        ]))
        .expect("les deux");
        assert_eq!(
            lus.pair,
            Some(ReglagePair {
                adresse: "argon.air-desktop.org:6630".to_owned(),
                cle: std::path::PathBuf::from("/argon.pub"),
            })
        );
        assert_eq!(
            Reglages::depuis(avec(&["--peer", "argon:6630"])).map(|_| ()),
            Err(Faute::PairIncomplet)
        );
        assert_eq!(
            Reglages::depuis(avec(&["--peer-key", "/argon.pub"])).map(|_| ()),
            Err(Faute::PairIncomplet)
        );
        assert!(!Faute::PairIncomplet.to_string().is_empty());
    }

    #[test]
    fn un_annuaire_local_federe_vers_ses_racines_par_leur_identite() {
        assert_eq!(
            Reglages::depuis(minimum()).map(|lus| lus.federation),
            Ok(None)
        );
        let lus = Reglages::depuis(avec(&[
            "--federation",
            "nitrogen.air-desktop.org:6630",
            "--federation",
            "[2001:41d0:20a:900::1d32]:6630",
        ]))
        .map(|lus| lus.federation);
        assert_eq!(
            lus,
            Ok(Some(ReglageFederation {
                racines: vec![
                    CibleFederee {
                        adresse: "nitrogen.air-desktop.org:6630".to_owned(),
                        identite: None,
                    },
                    CibleFederee {
                        adresse: "[2001:41d0:20a:900::1d32]:6630".to_owned(),
                        identite: None,
                    },
                ],
                locateurs: Vec::new(),
            }))
        );
        // `--locator` : répétable, quatre au plus, de la forme `hôte:port`,
        // et seulement pour un annuaire local (décision 57).
        let federe = ["--federation", "a:1"];
        let quatre = [
            "--locator",
            "[2001:db8::7]:6630",
            "--locator",
            "192.0.2.7:6630",
            "--locator",
            "maison.example:6630",
            "--locator",
            "b:2",
        ];
        assert_eq!(
            Reglages::depuis(avec(&[&federe[..], &quatre[..]].concat()))
                .map(|lus| lus.federation.map(|federation| federation.locateurs)),
            Ok(Some(vec![
                "[2001:db8::7]:6630".to_owned(),
                "192.0.2.7:6630".to_owned(),
                "maison.example:6630".to_owned(),
                "b:2".to_owned(),
            ]))
        );
        assert_eq!(
            Reglages::depuis(avec(
                &[&federe[..], &quatre[..], &["--locator", "c:3"]].concat()
            ))
            .map(|_| ()),
            Err(Faute::LocateurInvalide("c:3".to_owned()))
        );
        assert_eq!(
            Reglages::depuis(avec(&[&federe[..], &["--locator", "sans-port"]].concat()))
                .map(|_| ()),
            Err(Faute::LocateurInvalide("sans-port".to_owned()))
        );
        assert_eq!(
            Reglages::depuis(avec(&["--locator", "b:2"])).map(|_| ()),
            Err(Faute::LocateurInvalide("b:2".to_owned()))
        );
        assert!(
            !Faute::LocateurInvalide("x".to_owned())
                .to_string()
                .is_empty()
        );
        // `<locateur>=<n-…>` : l'identité attendue, dite (décision 58).
        let identite = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Annuaire, [7; 16]);
        assert_eq!(
            Reglages::depuis(avec(&[
                "--federation",
                &format!("127.0.0.1:7000={}", identite.texte()),
            ]))
            .map(|lus| lus.federation.map(|federation| federation.racines)),
            Ok(Some(vec![CibleFederee {
                adresse: "127.0.0.1:7000".to_owned(),
                identite: Some(identite),
            }]))
        );
        for mauvais in [
            "127.0.0.1:7000=u-0000000000000000000000000G",
            "127.0.0.1:7000=x",
        ] {
            assert!(matches!(
                Reglages::depuis(avec(&["--federation", mauvais])),
                Err(Faute::AnnuaireInvalide(_))
            ));
        }
        assert!(
            !Faute::AnnuaireInvalide("x".to_owned())
                .to_string()
                .is_empty()
        );
        // Un locateur sans `=<n-…>` est permis : il doit alors être un
        // locateur de la liste embarquée — ce que le démarrage vérifie.
        assert!(Reglages::depuis(avec(&["--federation", "pas une adresse"])).is_err());
    }

    #[test]
    fn l_adresse_du_pair_a_la_forme_hote_port() {
        for bonne in [
            "argon.air-desktop.org:6630",
            "178.32.16.249:6630",
            "[2001:41d0:20a:900::1d32]:6630",
            "[::1]:1",
            "localhost:65535",
        ] {
            let lus = Reglages::depuis(avec(&["--peer", bonne, "--peer-key", "/argon.pub"]))
                .unwrap_or_else(|faute| panic!("{bonne} : {faute}"));
            assert_eq!(lus.pair.map(|pair| pair.adresse), Some(bonne.to_owned()));
        }
        for mauvaise in [
            "argon",
            "argon:",
            ":6630",
            "argon:0",
            "argon:65536",
            "argon:six",
            "2001:41d0:20a:900::1d32:6630",
            "[2001:41d0:20a:900::1d32:6630",
            "[argon]:6630",
            "",
        ] {
            assert_eq!(
                Reglages::depuis(avec(&["--peer", mauvaise, "--peer-key", "/argon.pub"]))
                    .map(|_| ()),
                Err(Faute::PairInvalide(mauvaise.to_owned())),
                "{mauvaise}"
            );
        }
        assert!(
            Faute::PairInvalide("x".to_owned())
                .to_string()
                .contains("hôte:port")
        );
    }

    #[test]
    fn chaque_faute_se_lit_en_francais() {
        for faute in [
            Faute::Inconnu("--x".to_owned()),
            Faute::SansValeur("--port".to_owned()),
            Faute::PasUnNombre {
                drapeau: "--port".to_owned(),
                donnee: "x".to_owned(),
            },
            Faute::Manque("--store"),
            Faute::Ancien {
                ancien: "--entrepot",
                nouveau: "--store",
            },
        ] {
            let dit = format!("{faute}");
            assert!(!dit.is_empty(), "{faute:?}");
        }
    }

    // ── Les orphelins, et le geste d'oubli ──────────────────────────────────

    #[test]
    fn les_orphelins_sont_a_trente_jours_par_defaut_et_zero_veut_dire_jamais() {
        let lus = Reglages::depuis(minimum()).expect("le minimum suffit");
        assert_eq!(lus.orphelins_jours, 30);
        assert_eq!(lus.orphelins_ms(), Some(30 * 24 * 60 * 60 * 1_000));

        let lus = Reglages::depuis(avec(&["--orphans", "7"])).expect("sept jours");
        assert_eq!(lus.orphelins_ms(), Some(7 * 24 * 60 * 60 * 1_000));

        // **ZÉRO EST « JAMAIS »**, et non un délai nul qui effacerait à la
        // seconde.
        let lus = Reglages::depuis(avec(&["--orphans", "0"])).expect("jamais");
        assert_eq!(lus.orphelins_jours, 0);
        assert_eq!(lus.orphelins_ms(), None);

        assert_eq!(
            Reglages::depuis(avec(&["--orphans", "trente"])).map(|_| ()),
            Err(Faute::PasUnNombre {
                drapeau: "--orphans".to_owned(),
                donnee: "trente".to_owned(),
            })
        );
        assert_eq!(
            Reglages::depuis(avec(&["--orphans"])).map(|_| ()),
            Err(Faute::SansValeur("--orphans".to_owned()))
        );
    }

    #[test]
    fn le_geste_d_inscription_se_lit_a_part() {
        use super::Inscription;
        assert_eq!(Reglages::geste_d_inscription(&minimum()), Ok(None));
        let commun = ["--directory", "banc:6630", "--identity-key", "/i"];
        let mut presenter = vec!["--register", "01234-56789"];
        presenter.extend_from_slice(&commun);
        assert_eq!(
            Reglages::geste_d_inscription(&presenter),
            Ok(Some(Inscription {
                racine: "banc:6630".to_owned(),
                identite: "/i".into(),
                code: Some("01234-56789".to_owned()),
            }))
        );
        let mut relire = vec!["--registration-status"];
        relire.extend_from_slice(&commun);
        assert_eq!(
            Reglages::geste_d_inscription(&relire).map(|lu| lu.and_then(|quoi| quoi.code)),
            Ok(None)
        );
        assert_eq!(
            Reglages::geste_d_inscription(&["--register"]),
            Err(Faute::SansValeur("--register".to_owned()))
        );
        for (manque, arguments) in [
            (
                "--directory",
                vec!["--registration-status", "--identity-key", "/i"],
            ),
            (
                "--identity-key",
                vec!["--registration-status", "--directory", "b:1"],
            ),
        ] {
            assert_eq!(
                Reglages::geste_d_inscription(&arguments),
                Err(Faute::Manque(manque))
            );
        }
        // **`--ca` EST REFUSÉ**, et non lu en silence (0.34.0).
        let mut hier = presenter.clone();
        hier.extend_from_slice(&["--ca", "/c"]);
        assert!(matches!(
            Reglages::geste_d_inscription(&hier),
            Err(Faute::Retire {
                drapeau: "--ca",
                ..
            })
        ));
    }

    #[test]
    fn le_geste_d_administration_se_lit_a_part_et_nomme_un_compte() {
        assert_eq!(Reglages::geste_d_administration(&minimum()), Ok(None));
        let compte = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Utilisateur, [7; 16]);
        let texte = compte.texte();
        for (drapeau, nomme) in [("--add-admin", true), ("--remove-admin", false)] {
            assert_eq!(
                Reglages::geste_d_administration(&[
                    drapeau,
                    texte.as_str(),
                    "--directory",
                    "banc:6630",
                    "--operator-secret",
                    "/k",
                ]),
                Ok(Some(Administration {
                    joindre: Invite {
                        annuaire: "banc:6630".to_owned(),
                        secrete: std::path::PathBuf::from("/k"),
                    },
                    compte,
                    nomme,
                }))
            );
        }
        // Un compte, et rien d'autre.
        assert_eq!(
            Reglages::geste_d_administration(&["--add-admin", "m-0000000000000000000000000"]),
            Err(Faute::CompteInvalide(
                "m-0000000000000000000000000".to_owned()
            ))
        );
        assert_eq!(
            Reglages::geste_d_administration(&["--remove-admin"]),
            Err(Faute::SansValeur("--remove-admin".to_owned()))
        );
        assert_eq!(
            Reglages::geste_d_administration(&["--add-admin", texte.as_str()]),
            Err(Faute::Manque("--directory"))
        );
        assert_eq!(
            Reglages::geste_d_administration(&[
                "--add-admin",
                texte.as_str(),
                "--directory",
                "b:1",
                "--operator-secret"
            ]),
            Err(Faute::SansValeur("--operator-secret".to_owned()))
        );
        assert!(matches!(
            Reglages::geste_d_administration(&[
                "--add-admin",
                texte.as_str(),
                "--directory",
                "b:1",
                "--ca",
                "/c",
                "--operator-secret",
                "/k",
            ]),
            Err(Faute::Retire {
                drapeau: "--ca",
                ..
            })
        ));
    }

    #[test]
    fn le_geste_d_invitation_se_lit_a_part_et_exige_ses_deux_chemins() {
        // Sans `--invite`, rien : ce sont des réglages ordinaires.
        assert_eq!(Reglages::geste_d_invitation(&minimum()), Ok(None));

        // Avec, les deux : où joindre — et qui l'on doit y trouver, dans le
        // locateur ou la liste embarquée —, et la clé qui signe.
        assert_eq!(
            Reglages::geste_d_invitation(&[
                "--invite",
                "--directory",
                "banc:6630",
                "--operator-secret",
                "/k",
            ]),
            Ok(Some(Invite {
                annuaire: "banc:6630".to_owned(),
                secrete: std::path::PathBuf::from("/k"),
            }))
        );

        // **`--ca` EST REFUSÉ DEPUIS 0.34.0** (décision 58), avec ce qu'il
        // faut faire à la place.
        assert!(matches!(
            Reglages::geste_d_invitation(&[
                "--invite",
                "--directory",
                "b:1",
                "--ca",
                "/c",
                "--operator-secret",
                "/k",
            ]),
            Err(Faute::Retire {
                drapeau: "--ca",
                ..
            })
        ));
        // Aucun des deux n'a de défaut, et l'absent est nommé : deviner une
        // racine ou une clé serait deviner à qui l'on parle.
        for (arguments, manque) in [
            (vec!["--invite", "--operator-secret", "/k"], "--directory"),
            (vec!["--invite", "--directory", "b:1"], "--operator-secret"),
        ] {
            assert_eq!(
                Reglages::geste_d_invitation(&arguments),
                Err(Faute::Manque(manque)),
                "{arguments:?}"
            );
        }

        // Un drapeau posé sans sa valeur se dit, plutôt que de prendre le
        // drapeau suivant pour une valeur.
        assert_eq!(
            Reglages::geste_d_invitation(&["--invite", "--directory"]),
            Err(Faute::SansValeur("--directory".to_owned()))
        );
    }

    #[test]
    fn le_geste_d_oubli_se_lit_a_part_et_exige_un_compte_et_un_entrepot() {
        let u = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Utilisateur, [0x24; 16]);
        let texte = u.texte().as_str().to_owned();

        // Sans `--forget`, rien : ce sont des réglages ordinaires.
        assert_eq!(Reglages::geste_d_oubli(&minimum()), Ok(None));

        // Avec, le compte et l'entrepôt — et l'identité si elle est là.
        assert_eq!(
            Reglages::geste_d_oubli(&["--forget", &texte, "--store", "/a"]),
            Ok(Some(Oubli {
                compte: u,
                entrepot: std::path::PathBuf::from("/a"),
                identite: None,
            }))
        );
        assert_eq!(
            Reglages::geste_d_oubli(&["--store", "/a", "--identity-key", "/k", "--forget", &texte]),
            Ok(Some(Oubli {
                compte: u,
                entrepot: std::path::PathBuf::from("/a"),
                identite: Some(std::path::PathBuf::from("/k")),
            }))
        );

        // Ce qui est refusé, et nommé.
        assert_eq!(
            Reglages::geste_d_oubli(&["--forget"]),
            Err(Faute::SansValeur("--forget".to_owned()))
        );
        assert_eq!(
            Reglages::geste_d_oubli(&["--forget", &texte]),
            Err(Faute::Manque("--store"))
        );
        assert_eq!(
            Reglages::geste_d_oubli(&["--forget", &texte, "--store"]),
            Err(Faute::SansValeur("--store".to_owned()))
        );
        // Un identifiant d'un autre genre n'est pas un compte.
        let m = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x24; 16]);
        let machine = m.texte().as_str().to_owned();
        assert_eq!(
            Reglages::geste_d_oubli(&["--forget", &machine, "--store", "/a"]),
            Err(Faute::CompteInvalide(machine.clone()))
        );
        assert_eq!(
            Reglages::geste_d_oubli(&["--forget", "thierry", "--store", "/a"]),
            Err(Faute::CompteInvalide("thierry".to_owned()))
        );
        assert!(!Faute::CompteInvalide("x".to_owned()).to_string().is_empty());
    }
}
