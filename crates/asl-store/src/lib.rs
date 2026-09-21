//! L'entrepôt durable : des tables, des transactions, et rien qui décide.
//!
//! # CETTE CRATE FAIT DES ENTRÉES-SORTIES, DONC ELLE EST HORS DU 100 %
//!
//! Y atteindre 100 % exigerait de simuler les pannes du système de fichiers — un
//! `ENOSPC` ici, un `EIO` là — et l'on mesurerait alors la fidélité de la
//! simulation. Ses essais écrivent donc dans de vrais fichiers temporaires.
//!
//! **Le FORMAT, lui, est couvert à 100 %** : il vit dans `asl-registre`, qui ne
//! touche à rien. C'est le partage qu'`air-mail-server` fait entre `ams-store`
//! et `ams-index`, et il compte plus ici qu'ailleurs — une faute d'encodage
//! n'arrête rien, elle rend un enregistrement faux DURABLEMENT.
//!
//! # POURQUOI `redb`, ET CE QUE CE CHOIX COÛTE
//!
//! Le manifeste du workspace porte le relevé qui a tranché. En deux lignes :
//! `redb` ne tire que `libc`, déjà présente et déjà admise, là où SQLite
//! ferait entrer douze unités dont `libsqlite3-sys` et `pkg-config` — c'est-à-dire
//! du C compilé, une barrière au rouge, et une dette de portage vers `linux-air`.
//!
//! Ce qu'il coûte : **pas de SQL ad hoc, aucun outil externe** pour ouvrir le
//! fichier. Un administrateur qui veut regarder passe par notre code.
//!
//! # LES CLÉS SONT DES OCTETS, LES VALEURS DES TABLEAUX FIXES
//!
//! Un identifiant se range sur dix-sept octets — son genre, puis ses seize. Le
//! genre en tête n'est pas décoratif : il fait que les enregistrements d'un même
//! genre se suivent, et qu'un balayage par genre est un intervalle.
//!
//! # L'ENTREPÔT ÉCRIT POUR UNE RACINE, ET CHAQUE ÉCRITURE EST ESTAMPILLÉE
//!
//! `docs/replication.md` §4 et §5 : une racine tient un compteur, chaque
//! écriture locale porte `(compteur, racine)`, et **ajoute une opération au
//! journal d'opérations dans la même transaction**. C'est ce que l'autre racine
//! tire. Trois choses de plus que ce que l'entrepôt portait : l'estampille sur
//! les enregistrements, le journal d'opérations, et le curseur par pair.
//!
//! **L'estampille est frappée ICI, et nulle part ailleurs.** L'appelant dit ce
//! qu'il écrit — un compte, un nom, une clé — et l'entrepôt dit quand, au sens
//! de l'horloge de Lamport : c'est le seul endroit qui puisse avancer le
//! compteur et écrire l'enregistrement dans une seule transaction. Une
//! estampille venue de l'appelant serait une estampille qu'on ne peut pas
//! vérifier.
//!
//! **L'application des opérations venues de l'autre racine est ici aussi**
//! ([`Entrepot::appliquer_la_suite`]) : la règle de conflit de
//! `replication.md` §3.2, genre par genre, le compteur hissé et le curseur
//! avancé dans la transaction qui applique — un lot de cadres par transaction.
//! Et ce qu'une base a estampillé sans identité passe sous l'identité réelle
//! à l'ouverture ([`RACINE_SANS_IDENTITE`]).

use std::path::Path;

use asl_id::{Genre, Identifiant};
use asl_registre::{
    APPAREIL_OCTETS, AUTORISATION_OCTETS, AliasRange, Appareil, Attestation, Autorisation,
    CLE_APPAREIL_OCTETS, CLE_OCTETS, CLEF_JOURNAL_OCTETS, COMPTE_OCTETS, Cadre, Capacites, Cause,
    CleLiee, Compte, DESCRIPTION_OCTETS, Description, EMPREINTE_OCTETS, ENROLEMENT_OCTETS,
    ENTREE_OCTETS, ESTAMPILLE_OCTETS, Effacement, Enrolement, EntreeJournal, Estampille,
    IDENTIFIANT_OCTETS, JetonPoussee, JetonRange, MACHINE_OCTETS, Machine, NomRange,
    OPERATION_OCTETS_MAX, Operation, POUSSEE_OCTETS, Plateforme, Portee, Provenance,
    SERVICE_OCTETS, Service, Systeme,
};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
    WriteTransaction,
};

// ── Les tables ──────────────────────────────────────────────────────────────

/// Les comptes, par identifiant.
const COMPTES: TableDefinition<'_, &[u8], &[u8; COMPTE_OCTETS]> = TableDefinition::new("comptes");

/// Les machines, par identifiant.
const MACHINES: TableDefinition<'_, &[u8], &[u8; MACHINE_OCTETS]> =
    TableDefinition::new("machines");

/// L'index des réclamations d'alias : `alias ‖ 0 ‖ estampille` vers le compte
/// qui réclame.
///
/// # C'EST UN INDEX, DONC UNE SECONDE VÉRITÉ — ET IL FAUT LE DIRE
///
/// L'alias vit AUSSI dans l'enregistrement du compte, avec l'estampille de sa
/// réclamation. Les deux doivent rester d'accord, et ce sont
/// [`Entrepot::creer_compte`] et [`Entrepot::reclamer_alias`] qui en répondent :
/// ils retirent l'ancienne réclamation avant d'écrire la nouvelle.
///
/// # UN ALIAS EST UNE RÉCLAMATION, ET LA PLUS ANCIENNE TIENT
///
/// `docs/replication.md` §3.2 : le titulaire d'un alias est le compte dont la
/// réclamation courante porte la plus petite estampille. **L'estampille est
/// dans la clé**, en gros-boutiste, après l'alias et un octet nul : les
/// réclamations d'un même alias se suivent dans l'ordre des estampilles, et
/// **le titulaire est la première de l'intervalle**. C'est une fonction de
/// l'ensemble des réclamations, pas de leur ordre d'arrivée — ce que
/// l'invariant de §3.1 exige, et ce qu'une table `alias → compte` ne pouvait
/// pas donner.
///
/// Aujourd'hui, une racine seule refuse une seconde réclamation
/// ([`Faute::AliasPris`]) : la file ne se remplit que par ce que l'autre racine
/// a accepté de son côté, et c'est l'application des opérations qui l'y mettra.
const ALIAS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("alias");

/// Les appareils, par identifiant.
const APPAREILS: TableDefinition<'_, &[u8], &[u8; APPAREIL_OCTETS]> =
    TableDefinition::new("appareils");

/// Les jetons de poussée, **par identifiant d'appareil**.
///
/// # UNE TABLE À PART, ET NON UNE COLONNE
///
/// `asl_registre::JetonPoussee` dit les trois raisons. Celle qui se voit ici est
/// la troisième : la table des appareils est lue à CHAQUE requête authentifiée,
/// et y loger 255 octets le plus souvent vides ferait payer à toutes les
/// requêtes un champ que presque aucune ne regarde.
const POUSSEES: TableDefinition<'_, &[u8], &[u8; POUSSEE_OCTETS]> =
    TableDefinition::new("poussees");

/// Ce que chaque appareil dit de lui-même, **par identifiant d'appareil**.
///
/// **Elle SURVIT à la révocation**, à l'inverse de [`POUSSEES`] : l'écran
/// d'après une perte doit montrer ce qu'on a retiré, et une description est
/// ce qui le rend lisible.
const DESCRIPTIONS: TableDefinition<'_, &[u8], &[u8; DESCRIPTION_OCTETS]> =
    TableDefinition::new("descriptions");

/// Les codes d'enrôlement en attente, **par empreinte du code**.
///
/// # LA CLÉ EST L'EMPREINTE, ET C'EST TOUT LE DISPOSITIF
///
/// `POST /v1/enrolement` ne nomme pas la machine : il présente un code. Chercher
/// par l'empreinte de ce code est donc la seule façon de trouver — et cela
/// tombe bien, puisque c'est aussi la seule façon de ne pas garder de secret en
/// clair sur le disque.
const ENROLEMENTS: TableDefinition<'_, &[u8], &[u8; ENROLEMENT_OCTETS]> =
    TableDefinition::new("enrolements");

/// L'empreinte du code en cours pour une machine, s'il y en a un.
///
/// **AU PLUS UN CODE VIVANT PAR MACHINE.** En émettre un second sans retirer le
/// premier laisserait deux secrets ouvrir la même porte, dont un que personne
/// n'attend plus. Cet index est ce qui permet de retrouver le précédent pour
/// l'effacer — sans lui, il faudrait balayer toute la table.
const ENROLEMENTS_PAR_MACHINE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("enrolements-par-machine");

/// Les services, par identifiant.
const SERVICES: TableDefinition<'_, &[u8], &[u8; SERVICE_OCTETS]> =
    TableDefinition::new("services");

/// L'index des services d'une machine : `machine ‖ nom` vers l'identifiant.
///
/// # POURQUOI CETTE CLÉ COMPOSÉE, ET NON DEUX TABLES
///
/// `/v1/ou/{machine}/{service}` demande un service PAR SON NOM sur une machine
/// donnée. Sans cet index, il faudrait balayer tous les services pour trouver
/// celui-là — et le balayage grandit avec l'annuaire entier, quand la réponse ne
/// dépend que d'une machine.
///
/// **La machine en tête n'est pas un détail** : elle fait que les services d'une
/// même machine se suivent, donc que « tous les services de cette machine » est
/// un intervalle et non un balayage.
const SERVICES_PAR_NOM: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("services-par-nom");

/// Les autorisations, par identifiant.
const AUTORISATIONS: TableDefinition<'_, &[u8], &[u8; AUTORISATION_OCTETS]> =
    TableDefinition::new("autorisations");

/// L'index des machines d'un compte : `compte ‖ machine`.
///
/// `MACHINES` est indexée par machine, et porte son propriétaire à l'intérieur.
/// Répondre à « quelles sont les machines de ce compte ? » demandait donc de
/// balayer TOUTES les machines de l'annuaire. C'est la même forme que
/// [`SERVICES_PAR_NOM`] : le compte en tête fait que ses machines se suivent.
const MACHINES_PAR_COMPTE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("machines-par-compte");

/// L'index des appareils d'un compte : `compte ‖ appareil`.
///
/// La même forme que [`MACHINES_PAR_COMPTE`], et pour la même raison :
/// `GET /v1/appareils` demande les appareils d'un compte.
const APPAREILS_PAR_COMPTE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("appareils-par-compte");

/// L'index des autorisations reçues : `bénéficiaire ‖ autorisation`.
///
/// **C'EST LE SENS DANS LEQUEL ON INTERROGE.** Une résolution demande « ce
/// compte-ci a-t-il le droit ? », donc on cherche par BÉNÉFICIAIRE. Indexer par
/// donneur obligerait à tout balayer pour répondre à la question qu'on pose.
const AUTORISATIONS_RECUES: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("autorisations-recues");

/// L'index des autorisations accordées : `donneur ‖ autorisation`.
///
/// Le second sens, que la résolution n'avait pas besoin de connaître :
/// `GET /v1/autorisations` demande les DEUX (`protocole.md` §2.2).
///
/// **Les index se reconstruisent à la reprise** (`docs/replication.md` §11.4) :
/// une autorisation posée avant que cet index existe y figure depuis que la
/// base a été reprise, et il en va de même de [`APPAREILS_PAR_COMPTE`] et de
/// [`MACHINES_PAR_COMPTE`]. Ce que ces trois-là avaient accepté à leur
/// naissance — « rien ne la remplit rétroactivement » — cesse d'être vrai.
const AUTORISATIONS_ACCORDEES: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("autorisations-accordees");

/// Le journal des requêtes (C18).
const JOURNAL: TableDefinition<'_, &[u8], &[u8; ENTREE_OCTETS]> = TableDefinition::new("journal");

/// Le rang qui départage deux entrées de la même milliseconde.
const RANG: TableDefinition<'_, &str, u64> = TableDefinition::new("rang");

/// La clé sous laquelle le rang du journal est rangé.
const CLEF_DU_RANG: &str = "journal";

/// Ce que la racine sait d'elle-même : le format de l'entrepôt, son compteur,
/// et jusqu'où son journal d'opérations a été expiré.
///
/// # LE FORMAT EST ÉCRIT, ET C'EST CE QUI REND LA REPRISE DÉCIDABLE
///
/// Une base d'avant l'estampille n'a pas cette table ; une base neuve la reçoit
/// à sa création. À l'ouverture, **son absence sur une base qui porte des
/// tables est le signe d'une base ancienne**, et c'est la reprise
/// (`docs/replication.md` §11.4). Un format qu'on ne connaît pas — celui d'une
/// version future — est refusé plutôt que relu de travers.
const RACINE: TableDefinition<'_, &str, u64> = TableDefinition::new("racine");

/// La clé du format de l'entrepôt.
const CLEF_DU_FORMAT: &str = "format";

/// La clé du compteur de la racine.
const CLEF_DU_COMPTEUR: &str = "compteur";

/// La clé du dernier compteur dont l'opération a été retirée du journal.
const CLEF_DES_RETIREES: &str = "operations-retirees-jusqu-a";

/// Le format de cet entrepôt : le troisième, celui des dates.
///
/// Le premier n'était pas numéroté — il n'y avait rien d'autre —, et c'est son
/// absence qui le désigne. Le second est celui de l'estampille (0.5.0 à
/// 0.10.1). Le troisième ajoute `révoqué le` à l'appareil, `effacé le` et sa
/// cause au compte (`docs/modele.md` §2.1, §2.2, 2026-09-18) — et chacun se
/// reprend depuis le précédent, à l'ouverture, dans une transaction.
const FORMAT: u64 = 3;

/// Le format d'avant les dates.
const FORMAT_SANS_DATES: u64 = 2;

/// Le journal d'opérations (`docs/replication.md` §5), **par compteur**.
///
/// # LA VALEUR EST L'INSTANT D'ÉCRITURE, PUIS LE CADRE
///
/// Le cadre est ce que l'autre racine tire, tel quel :
/// `genre ‖ compteur ‖ racine ‖ charge` (`asl_registre::Operation`). L'instant
/// qui le précède ne part pas sur le fil : il sert à la rétention de trente
/// jours (§5.4), et à rien d'autre — le compteur ne dit pas l'heure, et une
/// rétention se compte en jours.
///
/// **Il ne contient que ce que cette racine a écrit ELLE-MÊME**, et de
/// provenance locale (§7, C11) : ce qu'elle appliquera de l'autre n'y sera pas
/// réécrit, et ce qu'elle aura un jour reçu d'un annuaire rattaché ne passe pas.
const OPERATIONS: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("operations");

/// Le curseur par pair : ce que cette racine a appliqué de chaque autre.
///
/// C'est le lecteur qui le tient, parce que c'est lui qui sait ce qu'il a
/// appliqué (`docs/replication.md` §2.1). Il avance dans la transaction qui
/// applique — ce sera à l'application de l'y mettre.
const CURSEURS: TableDefinition<'_, &[u8], u64> = TableDefinition::new("curseurs");

/// Ce que le journal d'opérations garde : trente jours, en millisecondes.
///
/// `docs/replication.md` §5.4, décidé : une racine absente un mois n'est plus
/// une racine en retard, c'est une racine à reconstruire — et la reconstruire
/// est l'amorçage, la même procédure que pour une racine neuve.
pub const RETENTION_DES_OPERATIONS_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// L'identifiant sous lequel une racine estampille TANT QU'ELLE N'A PAS DE
/// CLÉ D'IDENTITÉ : seize zéros.
///
/// # IL NE SE DÉDUIT D'AUCUNE CLÉ, ET C'EST CE QUI LE RÉSERVE
///
/// `docs/replication.md` §2.2 : le `n-…` d'une racine se déduit de sa clé
/// d'identité Ed25519. Une racine sans `--identity-key` n'en a pas, et
/// l'entrepôt ne sait pas écrire sans racine — chaque écriture porte
/// `(compteur, racine)`. Elle estampille donc sous cet identifiant, que le
/// journal d'exploitation nomme au démarrage, et qui ne sera jamais celui
/// d'une racine réelle.
///
/// **Il ne traverse jamais la voie entre racines** : au premier démarrage AVEC
/// une clé, tout ce qui est estampillé sous lui est ré-estampillé sous
/// l'identité réelle ([`Entrepot::ouvrir`], `replication.md` §11.4). C'est ce
/// qui fait qu'une base des bancs, reprise avant d'avoir une identité, se
/// réplique ensuite comme si elle l'avait toujours eue.
pub const RACINE_SANS_IDENTITE: Identifiant =
    Identifiant::depuis_entropie(Genre::Annuaire, [0; 16]);

/// Les tables de la forme d'avant l'estampille, par leur nom d'hier.
///
/// **Les mêmes noms, une autre taille de valeur** : `redb` range le type avec
/// la table, et n'ouvre celle d'hier qu'avec la taille d'hier. La reprise les
/// lit sous ces définitions, les supprime, et les recrée sous les courantes.
mod anciennes {
    use asl_registre::ancien;
    use redb::TableDefinition;

    /// Les comptes d'hier.
    pub const COMPTES: TableDefinition<'_, &[u8], &[u8; ancien::COMPTE_OCTETS]> =
        TableDefinition::new("comptes");
    /// Les machines d'hier.
    pub const MACHINES: TableDefinition<'_, &[u8], &[u8; ancien::MACHINE_OCTETS]> =
        TableDefinition::new("machines");
    /// Les appareils d'hier.
    pub const APPAREILS: TableDefinition<'_, &[u8], &[u8; ancien::APPAREIL_OCTETS]> =
        TableDefinition::new("appareils");
    /// Les jetons d'hier.
    pub const POUSSEES: TableDefinition<'_, &[u8], &[u8; ancien::POUSSEE_OCTETS]> =
        TableDefinition::new("poussees");
    /// Les descriptions d'hier.
    pub const DESCRIPTIONS: TableDefinition<'_, &[u8], &[u8; ancien::DESCRIPTION_OCTETS]> =
        TableDefinition::new("descriptions");
    /// Les enrôlements d'hier.
    pub const ENROLEMENTS: TableDefinition<'_, &[u8], &[u8; ancien::ENROLEMENT_OCTETS]> =
        TableDefinition::new("enrolements");
    /// Les services d'hier.
    pub const SERVICES: TableDefinition<'_, &[u8], &[u8; ancien::SERVICE_OCTETS]> =
        TableDefinition::new("services");
    /// Les autorisations d'hier.
    pub const AUTORISATIONS: TableDefinition<'_, &[u8], &[u8; ancien::AUTORISATION_OCTETS]> =
        TableDefinition::new("autorisations");
    /// L'index des alias d'hier : `alias → compte`, sans réclamation.
    pub const ALIAS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("alias");

    /// Les deux tables de la forme d'avant les DATES (0.5.0 à 0.10.1) :
    /// l'estampille est là, `révoqué le` et `effacé le` non. Les autres
    /// tables n'ont pas bougé.
    pub mod sans_dates {
        use asl_registre::sans_dates;
        use redb::TableDefinition;

        /// Les comptes d'avant les dates.
        pub const COMPTES: TableDefinition<'_, &[u8], &[u8; sans_dates::COMPTE_OCTETS]> =
            TableDefinition::new("comptes");
        /// Les appareils d'avant les dates.
        pub const APPAREILS: TableDefinition<'_, &[u8], &[u8; sans_dates::APPAREIL_OCTETS]> =
            TableDefinition::new("appareils");
    }
}

// ── Les fautes ──────────────────────────────────────────────────────────────

/// Ce qui empêche l'entrepôt de répondre.
#[derive(Debug)]
pub enum Faute {
    /// La base elle-même a refusé.
    Base(redb::Error),
    /// Un enregistrement relu n'a pas la forme attendue.
    ///
    /// **Cela signifie une corruption**, pas une requête fautive : ces octets
    /// ont été écrits par nous.
    Enregistrement(asl_registre::Faute),
    /// Cet alias appartient déjà à un autre compte.
    ///
    /// **Ce n'est pas une faute technique**, c'est la règle : deux comptes qui
    /// répondraient au même alias rendraient l'alias inutilisable pour retrouver
    /// quelqu'un, ce qui est sa seule raison d'être.
    AliasPris,
    /// Ce qu'on crée existe déjà.
    ///
    /// Un identifiant à 128 bits ne collisionne pas : c'est l'appelant qui a
    /// réemployé un identifiant, ou déclaré un `(machine, nom)` qu'un autre
    /// service tient. **Créer n'écrase jamais** — les règles de
    /// `replication.md` §5.2 disent « insérer si absent », et l'entrepôt les
    /// tient pour ses propres écritures aussi.
    Existe,
    /// Un identifiant rangé n'a pas la longueur d'un identifiant.
    Longueur {
        /// Ce qui a été trouvé.
        obtenue: usize,
    },
    /// L'entrepôt est d'un format que ce binaire ne connaît pas.
    ///
    /// **Une version future relue par une version ancienne** — le cas qui
    /// arrive à chaque retour arrière de déploiement. On refuse d'ouvrir plutôt
    /// que de relire de travers.
    Format {
        /// Ce que la base annonce.
        lu: u64,
    },
}

impl core::fmt::Display for Faute {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Base(quoi) => write!(sortie, "la base a refusé : {quoi}"),
            Self::Enregistrement(quoi) => {
                write!(sortie, "un enregistrement est corrompu : {quoi:?}")
            }
            Self::AliasPris => write!(sortie, "cet alias appartient à un autre compte"),
            Self::Existe => write!(sortie, "cela existe déjà"),
            Self::Longueur { obtenue } => {
                write!(sortie, "un identifiant de {obtenue} octets a été trouvé")
            }
            Self::Format { lu } => write!(
                sortie,
                "l'entrepôt est au format {lu}, que ce binaire ne connaît pas (il connaît {FORMAT})"
            ),
        }
    }
}

impl Faute {
    /// L'entrepôt est-il tenu par un autre processus ?
    ///
    /// **C'est `redb` qui le sait** : le daemon prend un verrou exclusif sur
    /// le fichier à l'ouverture (`File::try_lock`), et ouvrir un fichier
    /// qu'un autre tient rend `DatabaseAlreadyOpen`. Un geste hors ligne —
    /// `asl-server --forget` — le demande pour refuser de tourner pendant que
    /// l'annuaire sert, et le dire (`replication.md` §8).
    #[must_use]
    pub const fn entrepot_tenu(&self) -> bool {
        matches!(self, Self::Base(redb::Error::DatabaseAlreadyOpen))
    }
}

impl std::error::Error for Faute {}

/// Chaque erreur de `redb` devient [`Faute::Base`].
///
/// **Une implémentation par type, et non une générique sur `Into<redb::Error>`** :
/// la générique interdirait celle qui suit, pour `asl_registre::Faute` — le
/// compilateur ne peut pas promettre qu'une version future de `redb` n'en fera
/// pas une erreur à elle.
macro_rules! depuis_redb {
    ($($erreur:ty),* $(,)?) => {
        $(
            impl From<$erreur> for Faute {
                fn from(quoi: $erreur) -> Self {
                    Self::Base(quoi.into())
                }
            }
        )*
    };
}

depuis_redb!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
);

impl From<asl_registre::Faute> for Faute {
    fn from(quoi: asl_registre::Faute) -> Self {
        Self::Enregistrement(quoi)
    }
}

// ── Les clés ────────────────────────────────────────────────────────────────

/// La clé d'un identifiant : son genre, puis ses seize octets.
fn clef(quoi: Identifiant) -> [u8; IDENTIFIANT_OCTETS] {
    let mut sortie = [0_u8; IDENTIFIANT_OCTETS];
    sortie
        .get_mut(..1)
        .unwrap_or_default()
        .fill(quoi.genre().prefixe());
    for (place, octet) in sortie.iter_mut().skip(1).zip(quoi.octets().iter()) {
        *place = *octet;
    }
    sortie
}

/// Relit un identifiant rangé comme clé.
fn depuis_clef(octets: &[u8]) -> Result<Identifiant, Faute> {
    if octets.len() != IDENTIFIANT_OCTETS {
        return Err(Faute::Longueur {
            obtenue: octets.len(),
        });
    }
    let genre = octets
        .first()
        .copied()
        .and_then(Genre::depuis_prefixe)
        .ok_or(Faute::Longueur {
            obtenue: octets.len(),
        })?;
    let mut entropie = [0_u8; 16];
    for (place, octet) in entropie.iter_mut().zip(octets.iter().skip(1)) {
        *place = *octet;
    }
    Ok(Identifiant::depuis_entropie(genre, entropie))
}

/// La clé d'un service dans l'index par nom : la machine, puis le nom.
///
/// **LA MACHINE EN TÊTE**, pour que ses services se suivent — voir
/// [`SERVICES_PAR_NOM`].
fn clef_de_nom(machine: Identifiant, nom: &[u8]) -> Vec<u8> {
    let mut composee = clef(machine).to_vec();
    composee.extend_from_slice(nom);
    composee
}

/// Une clé d'index : ce par quoi l'on cherche, puis ce qu'on trouve.
///
/// **L'ORDRE EST TOUT** : le premier membre en tête fait que ses entrées se
/// suivent, donc qu'un intervalle remplace un balayage.
fn paire(par_quoi: Identifiant, quoi: Identifiant) -> Vec<u8> {
    let mut composee = clef(par_quoi).to_vec();
    composee.extend_from_slice(&clef(quoi));
    composee
}

/// Les bornes d'un intervalle qui couvre tout ce qui commence par cette clé.
fn intervalle(par_quoi: Identifiant) -> ([u8; IDENTIFIANT_OCTETS], Vec<u8>) {
    let debut = clef(par_quoi);
    let mut fin = debut.to_vec();
    fin.push(0xFF);
    (debut, fin)
}

/// La clé d'une réclamation d'alias : l'alias, un octet nul, l'estampille.
///
/// L'octet nul sépare deux alias dont l'un préfixe l'autre — `lea` et
/// `leandre` — et l'alphabet d'un alias ne le contient pas. **L'estampille
/// suit, en gros-boutiste** : l'ordre des octets est l'ordre des réclamations,
/// et la première de l'intervalle est le titulaire (voir [`ALIAS`]).
fn clef_de_reclamation(alias: &[u8], estampille: Estampille) -> Vec<u8> {
    let mut composee = Vec::with_capacity(alias.len().saturating_add(1 + ESTAMPILLE_OCTETS));
    composee.extend_from_slice(alias);
    composee.push(0);
    composee.extend_from_slice(&estampille.compteur.to_be_bytes());
    composee.extend_from_slice(&clef(estampille.racine));
    composee
}

/// Les bornes de l'intervalle des réclamations d'un alias.
fn intervalle_des_reclamations(alias: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut debut = alias.to_vec();
    debut.push(0);
    let mut fin = alias.to_vec();
    fin.push(1);
    (debut, fin)
}

/// Maintenant, en millisecondes d'époque — pour dater ce qui expire.
fn maintenant_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
        })
}

// ── Ce qu'une écriture locale fait de plus ──────────────────────────────────

/// Avance le compteur de la racine, et rend l'estampille de cette écriture.
///
/// **Dans la transaction qui écrit**, et c'est ce qui rend le compteur
/// strictement croissant : deux écritures concurrentes ne peuvent pas obtenir
/// la même estampille, parce que `redb` n'a qu'une transaction d'écriture à la
/// fois.
fn estampiller(ecriture: &WriteTransaction, racine: Identifiant) -> Result<Estampille, Faute> {
    let mut table = ecriture.open_table(RACINE)?;
    let compteur = table
        .get(CLEF_DU_COMPTEUR)?
        .map_or(0, |quoi| quoi.value())
        .saturating_add(1);
    table.insert(CLEF_DU_COMPTEUR, compteur)?;
    Ok(Estampille { compteur, racine })
}

/// Ajoute cette opération au journal d'opérations, sous cette estampille.
///
/// # SEULEMENT CE QUI EST DE PROVENANCE LOCALE
///
/// `docs/replication.md` §7, C11 : la voie entre racines ne transporte que des
/// enregistrements de provenance locale. Ce qu'une racine aura un jour reçu
/// d'un annuaire rattaché n'est pas à elle, et ne passe pas — il n'entre donc
/// pas dans ce journal. Aujourd'hui rien ne vient d'ailleurs ; la règle est
/// écrite là où elle s'appliquera.
fn journaliser_l_operation(
    ecriture: &WriteTransaction,
    estampille: Estampille,
    provenance: Provenance,
    operation: &Operation,
) -> Result<Option<Estampille>, Faute> {
    if provenance != Provenance::Ici {
        return Ok(None);
    }
    let mut cadre = [0_u8; OPERATION_OCTETS_MAX];
    let combien = operation.ecrire(estampille, &mut cadre);
    let mut valeur = Vec::with_capacity(combien.saturating_add(8));
    valeur.extend_from_slice(&maintenant_ms().to_be_bytes());
    valeur.extend_from_slice(cadre.get(..combien).unwrap_or_default());
    let mut table = ecriture.open_table(OPERATIONS)?;
    table.insert(estampille.compteur, valeur.as_slice())?;
    Ok(Some(estampille))
}

/// Ce qu'un rattrapage rend (`docs/replication.md` §5.3-5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rattrapage {
    /// Les cadres écrits après le compteur demandé, dans l'ordre.
    ///
    /// Chacun est `genre ‖ compteur ‖ racine ‖ charge`, tel que
    /// `asl_registre::Operation::lire` le relit, et tel que le fil le porte.
    Operations(Vec<Vec<u8>>),
    /// Le journal ne remonte plus jusque-là : c'est le `410`, et la réponse
    /// est l'instantané.
    HorsJournal {
        /// Le dernier compteur dont l'opération a été retirée. Un rattrapage
        /// n'est possible qu'à partir de lui.
        retirees_jusqu_a: u64,
    },
}

/// Les effets sur l'état VIVANT d'une opération appliquée (`docs/replication.md`
/// §3.3).
///
/// # CE QUI EST VIVANT SE REJOUE, CE QUI EST PARTI NE REPART PAS
///
/// Appliquer une opération venue de l'autre racine produit les mêmes effets sur
/// l'état vivant qu'une écriture locale : une clé de machine révoquée ferme les
/// connexions de cette machine ICI, une capacité `annonce` retirée fait tomber
/// ses baux ICI, un appareil révoqué ferme les siennes. **L'entrepôt ne tient
/// pas les connexions** — c'est la boucle qui les tient —, donc il ne peut pas
/// fermer lui-même : il NOMME ce qu'il faut fermer, et la boucle le fait, comme
/// pour une révocation locale.
///
/// **Et AUCUN effet vers l'extérieur** : la notification d'une autorisation part
/// de la racine qui a pris l'écriture, jamais de celle qui l'applique. Il n'y a
/// donc rien ici pour cela.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EffetsVivants {
    /// Les machines et appareils dont les connexions doivent tomber ici : une
    /// clé de machine révoquée, une capacité `annonce` retirée, un appareil
    /// révoqué. La boucle les compare au pair authentifié de chaque connexion
    /// (`asl_session::Session::pair`), comme pour une révocation locale.
    pub a_fermer: Vec<Identifiant>,
}

/// Pourquoi une opération a été refusée (`docs/replication.md` §3, §5.3, §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotifDeRefus {
    /// Son compteur ne dépasse pas le curseur : c'est une relivraison, et la
    /// règle d'application est idempotente — on la saute sans bruit (§5.3).
    Recule,
    /// Elle porte NOTRE propre identifiant de racine : c'est un rejeu de ce que
    /// nous avons écrit, revenu par la voie. Il n'y a pas de réplication
    /// transitive (§5.1), donc cela ne devrait pas arriver — on le journalise.
    Rejeu,
    /// Son enregistrement n'est pas de provenance locale : C11 ne laisse passer
    /// que `locale` entre racines (§7). Refusée et journalisée.
    HorsProvenance,
}

/// Ce qu'une application de cadre a donné (`docs/replication.md` §3, §5.3-5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applique {
    /// L'opération a été appliquée : le curseur du pair est à ce compteur, et
    /// voici ce qu'il faut fermer ici.
    Faite {
        /// Le compteur auquel le curseur du pair est désormais.
        curseur: u64,
        /// Ce que l'application ferme ici.
        effets: EffetsVivants,
    },
    /// C'était le cadre de fin d'un instantané : le curseur reprend là.
    Fin {
        /// Le compteur de coupe — c'est là que `GET /v1/pair/operations`
        /// reprend.
        curseur: u64,
    },
    /// L'opération a été refusée, et pour cette raison. Le curseur n'avance pas.
    Refusee(MotifDeRefus),
}

/// Ce que l'effacement d'un compte a retiré (`docs/modele.md` §2.1).
///
/// **Des nombres, et ce qu'il faut fermer** — rien qui nomme ce qui est parti :
/// `--forget` imprime les nombres, la boucle ferme les connexions, et ni l'un
/// ni l'autre n'a besoin d'une liste de ce qui n'existe plus.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Retrait {
    /// Combien d'appareils ont été effacés — révoqués et effacés, avec leur
    /// jeton et leur description.
    pub appareils: usize,
    /// Combien de machines ont été effacées, avec leur clé.
    pub machines: usize,
    /// Combien de codes d'enrôlement en cours ont été annulés.
    pub codes: usize,
    /// Combien de services déclarés sont partis avec leurs machines.
    pub services: usize,
    /// Combien d'autorisations ont été retirées, dans les deux sens.
    pub autorisations: usize,
    /// L'alias a-t-il été libéré ?
    pub alias: bool,
    /// Les machines et appareils du compte : ce dont les connexions doivent
    /// tomber ici, comme après une révocation (`protocole.md` §2.1 quater).
    pub a_fermer: Vec<Identifiant>,
}

/// Ce qu'un effacement local a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Efface {
    /// Le compte vient d'être effacé, et voici ce qui est parti.
    Fait(Retrait),
    /// Il l'était déjà — le, et par qui — et rien n'a été écrit.
    Deja(Effacement),
}

/// Ce qu'un instantané accumule : des cadres, dans l'ordre d'émission.
#[derive(Default)]
struct Suite {
    /// Les cadres, chacun tel que le fil le porte.
    cadres: Vec<Vec<u8>>,
}

impl Suite {
    /// Ajoute cette opération, sous cette estampille.
    fn ajouter(&mut self, estampille: Estampille, operation: &Operation) {
        let mut cadre = [0_u8; OPERATION_OCTETS_MAX];
        let combien = operation.ecrire(estampille, &mut cadre);
        self.cadres
            .push(cadre.get(..combien).unwrap_or_default().to_vec());
    }

    /// Termine la suite par le cadre de fin, à cette coupe.
    fn finir(&mut self, coupe: Estampille) {
        let mut cadre = [0_u8; OPERATION_OCTETS_MAX];
        let combien = Cadre::Fin { coupe }.ecrire(&mut cadre);
        self.cadres
            .push(cadre.get(..combien).unwrap_or_default().to_vec());
    }
}

// ── L'entrepôt ──────────────────────────────────────────────────────────────

/// L'entrepôt durable d'un annuaire.
pub struct Entrepot {
    /// La base, un seul fichier.
    base: Database,
    /// La racine pour laquelle cet entrepôt écrit : ce que porte chaque
    /// estampille qu'il frappe.
    racine: Identifiant,
    /// Le compteur de la dernière opération JOURNALISÉE, en mémoire.
    ///
    /// # C'EST LA NOTIFICATION DES ÉCRITURES, ET ELLE NE COÛTE RIEN
    ///
    /// `GET /v1/pair/operations` ne se termine jamais : la voie doit apprendre
    /// qu'une opération vient d'être écrite pour la pousser. Une relecture du
    /// journal à chaque tour de boucle serait une transaction de lecture par
    /// datagramme reçu ; un canal demanderait à la transaction de connaître
    /// la boucle. Un entier en mémoire, posé APRÈS le commit, dit à qui le
    /// compare à son curseur qu'il y a quelque chose à lire — et rien d'autre.
    ///
    /// **Après le commit, jamais avant** : posé avant, le lecteur pourrait
    /// relire le journal sans y trouver l'opération, et ne plus jamais être
    /// prévenu pour elle.
    derniere_operation: std::sync::atomic::AtomicU64,
    /// Combien d'enregistrements et d'opérations l'ouverture a ré-estampillés
    /// sous l'identité réelle (`replication.md` §11.4) — zéro le plus souvent.
    reestampilles: usize,
    /// Combien d'appareils déjà révoqués ont reçu, à l'ouverture, la date de
    /// la reprise pour `révoqué le` (`docs/modele.md` §2.2) — zéro le plus
    /// souvent, et une fois seulement.
    dates_de_reprise: usize,
}

impl Entrepot {
    /// Ouvre l'entrepôt à cet endroit, en le créant s'il n'existe pas, pour
    /// que cette racine y écrive.
    ///
    /// **LES TABLES SONT CRÉÉES ICI, ET PAS À LA PREMIÈRE ÉCRITURE.** Une table
    /// qui naîtrait au premier `insert` ferait échouer toute LECTURE antérieure
    /// avec « table inexistante » — une base neuve rendrait donc une erreur là
    /// où elle doit rendre « rien ».
    ///
    /// # UNE BASE ANCIENNE EST REPRISE, ET RIEN N'EST PERDU
    ///
    /// `docs/replication.md` §11.4 : une base écrite avant l'estampille porte
    /// des tables, et pas de format. Chaque enregistrement reçoit alors une
    /// estampille — un compteur attribué en séquence, l'identifiant de la
    /// racine qui reprend —, le compteur de la racine est posé au-dessus, les
    /// index sont reconstruits, **et le journal d'opérations démarre vide** :
    /// une base reprise s'amorcera chez l'autre racine par instantané, jamais
    /// par rattrapage. Tout cela dans UNE transaction — une reprise
    /// interrompue n'a pas eu lieu, et recommencera.
    ///
    /// # ET CE QUI A ÉTÉ ESTAMPILLÉ SANS IDENTITÉ EST RÉ-ESTAMPILLÉ
    ///
    /// Une base reprise — ou écrite — par une racine sans `--identity-key`
    /// porte des estampilles sous [`RACINE_SANS_IDENTITE`]. **Au premier
    /// démarrage avec une clé, elles passent sous l'identité réelle**, le
    /// compteur gardé : chaque enregistrement, chaque champ estampillé, chaque
    /// réclamation d'alias de l'index, et chaque opération du journal. Dans la
    /// même transaction que le reste, et une fois : une seconde ouverture ne
    /// trouve plus rien à ré-estampiller, et [`Entrepot::reestampilles`] rend
    /// zéro. Sans cela, seize zéros partiraient sur la voie, et l'autre racine
    /// les ré-estampillerait sous SON identité au redémarrage suivant — deux
    /// estampilles pour un même fait, et une règle de conflit qui ne calcule
    /// plus la même chose des deux côtés.
    ///
    /// Une racine SANS clé ne ré-estampille rien : elle n'a pas d'identité à
    /// donner.
    ///
    /// # ET UNE BASE D'AVANT LES DATES EST REPRISE AUSSI
    ///
    /// `docs/modele.md` §2.2 (2026-09-18) : le compte et l'appareil ont
    /// changé de forme — `effacé le` et sa cause, `révoqué le`. Une base au
    /// format 2 est reprise à l'ouverture, dans une transaction : les deux
    /// tables sont relues sous leur définition d'hier et réécrites sous
    /// celle d'aujourd'hui ; **les appareils déjà révoqués reçoivent pour
    /// `révoqué le` la date de la reprise** — l'annuaire ne sait pas mieux,
    /// et poser plus ancien serait affirmer ce qu'il n'a pas mesuré (C6) —,
    /// aucun compte n'est effacé ; et **le journal d'opérations est vidé,
    /// marqué retiré jusqu'au compteur**, comme à la première reprise : ce
    /// qu'il portait est de la forme d'hier, que l'autre racine ne saurait
    /// plus lire, et une base reprise s'amorce chez l'autre par instantané.
    /// Le curseur du pair ne bouge pas. [`Entrepot::dates_de_reprise`] dit
    /// combien d'appareils ont reçu une date, pour le journal d'exploitation.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si le fichier ne peut être ni ouvert ni créé,
    /// [`Faute::Format`] s'il est d'un format inconnu, [`Faute::Enregistrement`]
    /// si une base ancienne porte un enregistrement illisible.
    pub fn ouvrir(chemin: &Path, racine: Identifiant) -> Result<Self, Faute> {
        Self::amorcer(Database::create(chemin)?, racine)
    }

    /// Un entrepôt EN MÉMOIRE, qui ne touche aucun fichier.
    ///
    /// **POUR LES ESSAIS ET LE FUZZ, ET RIEN D'AUTRE** : l'application des
    /// opérations se pilote sans disque, et le fuzz en fait des milliers par
    /// seconde là où un `fsync` par transaction en ferait quelques centaines.
    /// La règle est la même — c'est le support qui change.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base en mémoire refuse.
    pub fn en_memoire(racine: Identifiant) -> Result<Self, Faute> {
        let base =
            Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::amorcer(base, racine)
    }

    /// Prépare les tables et lit le compteur, quel que soit le support.
    fn amorcer(base: Database, racine: Identifiant) -> Result<Self, Faute> {
        let reestampilles;
        let mut dates_de_reprise = 0_usize;
        {
            let ecriture = base.begin_write()?;
            let format = {
                let table = ecriture.open_table(RACINE)?;
                table.get(CLEF_DU_FORMAT)?.map(|quoi| quoi.value())
            };
            // La date de la reprise : celle que reçoivent les appareils déjà
            // révoqués, faute de mieux.
            let quand = maintenant_ms();
            match format {
                Some(FORMAT) => {}
                Some(FORMAT_SANS_DATES) => {
                    dates_de_reprise = reprendre_les_dates(&ecriture, quand)?;
                    let mut table = ecriture.open_table(RACINE)?;
                    table.insert(CLEF_DU_FORMAT, FORMAT)?;
                }
                Some(lu) => return Err(Faute::Format { lu }),
                None => {
                    // **PAS DE FORMAT, MAIS DES TABLES : C'EST UNE BASE
                    // ANCIENNE.** Une base neuve n'a rien du tout, et reçoit
                    // son format avec ses tables.
                    let ancienne = ecriture
                        .list_tables()?
                        .any(|table| table.name() == COMPTES.name());
                    if ancienne {
                        dates_de_reprise = reprendre(&ecriture, racine, quand)?;
                    }
                    let mut table = ecriture.open_table(RACINE)?;
                    table.insert(CLEF_DU_FORMAT, FORMAT)?;
                }
            }
            ecriture.open_table(COMPTES)?;
            ecriture.open_table(MACHINES)?;
            ecriture.open_table(APPAREILS)?;
            ecriture.open_table(ENROLEMENTS)?;
            ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
            ecriture.open_table(ALIAS)?;
            ecriture.open_table(SERVICES)?;
            ecriture.open_table(SERVICES_PAR_NOM)?;
            ecriture.open_table(AUTORISATIONS)?;
            ecriture.open_table(AUTORISATIONS_RECUES)?;
            ecriture.open_table(AUTORISATIONS_ACCORDEES)?;
            ecriture.open_table(MACHINES_PAR_COMPTE)?;
            ecriture.open_table(APPAREILS_PAR_COMPTE)?;
            ecriture.open_table(POUSSEES)?;
            ecriture.open_table(DESCRIPTIONS)?;
            ecriture.open_table(JOURNAL)?;
            ecriture.open_table(RANG)?;
            ecriture.open_table(OPERATIONS)?;
            ecriture.open_table(CURSEURS)?;
            // **APRÈS QUE LES TABLES EXISTENT, DANS LA MÊME TRANSACTION** : ce
            // que la racine sans identité a estampillé passe sous l'identité
            // réelle, ou rien ne bouge.
            reestampilles = if racine == RACINE_SANS_IDENTITE {
                0
            } else {
                reestampiller(&ecriture, RACINE_SANS_IDENTITE, racine)?
            };
            ecriture.commit()?;
        }
        // Le compteur de la racine majore ce que le journal porte : un lecteur
        // qui part de là ne manque rien, et relit au pire une fois pour rien.
        let compteur = {
            let lecture = base.begin_read()?;
            let table = lecture.open_table(RACINE)?;
            table.get(CLEF_DU_COMPTEUR)?.map_or(0, |quoi| quoi.value())
        };
        Ok(Self {
            base,
            racine,
            derniere_operation: std::sync::atomic::AtomicU64::new(compteur),
            reestampilles,
            dates_de_reprise,
        })
    }

    /// Combien d'enregistrements et d'opérations l'ouverture a ré-estampillés
    /// sous l'identité réelle (`docs/replication.md` §11.4).
    ///
    /// **C'est au journal d'exploitation de le dire, avec le nombre** : une
    /// reprise qui a eu lieu se lit là où l'exploitant relit ses réglages, et
    /// zéro se tait.
    #[must_use]
    pub const fn reestampilles(&self) -> usize {
        self.reestampilles
    }

    /// Combien d'appareils déjà révoqués ont reçu, à l'ouverture, la date de
    /// la reprise pour `révoqué le` (`docs/modele.md` §2.2) — et c'est aussi
    /// au journal d'exploitation de le dire : c'est de cette date que la
    /// règle des orphelins comptera pour eux.
    #[must_use]
    pub const fn dates_de_reprise(&self) -> usize {
        self.dates_de_reprise
    }

    /// Le compteur de la dernière opération journalisée, sans transaction.
    ///
    /// **Ce n'est pas [`Entrepot::compteur`]** : celui-là est l'horloge de
    /// Lamport, qui se hisse aussi sur ce qu'on reçoit ; celui-ci ne bouge que
    /// sur ce que CETTE racine a écrit et journalisé. La voie entre racines le
    /// compare à ce qu'elle a déjà poussé, à chaque tour, et ne relit le
    /// journal que s'il a avancé.
    #[must_use]
    pub fn derniere_operation(&self) -> u64 {
        self.derniere_operation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Commet cette écriture, et prévient si une opération est entrée dans le
    /// journal — sous l'estampille que [`journaliser_l_operation`] a rendue.
    ///
    /// **Tout ce qui peut journaliser passe par ici**, et rien d'autre : le
    /// journal des requêtes (C18), le curseur, le compteur hissé n'ajoutent
    /// aucune opération, et prévenir pour eux ferait relire le journal pour
    /// rien. Une écriture de provenance distante non plus : elle est
    /// estampillée, pas journalisée, et `None` le dit.
    fn commettre_une_operation(
        &self,
        ecriture: WriteTransaction,
        journalisee: Option<Estampille>,
    ) -> Result<(), Faute> {
        ecriture.commit()?;
        if let Some(estampille) = journalisee {
            self.derniere_operation
                .fetch_max(estampille.compteur, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }

    /// La racine pour laquelle cet entrepôt écrit.
    #[must_use]
    pub const fn racine(&self) -> Identifiant {
        self.racine
    }

    // ── Le compteur ─────────────────────────────────────────────────────────

    /// Le compteur de la racine : l'estampille de sa dernière écriture, ou le
    /// plus haut qu'elle ait reçu.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn compteur(&self) -> Result<u64, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(RACINE)?;
        Ok(table.get(CLEF_DU_COMPTEUR)?.map_or(0, |quoi| quoi.value()))
    }

    /// Hisse le compteur au-dessus de ce qu'on a reçu.
    ///
    /// **C'est l'horloge de Lamport** (`docs/replication.md` §4) : quand la
    /// racine applique une opération estampillée `h`, son compteur devient
    /// `max(compteur, h)`. Il ne recule jamais — un compteur qui reculerait
    /// réémettrait des estampilles déjà vues, que l'autre refuserait comme un
    /// rejeu (§5.4).
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn hisser_le_compteur(&self, jusqu_a: u64) -> Result<(), Faute> {
        let ecriture = self.base.begin_write()?;
        {
            let mut table = ecriture.open_table(RACINE)?;
            let courant = table.get(CLEF_DU_COMPTEUR)?.map_or(0, |quoi| quoi.value());
            if jusqu_a > courant {
                table.insert(CLEF_DU_COMPTEUR, jusqu_a)?;
            }
        }
        ecriture.commit()?;
        Ok(())
    }

    // ── Les comptes ─────────────────────────────────────────────────────────

    /// Crée ce compte, avec cet alias s'il en réclame un d'emblée.
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si le compte existe, [`Faute::AliasPris`] si l'alias
    /// est tenu par un autre, [`Faute::Base`] si la base refuse.
    pub fn creer_compte(
        &self,
        qui: Identifiant,
        provenance: Provenance,
        alias: Option<AliasRange>,
    ) -> Result<(), Faute> {
        let clef_compte = clef(qui);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let mut comptes = ecriture.open_table(COMPTES)?;
            let mut reclamations = ecriture.open_table(ALIAS)?;
            if comptes.get(clef_compte.as_slice())?.is_some() {
                return Err(Faute::Existe);
            }
            if let Some(voulu) = &alias
                && titulaire(&reclamations, voulu.octets())?.is_some()
            {
                return Err(Faute::AliasPris);
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let compte = Compte {
                provenance,
                estampille,
                alias,
                reclamation: estampille,
                efface: None,
            };
            let mut octets = [0_u8; COMPTE_OCTETS];
            compte.ecrire(&mut octets);
            comptes.insert(clef_compte.as_slice(), &octets)?;
            if let Some(voulu) = &alias {
                reclamations.insert(
                    clef_de_reclamation(voulu.octets(), estampille).as_slice(),
                    clef_compte.as_slice(),
                )?;
            }
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                provenance,
                &Operation::Compte {
                    compte: qui,
                    enregistrement: compte,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Réclame cet alias pour ce compte — ou le lâche, avec `None`.
    ///
    /// # LES DEUX VERBES SONT LA MÊME ÉCRITURE
    ///
    /// `PUT` et `DELETE /v1/alias` sont une réclamation courante qui change ;
    /// l'index suit le compte dans la même transaction, l'ancienne réclamation
    /// part, la nouvelle entre. **Réclamer ce qu'on tient déjà ne change
    /// rien**, et surtout pas l'estampille : la plus ancienne réclamation
    /// tient (`replication.md` §3.2), et la rafraîchir ferait perdre un alias
    /// qu'on gagnait.
    ///
    /// Rend `false` si le compte n'existe pas — **ou s'il est effacé** : un
    /// compte effacé ne réclame plus rien, et toute écriture pour lui est
    /// refusée (`docs/modele.md` §2.1).
    ///
    /// # Errors
    ///
    /// [`Faute::AliasPris`] si l'alias est tenu par un autre, [`Faute::Base`]
    /// ou [`Faute::Enregistrement`].
    pub fn reclamer_alias(
        &self,
        qui: Identifiant,
        alias: Option<AliasRange>,
    ) -> Result<bool, Faute> {
        let clef_compte = clef(qui);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let mut comptes = ecriture.open_table(COMPTES)?;
            let mut reclamations = ecriture.open_table(ALIAS)?;
            let ancien = match comptes.get(clef_compte.as_slice())? {
                Some(brut) => Compte::lire(brut.value())?,
                None => return Ok(false),
            };
            if ancien.est_efface() {
                return Ok(false);
            }
            if ancien.alias == alias {
                return Ok(true);
            }
            if let Some(voulu) = &alias
                && let Some(tenu_par) = titulaire(&reclamations, voulu.octets())?
                && tenu_par != qui
            {
                return Err(Faute::AliasPris);
            }
            if let Some(parti) = &ancien.alias {
                reclamations
                    .remove(clef_de_reclamation(parti.octets(), ancien.reclamation).as_slice())?;
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let compte = Compte {
                estampille,
                alias,
                reclamation: estampille,
                ..ancien
            };
            let mut octets = [0_u8; COMPTE_OCTETS];
            compte.ecrire(&mut octets);
            comptes.insert(clef_compte.as_slice(), &octets)?;
            if let Some(voulu) = &alias {
                reclamations.insert(
                    clef_de_reclamation(voulu.octets(), estampille).as_slice(),
                    clef_compte.as_slice(),
                )?;
            }
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                compte.provenance,
                &Operation::Alias { compte: qui, alias },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(true)
    }

    /// Rend ce compte, s'il existe — **effacé compris**, marqué.
    ///
    /// C'est la lecture de l'entrepôt, pas celle de l'API : `GET
    /// /v1/utilisateurs/{u}` passe par [`Entrepot::compte_vivant`], qui ne
    /// rend pas un compte effacé. Celle-ci sert à qui doit VOIR la marque —
    /// `--forget`, qui dit « déjà effacé » plutôt que d'écrire.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn compte(&self, qui: Identifiant) -> Result<Option<Compte>, Faute> {
        let lecture = self.base.begin_read()?;
        let comptes = lecture.open_table(COMPTES)?;
        match comptes.get(clef(qui).as_slice())? {
            Some(trouve) => Ok(Some(Compte::lire(trouve.value())?)),
            None => Ok(None),
        }
    }

    /// Rend ce compte s'il existe **et n'est pas effacé**.
    ///
    /// **Un compte effacé est un inconnu pour l'API** (`protocole.md` §2.2) :
    /// `GET /v1/utilisateurs/{u}` rend le même `404` qu'un identifiant qui n'a
    /// jamais existé, et une autorisation ne s'accorde pas à lui. L'existence
    /// passée d'un compte n'est pas une information qu'on rend à qui tient un
    /// `u-…` au hasard.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn compte_vivant(&self, qui: Identifiant) -> Result<Option<Compte>, Faute> {
        Ok(self.compte(qui)?.filter(|compte| !compte.est_efface()))
    }

    /// À qui appartient cet alias ?
    ///
    /// **C'est tout ce que l'alias rend**, et c'est écrit dans les
    /// spécifications : un identifiant, jamais un profil. Le titulaire est la
    /// plus ancienne réclamation courante (voir [`ALIAS`]).
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Longueur`] si l'index est corrompu.
    pub fn compte_par_alias(&self, alias: &str) -> Result<Option<Identifiant>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(ALIAS)?;
        titulaire(&table, alias.as_bytes())
    }

    // ── L'effacement d'un compte (`docs/modele.md` §2.1) ────────────────────

    /// Efface ce compte : tout ce qu'il tient part, dans UNE transaction, et
    /// reste l'identifiant marqué effacé, avec la date et la cause.
    ///
    /// # CE QUI PART, ET C'EST TOUT
    ///
    /// Les appareils, avec leurs jetons et leurs descriptions ; les machines,
    /// avec leur clé, leurs codes d'enrôlement en cours et leurs services ;
    /// les autorisations, accordées ET reçues — effacées, non marquées :
    /// l'autre partie ne doit plus rien voir ; la réclamation d'alias, que la
    /// file hérite. La marque prend l'estampille de l'effacement, et la
    /// réclamation aussi — c'est `DELETE /v1/alias`, en plus large.
    ///
    /// **La date vient de l'appelant**, comme pour une révocation ; **la cause
    /// aussi** : le titulaire depuis son appareil, la racine par la règle des
    /// orphelins, l'exploitant hors ligne — un seul chemin d'entrepôt pour les
    /// trois (`protocole.md` §2.2). L'opération `compte-efface` est
    /// journalisée pour l'autre racine, une seule pour tout le compte
    /// (`replication.md` §5.2).
    ///
    /// Rend `None` si le compte n'existe pas, [`Efface::Deja`] s'il l'était
    /// déjà — sans rien écrire : un effacement ne se refait pas.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn effacer_compte(
        &self,
        qui: Identifiant,
        cause: Cause,
        efface_le: u64,
    ) -> Result<Option<Efface>, Faute> {
        let ecriture = self.base.begin_write()?;
        let journalisee;
        let retrait;
        {
            let avant = match compte_dans(&ecriture, qui)? {
                Some(compte) => compte,
                None => return Ok(None),
            };
            if let Some(marque) = avant.efface {
                return Ok(Some(Efface::Deja(marque)));
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let marque = Effacement {
                le: efface_le,
                cause,
            };
            retrait = effacer_dans(&ecriture, qui, avant.provenance, marque, estampille)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                avant.provenance,
                &Operation::CompteEfface {
                    compte: qui,
                    efface_le,
                    cause,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(Some(Efface::Fait(retrait)))
    }

    /// Efface les comptes orphelins — ceux dont TOUS les appareils sont
    /// révoqués, le plus récent avant `revoques_avant` —, avec la cause
    /// `orphelin`, à cette date, dans UNE transaction ; et rend lesquels,
    /// avec ce que chacun a retiré.
    ///
    /// # LA RÈGLE, ET CE QU'ELLE NE COMPTE PAS (`docs/modele.md` §2.1, C6)
    ///
    /// Un compte est orphelin depuis le `révoqué le` le plus récent de ses
    /// appareils, **jamais depuis leur silence** : un téléphone dans un tiroir
    /// est un appareil vivant. Un compte sans aucun appareil enregistré n'est
    /// pas orphelin non plus — il n'a pas de date d'où compter, et ce peut
    /// être un compte dont l'appareil arrive par la voie. Un compte déjà
    /// effacé ne l'est pas deux fois.
    ///
    /// **Chaque racine peut** : l'opération est de la classe « révocation,
    /// toujours », et la seconde ne trouve rien à retirer (`replication.md`
    /// §5.2). Une opération `compte-efface` par compte est journalisée.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn effacer_les_orphelins(
        &self,
        revoques_avant: u64,
        efface_le: u64,
    ) -> Result<Vec<(Identifiant, Retrait)>, Faute> {
        let ecriture = self.base.begin_write()?;
        let mut effaces = Vec::new();
        let mut derniere = None;
        {
            // Relevés avant d'être effacés : on n'écrit pas dans une table
            // qu'on parcourt.
            let mut orphelins = Vec::new();
            {
                let comptes = ecriture.open_table(COMPTES)?;
                let index = ecriture.open_table(APPAREILS_PAR_COMPTE)?;
                let appareils = ecriture.open_table(APPAREILS)?;
                for entree in comptes.iter()? {
                    let (clef_compte, valeur) = entree?;
                    let compte = Compte::lire(valeur.value())?;
                    if compte.est_efface() {
                        continue;
                    }
                    let qui = depuis_clef(clef_compte.value())?;
                    let (debut, fin) = intervalle(qui);
                    let mut dernier_revoque: Option<u64> = None;
                    let mut tous_revoques = true;
                    for entree in index.range(debut.as_slice()..fin.as_slice())? {
                        let (_, clef_appareil) = entree?;
                        let Some(brut) = appareils.get(clef_appareil.value())? else {
                            continue;
                        };
                        match Appareil::lire(brut.value())?.revoque_le {
                            Some(quand) => {
                                dernier_revoque =
                                    Some(dernier_revoque.map_or(quand, |d| d.max(quand)));
                            }
                            None => {
                                tous_revoques = false;
                                break;
                            }
                        }
                    }
                    if tous_revoques && dernier_revoque.is_some_and(|quand| quand < revoques_avant)
                    {
                        orphelins.push((qui, compte.provenance));
                    }
                }
            }
            for (qui, provenance) in orphelins {
                let estampille = estampiller(&ecriture, self.racine)?;
                let cause = Cause::Orphelin;
                let marque = Effacement {
                    le: efface_le,
                    cause,
                };
                let retrait = effacer_dans(&ecriture, qui, provenance, marque, estampille)?;
                if let Some(journalisee) = journaliser_l_operation(
                    &ecriture,
                    estampille,
                    provenance,
                    &Operation::CompteEfface {
                        compte: qui,
                        efface_le,
                        cause,
                    },
                )? {
                    derniere = Some(journalisee);
                }
                effaces.push((qui, retrait));
            }
        }
        self.commettre_une_operation(ecriture, derniere)?;
        Ok(effaces)
    }

    // ── Les machines ────────────────────────────────────────────────────────

    /// Déclare cette machine, sans clé : la clé arrivera avec le code.
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si la machine existe, [`Faute::Base`] si la base
    /// refuse.
    pub fn creer_machine(
        &self,
        quelle: Identifiant,
        provenance: Provenance,
        proprietaire: Identifiant,
        nom: NomRange,
        capacites: Capacites,
    ) -> Result<(), Faute> {
        let clef_machine = clef(quelle);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let mut machines = ecriture.open_table(MACHINES)?;
            if machines.get(clef_machine.as_slice())?.is_some() {
                return Err(Faute::Existe);
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let machine = Machine {
                provenance,
                estampille,
                proprietaire,
                cle: None,
                annonce: capacites.annonce,
                lecture: capacites.lecture,
                capacites_estampille: estampille,
                nom,
                nom_estampille: estampille,
            };
            let mut octets = [0_u8; MACHINE_OCTETS];
            machine.ecrire(&mut octets);
            machines.insert(clef_machine.as_slice(), &octets)?;
            // **LE PROPRIÉTAIRE NE CHANGE JAMAIS** : une machine qu'on
            // réécrirait pour un autre compte serait une autre machine. Il n'y a
            // donc jamais d'ancienne entrée d'index à retirer.
            let mut par_compte = ecriture.open_table(MACHINES_PAR_COMPTE)?;
            par_compte.insert(
                paire(proprietaire, quelle).as_slice(),
                clef_machine.as_slice(),
            )?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                provenance,
                &Operation::Machine {
                    machine: quelle,
                    enregistrement: machine,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Change le nom ou les capacités de cette machine, et rend ce qu'elle
    /// était.
    ///
    /// **Champ par champ** : le nom reçoit son estampille s'il est donné, les
    /// capacités la leur si elles le sont — c'est ce que la règle de
    /// `replication.md` §3.2 compare, champ par champ. Rien de donné, rien
    /// d'écrit, et pas d'opération.
    ///
    /// Rend `None` si aucune machine ne répond à cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn modifier_machine(
        &self,
        quelle: Identifiant,
        nom: Option<NomRange>,
        capacites: Option<Capacites>,
    ) -> Result<Option<Machine>, Faute> {
        let clef_machine = clef(quelle);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        let avant;
        {
            let mut machines = ecriture.open_table(MACHINES)?;
            avant = match machines.get(clef_machine.as_slice())? {
                Some(brut) => Machine::lire(brut.value())?,
                None => return Ok(None),
            };
            if nom.is_none() && capacites.is_none() {
                return Ok(Some(avant));
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let mut apres = Machine {
                estampille,
                ..avant
            };
            if let Some(nom) = nom {
                apres.nom = nom;
                apres.nom_estampille = estampille;
            }
            if let Some(capacites) = capacites {
                apres.annonce = capacites.annonce;
                apres.lecture = capacites.lecture;
                apres.capacites_estampille = estampille;
            }
            let mut octets = [0_u8; MACHINE_OCTETS];
            apres.ecrire(&mut octets);
            machines.insert(clef_machine.as_slice(), &octets)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                avant.provenance,
                &Operation::MachineModifiee {
                    machine: quelle,
                    nom,
                    capacites,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(Some(avant))
    }

    /// Lie cette clé à cette machine, par le code de cette empreinte, et rend
    /// ce qu'elle était.
    ///
    /// # LE CODE A DÉJÀ ÉTÉ CONSOMMÉ, ET C'EST VOULU
    ///
    /// [`Entrepot::consommer_enrolement`] l'a retiré, et l'étage 2 a décidé
    /// entre les deux — un code expiré est consommé sans lier. L'opération
    /// `cle-machine` porte l'empreinte pour que l'autre racine retire le code
    /// de son côté, et l'estampille d'émission du code pour la règle de
    /// `replication.md` §3.2 : le code le plus récemment émis gagne, puis la
    /// première consommation.
    ///
    /// Rend `None` si aucune machine ne répond à cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn lier_cle(
        &self,
        quelle: Identifiant,
        cle: [u8; CLE_OCTETS],
        empreinte: [u8; EMPREINTE_OCTETS],
        code: Estampille,
    ) -> Result<Option<Machine>, Faute> {
        let clef_machine = clef(quelle);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        let avant;
        {
            let mut machines = ecriture.open_table(MACHINES)?;
            avant = match machines.get(clef_machine.as_slice())? {
                Some(brut) => Machine::lire(brut.value())?,
                None => return Ok(None),
            };
            let estampille = estampiller(&ecriture, self.racine)?;
            let apres = Machine {
                estampille,
                cle: Some(CleLiee {
                    cle,
                    liaison: estampille,
                    code,
                }),
                ..avant
            };
            let mut octets = [0_u8; MACHINE_OCTETS];
            apres.ecrire(&mut octets);
            machines.insert(clef_machine.as_slice(), &octets)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                avant.provenance,
                &Operation::CleMachine {
                    machine: quelle,
                    cle,
                    empreinte,
                    code,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(Some(avant))
    }

    /// Retire la clé de cette machine, et rend ce qu'elle était.
    ///
    /// **LA CLÉ S'EFFACE, LA MACHINE RESTE.** Elle garde son nom, ses
    /// capacités et ses services ; ce qu'elle perd est le moyen de prouver
    /// qu'elle est elle. Sans clé, il n'y a rien à retirer, et pas d'opération.
    ///
    /// Rend `None` si aucune machine ne répond à cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn revoquer_cle(&self, quelle: Identifiant) -> Result<Option<Machine>, Faute> {
        let clef_machine = clef(quelle);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        let avant;
        {
            let mut machines = ecriture.open_table(MACHINES)?;
            avant = match machines.get(clef_machine.as_slice())? {
                Some(brut) => Machine::lire(brut.value())?,
                None => return Ok(None),
            };
            let Some(liee) = avant.cle else {
                return Ok(Some(avant));
            };
            let estampille = estampiller(&ecriture, self.racine)?;
            let apres = Machine {
                estampille,
                cle: None,
                ..avant
            };
            let mut octets = [0_u8; MACHINE_OCTETS];
            apres.ecrire(&mut octets);
            machines.insert(clef_machine.as_slice(), &octets)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                avant.provenance,
                &Operation::CleMachineRevoquee {
                    machine: quelle,
                    cle: liee.cle,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(Some(avant))
    }

    /// Rend cette machine, si elle existe.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn machine(&self, quelle: Identifiant) -> Result<Option<Machine>, Faute> {
        let lecture = self.base.begin_read()?;
        let machines = lecture.open_table(MACHINES)?;
        match machines.get(clef(quelle).as_slice())? {
            Some(trouve) => Ok(Some(Machine::lire(trouve.value())?)),
            None => Ok(None),
        }
    }

    /// Les machines d'un compte, avec leur identifiant.
    ///
    /// **UN INTERVALLE, ET NON UN BALAYAGE** — voir [`MACHINES_PAR_COMPTE`].
    ///
    /// # Errors
    ///
    /// [`Faute::Base`], [`Faute::Enregistrement`].
    pub fn machines_de_compte(
        &self,
        compte: Identifiant,
    ) -> Result<Vec<(Identifiant, Machine)>, Faute> {
        let lecture = self.base.begin_read()?;
        let index = lecture.open_table(MACHINES_PAR_COMPTE)?;
        let table = lecture.open_table(MACHINES)?;

        let (debut, fin) = intervalle(compte);
        let mut trouvees = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, valeur) = entree?;
            let quelle = depuis_clef(valeur.value())?;
            if let Some(brute) = table.get(valeur.value())? {
                trouvees.push((quelle, Machine::lire(brute.value())?));
            }
        }
        Ok(trouvees)
    }

    // ── Les appareils ───────────────────────────────────────────────────────

    /// Enrôle cet appareil.
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si l'appareil existe, [`Faute::Base`] si la base
    /// refuse.
    pub fn creer_appareil(
        &self,
        quel: Identifiant,
        provenance: Provenance,
        proprietaire: Identifiant,
        cle: [u8; CLE_APPAREIL_OCTETS],
        atteste: Attestation,
    ) -> Result<(), Faute> {
        let clef_appareil = clef(quel);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let mut table = ecriture.open_table(APPAREILS)?;
            if table.get(clef_appareil.as_slice())?.is_some() {
                return Err(Faute::Existe);
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let appareil = Appareil {
                provenance,
                estampille,
                proprietaire,
                cle,
                atteste,
                revoque_le: None,
            };
            let mut octets = [0_u8; APPAREIL_OCTETS];
            appareil.ecrire(&mut octets);
            table.insert(clef_appareil.as_slice(), &octets)?;
            let mut par_compte = ecriture.open_table(APPAREILS_PAR_COMPTE)?;
            par_compte.insert(
                paire(proprietaire, quel).as_slice(),
                clef_appareil.as_slice(),
            )?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                provenance,
                &Operation::Appareil {
                    appareil: quel,
                    enregistrement: appareil,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Cet appareil, s'il existe.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn appareil(&self, quel: Identifiant) -> Result<Option<Appareil>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(APPAREILS)?;
        match table.get(clef(quel).as_slice())? {
            Some(brut) => Ok(Some(Appareil::lire(brut.value())?)),
            None => Ok(None),
        }
    }

    /// Les appareils d'un compte, révoqués compris, avec leur identifiant et
    /// ce que chacun a dit de lui-même — `None` tant qu'il ne l'a pas fait.
    ///
    /// **La description se lit dans la même transaction** : c'est l'écran Compte
    /// qui demande, et il montre les deux ensemble.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`], [`Faute::Enregistrement`].
    pub fn appareils_de_compte(
        &self,
        compte: Identifiant,
    ) -> Result<Vec<(Identifiant, Appareil, Option<Description>)>, Faute> {
        let lecture = self.base.begin_read()?;
        let index = lecture.open_table(APPAREILS_PAR_COMPTE)?;
        let table = lecture.open_table(APPAREILS)?;
        let descriptions = lecture.open_table(DESCRIPTIONS)?;

        let (debut, fin) = intervalle(compte);
        let mut trouves = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, valeur) = entree?;
            let quel = depuis_clef(valeur.value())?;
            if let Some(brut) = table.get(valeur.value())? {
                let description = match descriptions.get(valeur.value())? {
                    Some(brute) => Some(Description::lire(brute.value())?),
                    None => None,
                };
                trouves.push((quel, Appareil::lire(brut.value())?, description));
            }
        }
        Ok(trouves)
    }

    /// Marque cet appareil révoqué à cette date, et rend ce qu'il était.
    ///
    /// **LE JETON PART AVEC L'APPAREIL, ET DANS LA MÊME ÉCRITURE.**
    /// `docs/modele.md` §2.6 : il est lié à l'appareil et se révoque avec lui.
    /// L'appareil, lui, reste marqué : l'écran d'après une perte doit MONTRER
    /// ce qu'on a retiré. **La description reste** aussi, pour la même raison.
    ///
    /// **La date vient de l'appelant**, en millisecondes d'époque, comme
    /// l'expiration d'un code : c'est la boucle qui tient l'horloge, et un
    /// essai qui fabrique un appareil révoqué depuis trente et un jours n'a
    /// pas à attendre. Elle se pose UNE fois : un appareil déjà révoqué garde
    /// la sienne, et rien n'est écrit ni journalisé — c'est de cette date que
    /// la règle des orphelins compte (`docs/modele.md` §2.1).
    ///
    /// Rend `None` si aucun appareil ne répond à cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn revoquer_appareil(
        &self,
        quel: Identifiant,
        revoque_le: u64,
    ) -> Result<Option<Appareil>, Faute> {
        let clef_appareil = clef(quel);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        let avant;
        {
            let mut table = ecriture.open_table(APPAREILS)?;
            avant = match table.get(clef_appareil.as_slice())? {
                Some(brut) => Appareil::lire(brut.value())?,
                None => return Ok(None),
            };
            if avant.revoque() {
                return Ok(Some(avant));
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let mut octets = [0_u8; APPAREIL_OCTETS];
            Appareil {
                estampille,
                revoque_le: Some(revoque_le),
                ..avant
            }
            .ecrire(&mut octets);
            table.insert(clef_appareil.as_slice(), &octets)?;
            let mut poussees = ecriture.open_table(POUSSEES)?;
            poussees.remove(clef_appareil.as_slice())?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                avant.provenance,
                &Operation::AppareilRevoque {
                    appareil: quel,
                    revoque_le,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(Some(avant))
    }

    /// Pose l'attestation d'un appareil qui a rejoint, et rend ce qu'il était.
    ///
    /// **UNE VALEUR PROUVÉE, SUR UN APPAREIL QUI NE L'EST PAS ENCORE**
    /// (`docs/replication.md` §5.2, `appareil-atteste`, 2026-09-21) : `aucune`
    /// ou `attendue` deviennent `apple` ou `android` ; un appareil déjà prouvé
    /// garde sa valeur, et rien n'est écrit ni journalisé — une clé ne
    /// s'atteste qu'une fois. C'est l'appelant qui a vérifié la chaîne, et
    /// qui a refusé un appareil révoqué ou un compte effacé : ici, on range.
    ///
    /// Rend `None` si aucun appareil ne répond à cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`] — celle-ci aussi quand la
    /// valeur n'est pas une preuve : l'opération ne se relirait pas, et ce
    /// que le fil refuserait ne s'écrit pas non plus.
    pub fn attester_appareil(
        &self,
        quel: Identifiant,
        atteste: Attestation,
    ) -> Result<Option<Appareil>, Faute> {
        if !atteste.prouvee() {
            return Err(Faute::Enregistrement(asl_registre::Faute::Etiquette {
                lue: atteste.etiquette(),
            }));
        }
        let clef_appareil = clef(quel);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        let avant;
        {
            let mut table = ecriture.open_table(APPAREILS)?;
            avant = match table.get(clef_appareil.as_slice())? {
                Some(brut) => Appareil::lire(brut.value())?,
                None => return Ok(None),
            };
            if avant.atteste.prouvee() {
                return Ok(Some(avant));
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let mut octets = [0_u8; APPAREIL_OCTETS];
            Appareil {
                estampille,
                atteste,
                ..avant
            }
            .ecrire(&mut octets);
            table.insert(clef_appareil.as_slice(), &octets)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                avant.provenance,
                &Operation::AppareilAtteste {
                    appareil: quel,
                    atteste,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(Some(avant))
    }

    // ── Les jetons de poussée ───────────────────────────────────────────────

    /// Dépose ou renouvelle le jeton de cet appareil.
    ///
    /// **UN SEUL JETON PAR APPAREIL, ET LE NEUF REMPLACE L'ANCIEN.** Apple et
    /// Google font tourner les leurs : en garder deux ferait envoyer chaque
    /// notification en double, dont une à un jeton mort.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_jeton(
        &self,
        appareil: Identifiant,
        provenance: Provenance,
        plateforme: Plateforme,
        jeton: JetonRange,
    ) -> Result<(), Faute> {
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let estampille = estampiller(&ecriture, self.racine)?;
            let poussee = JetonPoussee {
                provenance,
                estampille,
                plateforme,
                jeton,
            };
            let mut octets = [0_u8; POUSSEE_OCTETS];
            poussee.ecrire(&mut octets);
            let mut table = ecriture.open_table(POUSSEES)?;
            table.insert(clef(appareil).as_slice(), &octets)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                provenance,
                &Operation::Poussee {
                    appareil,
                    enregistrement: poussee,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Le jeton de cet appareil, s'il en a déposé un.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn jeton(&self, appareil: Identifiant) -> Result<Option<JetonPoussee>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(POUSSEES)?;
        match table.get(clef(appareil).as_slice())? {
            Some(brut) => Ok(Some(JetonPoussee::lire(brut.value())?)),
            None => Ok(None),
        }
    }

    // ── Les descriptions d'appareil ─────────────────────────────────────────

    /// Pose ou remplace ce que cet appareil dit de lui-même.
    ///
    /// **UNE SEULE PAR APPAREIL, ET LA NEUVE REMPLACE L'ANCIENNE** : un système
    /// mis à jour, un téléphone restauré sur un autre modèle — l'appareil se
    /// redécrit, et l'écran montre ce qu'il est aujourd'hui.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_description(
        &self,
        appareil: Identifiant,
        provenance: Provenance,
        systeme: Systeme,
        modele: NomRange,
    ) -> Result<(), Faute> {
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let estampille = estampiller(&ecriture, self.racine)?;
            let description = Description {
                provenance,
                estampille,
                systeme,
                modele,
            };
            let mut octets = [0_u8; DESCRIPTION_OCTETS];
            description.ecrire(&mut octets);
            let mut table = ecriture.open_table(DESCRIPTIONS)?;
            table.insert(clef(appareil).as_slice(), &octets)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                provenance,
                &Operation::Description {
                    appareil,
                    enregistrement: description,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Ce que cet appareil a dit de lui-même, s'il l'a fait.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn description(&self, appareil: Identifiant) -> Result<Option<Description>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(DESCRIPTIONS)?;
        match table.get(clef(appareil).as_slice())? {
            Some(brut) => Ok(Some(Description::lire(brut.value())?)),
            None => Ok(None),
        }
    }

    // ── Les codes d'enrôlement ──────────────────────────────────────────────

    /// Émet un code pour cette machine, **et retire celui qu'elle avait**.
    ///
    /// **LE PRÉCÉDENT MEURT AVEC L'ÉMISSION DU SUIVANT**, et dans la même
    /// transaction : un administrateur qui redemande un code parce qu'il a
    /// perdu le premier ne doit pas laisser derrière lui un secret vivant que
    /// plus personne ne surveille. C'est aussi la règle de l'opération
    /// `enrolement` chez l'autre racine : le code courant est le plus récent.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn emettre_enrolement(
        &self,
        empreinte: &[u8; EMPREINTE_OCTETS],
        provenance: Provenance,
        machine: Identifiant,
        expire_a: u64,
    ) -> Result<(), Faute> {
        let clef_machine = clef(machine);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let mut codes = ecriture.open_table(ENROLEMENTS)?;
            let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
            if let Some(ancienne) = index.get(clef_machine.as_slice())? {
                codes.remove(ancienne.value())?;
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let enrolement = Enrolement {
                provenance,
                estampille,
                machine,
                expire_a,
            };
            let mut octets = [0_u8; ENROLEMENT_OCTETS];
            enrolement.ecrire(&mut octets);
            codes.insert(empreinte.as_slice(), &octets)?;
            index.insert(clef_machine.as_slice(), empreinte.as_slice())?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                provenance,
                &Operation::Enrolement {
                    empreinte: *empreinte,
                    enregistrement: enrolement,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Consomme le code de cette empreinte, et rend ce qu'il désignait.
    ///
    /// # LIRE ET EFFACER SONT UNE SEULE TRANSACTION
    ///
    /// « À usage unique » ne se tient pas en deux temps : deux enrôlements
    /// simultanés avec le même code liraient tous deux un code vivant, et le
    /// second effacerait ce que le premier avait déjà consommé.
    ///
    /// # AUCUNE OPÉRATION, ET C'EST LA SPÉCIFICATION
    ///
    /// `replication.md` §5.2 : un code disparaît consommé par `cle-machine`,
    /// qui porte son empreinte, ou expiré par chaque racine à sa propre
    /// horloge, sans opération. La consommation seule — celle d'un code
    /// expiré, que l'étage 2 refuse ensuite — ne se réplique pas : l'autre
    /// racine l'expirera elle-même.
    ///
    /// Rend `None` si rien ne répond à cette empreinte — un code inconnu et un
    /// code déjà consommé sont **le même fait**.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn consommer_enrolement(&self, empreinte: &[u8]) -> Result<Option<Enrolement>, Faute> {
        let ecriture = self.base.begin_write()?;
        let trouve;
        {
            let mut codes = ecriture.open_table(ENROLEMENTS)?;
            let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
            trouve = match codes.remove(empreinte)? {
                Some(brut) => Some(Enrolement::lire(brut.value())?),
                None => None,
            };
            if let Some(enrolement) = &trouve {
                index.remove(clef(enrolement.machine).as_slice())?;
            }
        }
        ecriture.commit()?;
        Ok(trouve)
    }

    /// Efface les codes dont la date est passée, et rend combien.
    ///
    /// **Un code expiré est refusé de toute façon** — c'est
    /// `asl_auth::decider_enrolement` qui le dit. Ce balayage ne change donc
    /// aucune décision : il empêche seulement une table de secrets morts de
    /// grandir sans fin. Sans opération : chaque racine expire à sa propre
    /// horloge.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn expirer_les_enrolements(&self, avant: u64) -> Result<usize, Faute> {
        let ecriture = self.base.begin_write()?;
        let combien;
        {
            let mut codes = ecriture.open_table(ENROLEMENTS)?;
            let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
            let mut condamnes = Vec::new();
            for entree in codes.iter()? {
                let (empreinte, valeur) = entree?;
                let enrolement = Enrolement::lire(valeur.value())?;
                if enrolement.expire_a < avant {
                    condamnes.push((empreinte.value().to_vec(), enrolement.machine));
                }
            }
            for (empreinte, machine) in &condamnes {
                codes.remove(empreinte.as_slice())?;
                index.remove(clef(*machine).as_slice())?;
            }
            combien = condamnes.len();
        }
        ecriture.commit()?;
        Ok(combien)
    }

    // ── Les services ────────────────────────────────────────────────────────

    /// Déclare ce service sur cette machine, sous ce nom.
    ///
    /// **Un service ne bouge jamais et ne se retire jamais** (`replication.md`
    /// §3.2) : il n'y a pas de renommage, et `(machine, nom)` est unique.
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si le service existe, ou si un autre tient déjà ce
    /// nom sur cette machine ; [`Faute::Base`] si la base refuse.
    pub fn declarer_service(
        &self,
        quel: Identifiant,
        provenance: Provenance,
        machine: Identifiant,
        nom: NomRange,
    ) -> Result<(), Faute> {
        let clef_service = clef(quel);
        let clef_nom = clef_de_nom(machine, nom.octets());
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let mut services = ecriture.open_table(SERVICES)?;
            let mut par_nom = ecriture.open_table(SERVICES_PAR_NOM)?;
            if services.get(clef_service.as_slice())?.is_some()
                || par_nom.get(clef_nom.as_slice())?.is_some()
            {
                return Err(Faute::Existe);
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let service = Service {
                provenance,
                estampille,
                machine,
                nom,
            };
            let mut octets = [0_u8; SERVICE_OCTETS];
            service.ecrire(&mut octets);
            services.insert(clef_service.as_slice(), &octets)?;
            par_nom.insert(clef_nom.as_slice(), clef_service.as_slice())?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                provenance,
                &Operation::Service {
                    service: quel,
                    enregistrement: service,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Rend ce service, s'il existe.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn service(&self, quel: Identifiant) -> Result<Option<Service>, Faute> {
        let lecture = self.base.begin_read()?;
        let services = lecture.open_table(SERVICES)?;
        match services.get(clef(quel).as_slice())? {
            Some(trouve) => Ok(Some(Service::lire(trouve.value())?)),
            None => Ok(None),
        }
    }

    /// Quel service cette machine sert-elle sous ce nom ?
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Longueur`] si l'index est corrompu.
    pub fn service_par_nom(
        &self,
        machine: Identifiant,
        nom: &str,
    ) -> Result<Option<Identifiant>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(SERVICES_PAR_NOM)?;
        match table.get(clef_de_nom(machine, nom.as_bytes()).as_slice())? {
            Some(trouve) => depuis_clef(trouve.value()).map(Some),
            None => Ok(None),
        }
    }

    /// Les services d'une machine, avec leur identifiant.
    ///
    /// **UN INTERVALLE, ET NON UN BALAYAGE** : [`SERVICES_PAR_NOM`] range la
    /// machine en tête, précisément pour que « tous les services de cette
    /// machine » en soit un.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`], [`Faute::Enregistrement`].
    pub fn services_de_machine(
        &self,
        machine: Identifiant,
    ) -> Result<Vec<(Identifiant, Service)>, Faute> {
        let lecture = self.base.begin_read()?;
        let index = lecture.open_table(SERVICES_PAR_NOM)?;
        let table = lecture.open_table(SERVICES)?;

        let (debut, fin) = intervalle(machine);
        let mut trouves = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, valeur) = entree?;
            let quel = depuis_clef(valeur.value())?;
            if let Some(brut) = table.get(valeur.value())? {
                trouves.push((quel, Service::lire(brut.value())?));
            }
        }
        Ok(trouves)
    }

    // ── Les autorisations ───────────────────────────────────────────────────

    /// Accorde cette autorisation, et l'indexe dans les deux sens.
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si l'autorisation existe, [`Faute::Base`] si la base
    /// refuse.
    pub fn accorder_autorisation(
        &self,
        quelle: Identifiant,
        provenance: Provenance,
        par: Identifiant,
        a: Identifiant,
        portee: Portee,
        etiquette: NomRange,
    ) -> Result<(), Faute> {
        let clef_autorisation = clef(quelle);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        {
            let mut table = ecriture.open_table(AUTORISATIONS)?;
            if table.get(clef_autorisation.as_slice())?.is_some() {
                return Err(Faute::Existe);
            }
            let estampille = estampiller(&ecriture, self.racine)?;
            let autorisation = Autorisation {
                provenance,
                estampille,
                par,
                a,
                portee,
                revoquee: false,
                etiquette,
            };
            let mut octets = [0_u8; AUTORISATION_OCTETS];
            autorisation.ecrire(&mut octets);
            table.insert(clef_autorisation.as_slice(), &octets)?;
            // **NI LE BÉNÉFICIAIRE NI LE DONNEUR NE CHANGENT JAMAIS** : une
            // autorisation qu'on réécrirait pour d'autres comptes serait une
            // autre autorisation. Il n'y a donc jamais d'ancienne entrée d'index
            // à retirer.
            let mut recues = ecriture.open_table(AUTORISATIONS_RECUES)?;
            recues.insert(paire(a, quelle).as_slice(), clef_autorisation.as_slice())?;
            let mut accordees = ecriture.open_table(AUTORISATIONS_ACCORDEES)?;
            accordees.insert(paire(par, quelle).as_slice(), clef_autorisation.as_slice())?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                provenance,
                &Operation::Autorisation {
                    autorisation: quelle,
                    enregistrement: autorisation,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Cette autorisation, si elle existe.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn autorisation(&self, quelle: Identifiant) -> Result<Option<Autorisation>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(AUTORISATIONS)?;
        match table.get(clef(quelle).as_slice())? {
            Some(brut) => Ok(Some(Autorisation::lire(brut.value())?)),
            None => Ok(None),
        }
    }

    /// Marque cette autorisation révoquée, et rend ce qu'elle était.
    ///
    /// # ELLE RESTE, ET NE VAUT PLUS
    ///
    /// La supprimer marcherait — `couvre` ne la trouverait plus. **Mais
    /// l'utilisateur doit pouvoir voir ce qu'il a retiré** : `GET
    /// /v1/autorisations` rend les deux sens, et une ligne disparue ne dit pas
    /// qu'on a repris un droit. C'est `asl_auth::Autorisation::couvre` qui
    /// l'écarte, et à un seul endroit. **Les index ne bougent pas**, pour la
    /// même raison.
    ///
    /// Rend `None` si aucune autorisation ne répond à cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn revoquer_autorisation(
        &self,
        quelle: Identifiant,
    ) -> Result<Option<Autorisation>, Faute> {
        let clef_autorisation = clef(quelle);
        let ecriture = self.base.begin_write()?;
        let journalisee;
        let avant;
        {
            let mut table = ecriture.open_table(AUTORISATIONS)?;
            avant = match table.get(clef_autorisation.as_slice())? {
                Some(brut) => Autorisation::lire(brut.value())?,
                None => return Ok(None),
            };
            let estampille = estampiller(&ecriture, self.racine)?;
            let mut octets = [0_u8; AUTORISATION_OCTETS];
            Autorisation {
                estampille,
                revoquee: true,
                ..avant
            }
            .ecrire(&mut octets);
            table.insert(clef_autorisation.as_slice(), &octets)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                avant.provenance,
                &Operation::AutorisationRevoquee {
                    autorisation: quelle,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(Some(avant))
    }

    /// Toutes les autorisations reçues par ce compte.
    ///
    /// **RÉVOQUÉES COMPRISES** : c'est `asl_auth::Autorisation::couvre` qui les
    /// écarte, et le faire ici cacherait à l'utilisateur ce qu'il a retiré.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn autorisations_recues(&self, par: Identifiant) -> Result<Vec<Autorisation>, Faute> {
        Ok(self
            .autorisations_par(AUTORISATIONS_RECUES, par)?
            .into_iter()
            .map(|(_, autorisation)| autorisation)
            .collect())
    }

    /// Les autorisations qu'un compte a REÇUES, avec leur identifiant.
    ///
    /// **Une liste doit pouvoir se désigner** — c'est l'identifiant qu'on passe
    /// à `DELETE /v1/autorisations/{g}`.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`], [`Faute::Enregistrement`].
    pub fn autorisations_recues_nommees(
        &self,
        a: Identifiant,
    ) -> Result<Vec<(Identifiant, Autorisation)>, Faute> {
        self.autorisations_par(AUTORISATIONS_RECUES, a)
    }

    /// Les autorisations qu'un compte a ACCORDÉES, avec leur identifiant.
    ///
    /// **RÉVOQUÉES COMPRISES** : `protocole.md` §2.2 veut que l'écran montre ce
    /// qu'on a retiré.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`], [`Faute::Enregistrement`].
    pub fn autorisations_accordees(
        &self,
        par: Identifiant,
    ) -> Result<Vec<(Identifiant, Autorisation)>, Faute> {
        self.autorisations_par(AUTORISATIONS_ACCORDEES, par)
    }

    /// Le corps commun des deux sens.
    ///
    /// **ÉCRIT UNE FOIS, EMPLOYÉ DEUX** : deux copies de ce parcours finiraient
    /// par diverger, et c'est celle qu'on oublie de corriger qui rendrait un sens
    /// faux.
    fn autorisations_par(
        &self,
        index: TableDefinition<'_, &[u8], &[u8]>,
        compte: Identifiant,
    ) -> Result<Vec<(Identifiant, Autorisation)>, Faute> {
        let lecture = self.base.begin_read()?;
        let index = lecture.open_table(index)?;
        let table = lecture.open_table(AUTORISATIONS)?;

        let (debut, fin) = intervalle(compte);
        let mut trouvees = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, valeur) = entree?;
            let quelle = depuis_clef(valeur.value())?;
            if let Some(brute) = table.get(valeur.value())? {
                trouvees.push((quelle, Autorisation::lire(brute.value())?));
            }
        }
        Ok(trouvees)
    }

    // ── Le journal (C18) ────────────────────────────────────────────────────

    /// Journalise cette requête.
    ///
    /// # DEUX ENTRÉES DE LA MÊME MILLISECONDE NE SE CONFONDENT PAS
    ///
    /// Un rang monotone départage les clés. Sans lui, la seconde écraserait la
    /// première — et **le journal perdrait des faits sous charge**, c'est-à-dire
    /// exactement quand il compte. Le rang est rangé DANS la même transaction
    /// que l'entrée : deux écritures concurrentes ne peuvent pas obtenir le même.
    ///
    /// **Pas d'estampille, pas d'opération** : le journal ne se réplique pas
    /// (`replication.md` §1). Il dit ce que CETTE racine a servi.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn journaliser(&self, entree: &EntreeJournal) -> Result<(), Faute> {
        let ecriture = self.base.begin_write()?;
        {
            let mut rangs = ecriture.open_table(RANG)?;
            let suivant = rangs
                .get(CLEF_DU_RANG)?
                .map_or(0, |quoi| quoi.value())
                .saturating_add(1);
            rangs.insert(CLEF_DU_RANG, suivant)?;

            let mut octets = [0_u8; ENTREE_OCTETS];
            entree.ecrire(&mut octets);
            let mut journal = ecriture.open_table(JOURNAL)?;
            journal.insert(entree.clef(suivant).as_slice(), &octets)?;
        }
        ecriture.commit()?;
        Ok(())
    }

    /// Efface tout ce qui précède cet instant, et rend combien (C18).
    ///
    /// # C'EST UNE SUPPRESSION PAR INTERVALLE, ET C'EST POURQUOI ELLE TIENT
    ///
    /// La clé d'une entrée commence par son horodatage en GROS-BOUTISTE :
    /// l'ordre des octets est donc l'ordre du temps, et « tout ce qui précède
    /// quatre-vingt-dix jours » est un intervalle de clés.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn expirer_le_journal(&self, avant: u64) -> Result<usize, Faute> {
        let borne = borne_de_temps(avant);
        let ecriture = self.base.begin_write()?;
        let combien;
        {
            let mut journal = ecriture.open_table(JOURNAL)?;
            // On relève les clés avant d'effacer : effacer en parcourant
            // demanderait de tenir un emprunt mutable pendant une itération.
            let mut condamnees = Vec::new();
            for entree in journal.range(..borne.as_slice())? {
                let (clef, _) = entree?;
                condamnees.push(clef.value().to_vec());
            }
            combien = condamnees.len();
            for clef in &condamnees {
                journal.remove(clef.as_slice())?;
            }
        }
        ecriture.commit()?;
        Ok(combien)
    }

    /// Combien d'entrées le journal porte.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn entrees_du_journal(&self) -> Result<u64, Faute> {
        let lecture = self.base.begin_read()?;
        let journal = lecture.open_table(JOURNAL)?;
        Ok(journal.len()?)
    }

    // ── Le journal d'opérations (`replication.md` §5) ───────────────────────

    /// Tout ce que cette racine a écrit après ce compteur, dans l'ordre.
    ///
    /// **C'est `GET /v1/pair/operations?apres=…`**, moins le « sans fin » : ce
    /// qui suit s'obtient en redemandant depuis le dernier compteur reçu, et
    /// c'est à la voie de tenir la connexion. Un journal qui ne remonte plus
    /// jusqu'à `apres` rend [`Rattrapage::HorsJournal`] — le `410` de §5.4 —,
    /// et c'est le cas de toute base reprise (§11.4), dont le journal démarre
    /// vide au-dessus de ses enregistrements.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn operations_apres(&self, apres: u64) -> Result<Rattrapage, Faute> {
        let lecture = self.base.begin_read()?;
        let retirees_jusqu_a = lecture
            .open_table(RACINE)?
            .get(CLEF_DES_RETIREES)?
            .map_or(0, |quoi| quoi.value());
        if apres < retirees_jusqu_a {
            return Ok(Rattrapage::HorsJournal { retirees_jusqu_a });
        }
        let table = lecture.open_table(OPERATIONS)?;
        let mut cadres = Vec::new();
        for entree in table.range(apres.saturating_add(1)..)? {
            let (_, valeur) = entree?;
            cadres.push(valeur.value().get(8..).unwrap_or_default().to_vec());
        }
        Ok(Rattrapage::Operations(cadres))
    }

    /// L'état entier, en suite d'opérations, puis le cadre de fin.
    ///
    /// **C'est `GET /v1/pair/instantane`** (`docs/replication.md` §5.4) : une
    /// seule transaction de lecture, et pour chaque enregistrement les
    /// opérations qui le reconstituent — **avec LEURS estampilles**, celles de
    /// l'écriture d'origine, qui peuvent être de l'une ou l'autre racine. Puis
    /// [`Cadre::Fin`], qui porte le compteur auquel l'instantané a été coupé :
    /// c'est là que le tireur reprend `GET /v1/pair/operations`.
    ///
    /// # CE QUI SORT POUR CHAQUE ENREGISTREMENT, ET SOUS QUELLE ESTAMPILLE
    ///
    /// Un instantané s'applique avec les règles de §5.2, donc il FUSIONNE : ce
    /// qui a une règle « le plus récent gagne » doit sortir sous l'estampille
    /// du champ, et non sous celle de l'enregistrement.
    ///
    /// | Enregistrement | Ce qui sort |
    /// |---|---|
    /// | Compte | `compte` sous l'estampille du compte, puis `alias` sous celle de sa réclamation courante — même sans alias : lâcher est une réclamation aussi. |
    /// | Machine | `machine` **sans clé** sous l'estampille de la machine ; `machine-modifiee` pour le nom et les capacités, une opération par estampille distincte ; `cle-machine` sous l'estampille de la liaison, si une clé est liée. |
    /// | Appareil | `appareil` sous son estampille, puis `appareil-revoque` s'il l'est. |
    /// | Description, jeton | `description`, `poussee`, sous leur estampille. |
    /// | Code d'enrôlement | `enrolement` sous son estampille — les expirés partent d'eux-mêmes. |
    /// | Service, autorisation | `service` ; `autorisation`, puis `autorisation-revoquee` si elle l'est. |
    ///
    /// **L'empreinte du code d'une `cle-machine` d'instantané est nulle** : le
    /// code a été consommé, il n'existe plus nulle part, et l'opération dit
    /// « supprimer le code s'il est là » — il n'y sera pas. L'estampille
    /// d'émission, elle, est gardée avec la clé, et c'est elle que la règle
    /// de §3.2 compare.
    ///
    /// # C11 : SEULE LA PROVENANCE LOCALE SORT
    ///
    /// Ce qu'une racine aura un jour reçu d'un annuaire rattaché n'est pas à
    /// elle, et ne passe pas — comme dans le journal (§7).
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn instantane(&self) -> Result<Vec<Vec<u8>>, Faute> {
        let lecture = self.base.begin_read()?;
        let mut suite = Suite::default();

        let comptes = lecture.open_table(COMPTES)?;
        for entree in comptes.iter()? {
            let (clef, valeur) = entree?;
            let compte = Compte::lire(valeur.value())?;
            if compte.provenance != Provenance::Ici {
                continue;
            }
            let qui = depuis_clef(clef.value())?;
            // **UN COMPTE EFFACÉ FIGURE PAR SA MARQUE, ET PAR ELLE SEULE**
            // (`replication.md` §5.2) : une opération `compte-efface`, et rien
            // de ce qu'il tenait — l'autre racine, en l'appliquant, retire ce
            // qu'elle en avait.
            if let Some(marque) = compte.efface {
                suite.ajouter(
                    compte.estampille,
                    &Operation::CompteEfface {
                        compte: qui,
                        efface_le: marque.le,
                        cause: marque.cause,
                    },
                );
                continue;
            }
            suite.ajouter(
                compte.estampille,
                &Operation::Compte {
                    compte: qui,
                    enregistrement: compte,
                },
            );
            suite.ajouter(
                compte.reclamation,
                &Operation::Alias {
                    compte: qui,
                    alias: compte.alias,
                },
            );
        }

        let machines = lecture.open_table(MACHINES)?;
        for entree in machines.iter()? {
            let (clef, valeur) = entree?;
            let machine = Machine::lire(valeur.value())?;
            if machine.provenance != Provenance::Ici {
                continue;
            }
            let quelle = depuis_clef(clef.value())?;
            suite.ajouter(
                machine.estampille,
                &Operation::Machine {
                    machine: quelle,
                    enregistrement: Machine {
                        cle: None,
                        ..machine
                    },
                },
            );
            // **CHAMP PAR CHAMP** : une opération par estampille distincte, et
            // les deux champs dans la même quand elles se confondent — c'est
            // ce qu'un `PATCH` des deux aurait écrit.
            if machine.nom_estampille == machine.capacites_estampille {
                suite.ajouter(
                    machine.nom_estampille,
                    &Operation::MachineModifiee {
                        machine: quelle,
                        nom: Some(machine.nom),
                        capacites: Some(machine.capacites()),
                    },
                );
            } else {
                suite.ajouter(
                    machine.nom_estampille,
                    &Operation::MachineModifiee {
                        machine: quelle,
                        nom: Some(machine.nom),
                        capacites: None,
                    },
                );
                suite.ajouter(
                    machine.capacites_estampille,
                    &Operation::MachineModifiee {
                        machine: quelle,
                        nom: None,
                        capacites: Some(machine.capacites()),
                    },
                );
            }
            if let Some(liee) = machine.cle {
                suite.ajouter(
                    liee.liaison,
                    &Operation::CleMachine {
                        machine: quelle,
                        cle: liee.cle,
                        empreinte: [0; EMPREINTE_OCTETS],
                        code: liee.code,
                    },
                );
            }
        }

        let appareils = lecture.open_table(APPAREILS)?;
        for entree in appareils.iter()? {
            let (clef, valeur) = entree?;
            let appareil = Appareil::lire(valeur.value())?;
            if appareil.provenance != Provenance::Ici {
                continue;
            }
            let quel = depuis_clef(clef.value())?;
            suite.ajouter(
                appareil.estampille,
                &Operation::Appareil {
                    appareil: quel,
                    enregistrement: appareil,
                },
            );
            if let Some(revoque_le) = appareil.revoque_le {
                suite.ajouter(
                    appareil.estampille,
                    &Operation::AppareilRevoque {
                        appareil: quel,
                        revoque_le,
                    },
                );
            }
            // **L'ATTESTATION VOYAGE À PART, COMME LA RÉVOCATION** : l'autre
            // racine tient peut-être déjà cet appareil `attendue` — apporté
            // chez elle, prouvé ici —, et `appareil` n'insère que si absent.
            // Un appareil entré prouvé à sa création la reçoit aussi ; elle
            // n'y change rien.
            if appareil.atteste.prouvee() {
                suite.ajouter(
                    appareil.estampille,
                    &Operation::AppareilAtteste {
                        appareil: quel,
                        atteste: appareil.atteste,
                    },
                );
            }
        }

        let descriptions = lecture.open_table(DESCRIPTIONS)?;
        for entree in descriptions.iter()? {
            let (clef, valeur) = entree?;
            let description = Description::lire(valeur.value())?;
            if description.provenance != Provenance::Ici {
                continue;
            }
            suite.ajouter(
                description.estampille,
                &Operation::Description {
                    appareil: depuis_clef(clef.value())?,
                    enregistrement: description,
                },
            );
        }

        let poussees = lecture.open_table(POUSSEES)?;
        for entree in poussees.iter()? {
            let (clef, valeur) = entree?;
            let poussee = JetonPoussee::lire(valeur.value())?;
            if poussee.provenance != Provenance::Ici {
                continue;
            }
            suite.ajouter(
                poussee.estampille,
                &Operation::Poussee {
                    appareil: depuis_clef(clef.value())?,
                    enregistrement: poussee,
                },
            );
        }

        let codes = lecture.open_table(ENROLEMENTS)?;
        for entree in codes.iter()? {
            let (empreinte, valeur) = entree?;
            let enrolement = Enrolement::lire(valeur.value())?;
            if enrolement.provenance != Provenance::Ici {
                continue;
            }
            let mut octets = [0_u8; EMPREINTE_OCTETS];
            for (place, octet) in octets.iter_mut().zip(empreinte.value().iter()) {
                *place = *octet;
            }
            suite.ajouter(
                enrolement.estampille,
                &Operation::Enrolement {
                    empreinte: octets,
                    enregistrement: enrolement,
                },
            );
        }

        let services = lecture.open_table(SERVICES)?;
        for entree in services.iter()? {
            let (clef, valeur) = entree?;
            let service = Service::lire(valeur.value())?;
            if service.provenance != Provenance::Ici {
                continue;
            }
            suite.ajouter(
                service.estampille,
                &Operation::Service {
                    service: depuis_clef(clef.value())?,
                    enregistrement: service,
                },
            );
        }

        let autorisations = lecture.open_table(AUTORISATIONS)?;
        for entree in autorisations.iter()? {
            let (clef, valeur) = entree?;
            let autorisation = Autorisation::lire(valeur.value())?;
            if autorisation.provenance != Provenance::Ici {
                continue;
            }
            let quelle = depuis_clef(clef.value())?;
            suite.ajouter(
                autorisation.estampille,
                &Operation::Autorisation {
                    autorisation: quelle,
                    enregistrement: autorisation,
                },
            );
            if autorisation.revoquee {
                suite.ajouter(
                    autorisation.estampille,
                    &Operation::AutorisationRevoquee {
                        autorisation: quelle,
                    },
                );
            }
        }

        // **LE COMPTEUR DE COUPE EST LU DANS LA MÊME TRANSACTION** : tout ce
        // qui a été écrit jusqu'à lui est dans l'instantané, et tout ce qui
        // suivra sera dans le journal après lui.
        let coupe = lecture
            .open_table(RACINE)?
            .get(CLEF_DU_COMPTEUR)?
            .map_or(0, |quoi| quoi.value());
        suite.finir(Estampille {
            compteur: coupe,
            racine: self.racine,
        });
        Ok(suite.cadres)
    }

    /// Retire du journal d'opérations ce qui a été écrit avant cet instant, et
    /// rend combien.
    ///
    /// **Le compteur et l'instant avancent ensemble** — les deux sont
    /// monotones sur les écritures locales —, donc ce qui expire est un
    /// préfixe du journal, et le dernier compteur retiré est ce en deçà de quoi
    /// un rattrapage n'est plus possible.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn expirer_les_operations(&self, avant: u64) -> Result<usize, Faute> {
        let ecriture = self.base.begin_write()?;
        let combien;
        {
            let mut table = ecriture.open_table(OPERATIONS)?;
            let mut condamnees = Vec::new();
            for entree in table.iter()? {
                let (compteur, valeur) = entree?;
                let mut quand = [0_u8; 8];
                for (place, octet) in quand.iter_mut().zip(valeur.value().iter()) {
                    *place = *octet;
                }
                if u64::from_be_bytes(quand) >= avant {
                    break;
                }
                condamnees.push(compteur.value());
            }
            for compteur in &condamnees {
                table.remove(*compteur)?;
            }
            combien = condamnees.len();
            if let Some(derniere) = condamnees.last() {
                let mut racine = ecriture.open_table(RACINE)?;
                let deja = racine
                    .get(CLEF_DES_RETIREES)?
                    .map_or(0, |quoi| quoi.value());
                racine.insert(CLEF_DES_RETIREES, deja.max(*derniere))?;
            }
        }
        ecriture.commit()?;
        Ok(combien)
    }

    /// Combien d'opérations le journal garde.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn operations_gardees(&self) -> Result<u64, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(OPERATIONS)?;
        Ok(table.len()?)
    }

    // ── Le curseur par pair ─────────────────────────────────────────────────

    /// Ce que cette racine a appliqué de ce pair : le compteur de la dernière
    /// opération, ou zéro si aucune.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn curseur(&self, pair: Identifiant) -> Result<u64, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(CURSEURS)?;
        Ok(table
            .get(clef(pair).as_slice())?
            .map_or(0, |quoi| quoi.value()))
    }

    /// Avance le curseur de ce pair.
    ///
    /// **Il ne recule jamais** : « le tireur refuse ce qui recule »
    /// (`replication.md` §5.3), et un curseur qu'on ferait reculer relivrerait
    /// des opérations déjà appliquées. Ici, un compteur plus bas que le courant
    /// est ignoré. L'application des opérations l'avancera dans SA
    /// transaction ; ce verbe-ci est ce qu'elle appellera.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_curseur(&self, pair: Identifiant, compteur: u64) -> Result<(), Faute> {
        let ecriture = self.base.begin_write()?;
        {
            let mut table = ecriture.open_table(CURSEURS)?;
            let courant = table
                .get(clef(pair).as_slice())?
                .map_or(0, |quoi| quoi.value());
            if compteur > courant {
                table.insert(clef(pair).as_slice(), compteur)?;
            }
        }
        ecriture.commit()?;
        Ok(())
    }

    // ── L'application d'une opération reçue (`docs/replication.md` §3, §5.3) ─

    /// Applique un cadre venu de ce pair, et dit ce qu'il faut fermer ici.
    ///
    /// # TOUT SE PASSE DANS UNE SEULE TRANSACTION
    ///
    /// `docs/replication.md` §5.3 : « le tireur applique chaque opération et
    /// avance son curseur dans la même transaction ». C'est ce qui rend la
    /// relivraison sans effet — une coupure entre les deux relivre l'opération,
    /// et la règle d'application est idempotente. La transaction, ici :
    ///
    /// 1. **vérifie la provenance** — C11 ne laisse passer que `locale` (§7) ;
    /// 2. **vérifie l'estampille** — refuse ce qui recule (relivraison,
    ///    idempotente) ou porte NOTRE propre identifiant de racine (rejeu) ;
    /// 3. **applique la règle de conflit** de §3.2 pour le genre ;
    /// 4. **écrit SANS journaliser** — l'écriture distante ne repart pas (§5.1) ;
    /// 5. **hisse le compteur** au-dessus de l'estampille (§4) ;
    /// 6. **avance le curseur** du pair.
    ///
    /// # DEUX MODES, ET LA DIFFÉRENCE EST L'ANTI-REJEU
    ///
    /// `instantane` distingue le flux des opérations de l'amorçage (§5.4). Le
    /// flux ne porte que ce que le pair a écrit LUI-MÊME, donc jamais notre
    /// identifiant ni un compteur qui recule ; on refuse l'un et l'autre.
    /// L'instantané, lui, rend les estampilles d'ORIGINE — « de l'une ou l'autre
    /// racine » —, y compris les nôtres d'avant une perte, que l'on doit
    /// réappliquer pour reconstruire ; on ne refuse alors ni le rejeu ni le
    /// recul, et le curseur ne bouge qu'au cadre de fin.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn appliquer(
        &self,
        pair: Identifiant,
        cadre: &Cadre,
        instantane: bool,
    ) -> Result<Applique, Faute> {
        self.appliquer_la_suite(pair, core::slice::from_ref(cadre), instantane)
            .map(|mut faites| {
                faites
                    .pop()
                    .unwrap_or(Applique::Refusee(MotifDeRefus::Recule))
            })
    }

    /// Applique ces cadres, dans l'ordre, **dans UNE transaction** — et rend ce
    /// que chacun a donné, dans le même ordre.
    ///
    /// # UN LOT EST LE GRAIN DE L'ATOMICITÉ, ET C'EST LE MÊME INVARIANT
    ///
    /// [`Entrepot::appliquer`] tient « l'opération et le curseur dans la même
    /// transaction » un cadre à la fois. Ici, ce sont `n` cadres et le curseur
    /// au dernier appliqué, atomiquement : une coupure entre les deux relivre
    /// le lot entier, et la règle d'application est idempotente. Ce qui change
    /// est le coût — **une transaction par lot, et non par cadre**, donc un
    /// `fsync` pour ce qu'un tour de boucle a reçu plutôt qu'un par
    /// opération. Un instantané de quelques milliers d'enregistrements
    /// s'applique en secondes au lieu de minutes.
    ///
    /// Un cadre refusé (rejeu, provenance, recul) ne fait pas échouer le lot :
    /// il est rendu [`Applique::Refusee`] à son rang, et les suivants
    /// s'appliquent. Une faute de l'entrepôt, elle, annule tout le lot.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn appliquer_la_suite(
        &self,
        pair: Identifiant,
        cadres: &[Cadre],
        instantane: bool,
    ) -> Result<Vec<Applique>, Faute> {
        let ecriture = self.base.begin_write()?;
        let mut faites = Vec::with_capacity(cadres.len());
        {
            // Le curseur tel qu'il est DANS la transaction : un cadre du lot
            // le fait avancer pour le suivant.
            let mut curseur = ecriture
                .open_table(CURSEURS)?
                .get(clef(pair).as_slice())?
                .map_or(0, |quoi| quoi.value());
            for cadre in cadres {
                let (estampille, operation) = match cadre {
                    // Le cadre de fin d'un instantané : le curseur reprend à
                    // la coupe, et le compteur se hisse au-dessus d'elle.
                    Cadre::Fin { coupe } => {
                        hisser_dans(&ecriture, coupe.compteur)?;
                        avancer_le_curseur(&ecriture, pair, coupe.compteur)?;
                        curseur = curseur.max(coupe.compteur);
                        faites.push(Applique::Fin {
                            curseur: coupe.compteur,
                        });
                        continue;
                    }
                    Cadre::Operation {
                        estampille,
                        operation,
                    } => (*estampille, operation),
                };

                // 1. La provenance : C11 ne laisse passer que `locale` entre
                //    racines.
                if provenance_de(operation).is_some_and(|quoi| quoi != Provenance::Ici) {
                    faites.push(Applique::Refusee(MotifDeRefus::HorsProvenance));
                    continue;
                }
                // 2. L'estampille — mais l'instantané rend les estampilles
                //    d'origine, y compris les nôtres, et ne recule pas au sens
                //    du curseur.
                if !instantane {
                    if estampille.racine == self.racine {
                        faites.push(Applique::Refusee(MotifDeRefus::Rejeu));
                        continue;
                    }
                    if estampille.compteur <= curseur {
                        faites.push(Applique::Refusee(MotifDeRefus::Recule));
                        continue;
                    }
                }

                let mut effets = EffetsVivants::default();
                appliquer_dans(&ecriture, estampille, operation, &mut effets)?;
                // 5. Le compteur se hisse au-dessus de l'estampille appliquée
                //    (§4).
                hisser_dans(&ecriture, estampille.compteur)?;
                // 6. Le curseur avance — mais pas pendant un instantané, où
                //    c'est le cadre de fin qui le pose (à la coupe).
                if !instantane {
                    avancer_le_curseur(&ecriture, pair, estampille.compteur)?;
                    curseur = estampille.compteur;
                }
                faites.push(Applique::Faite {
                    curseur: if instantane { 0 } else { estampille.compteur },
                    effets,
                });
            }
        }
        ecriture.commit()?;
        Ok(faites)
    }

    // ── La rupture de confiance (C17) ───────────────────────────────────────

    /// Efface tout ce qui vient de cet annuaire, et rend combien.
    ///
    /// # LE JOURNAL N'EST PAS TOUCHÉ, ET C'EST UNE EXCEPTION ÉCRITE
    ///
    /// C17 dit « rompre une relation efface ce qui en vient — **sauf le
    /// journal** ». La raison est en tête de `docs/journal.md` : ce journal a
    /// une fonction DÉFENSIVE. L'effacer avec la relation effacerait la preuve
    /// de ce qui a motivé la rupture.
    ///
    /// **Ni le journal d'opérations** : il ne contient que ce que cette racine
    /// a écrit elle-même, de provenance locale, donc rien de ce qui vient de
    /// l'annuaire qu'on cesse de croire. Et rompre la réplication entre
    /// racines n'efface rien (`replication.md` §7) — ce qui est répliqué entre
    /// elles est de provenance locale, et ne passe pas par ici.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn oublier_ce_qui_vient_de(&self, annuaire: Identifiant) -> Result<usize, Faute> {
        let ecriture = self.base.begin_write()?;
        let mut combien = 0_usize;
        {
            let mut comptes = ecriture.open_table(COMPTES)?;
            let mut reclamations = ecriture.open_table(ALIAS)?;
            let mut condamnes = Vec::new();
            for entree in comptes.iter()? {
                let (clef, valeur) = entree?;
                let compte = Compte::lire(valeur.value())?;
                if compte.provenance.vient_de(annuaire) {
                    condamnes.push((clef.value().to_vec(), compte));
                }
            }
            for (clef, compte) in &condamnes {
                comptes.remove(clef.as_slice())?;
                // **LA RÉCLAMATION PART AVEC LE COMPTE.** Un alias resté seul
                // rendrait l'identifiant d'un compte qui n'existe plus.
                if let Some(nom) = &compte.alias {
                    reclamations
                        .remove(clef_de_reclamation(nom.octets(), compte.reclamation).as_slice())?;
                }
            }
            combien = combien.saturating_add(condamnes.len());

            let mut machines = ecriture.open_table(MACHINES)?;
            let mut par_compte = ecriture.open_table(MACHINES_PAR_COMPTE)?;
            let mut condamnees = Vec::new();
            for entree in machines.iter()? {
                let (clef, valeur) = entree?;
                let machine = Machine::lire(valeur.value())?;
                if machine.provenance.vient_de(annuaire) {
                    condamnees.push((
                        clef.value().to_vec(),
                        paire(machine.proprietaire, depuis_clef(clef.value())?),
                    ));
                }
            }
            for (clef, clef_index) in &condamnees {
                machines.remove(clef.as_slice())?;
                par_compte.remove(clef_index.as_slice())?;
            }
            combien = combien.saturating_add(condamnees.len());

            let mut services = ecriture.open_table(SERVICES)?;
            let mut par_nom = ecriture.open_table(SERVICES_PAR_NOM)?;
            let mut condamnes_services = Vec::new();
            for entree in services.iter()? {
                let (clef, valeur) = entree?;
                let service = Service::lire(valeur.value())?;
                if service.provenance.vient_de(annuaire) {
                    condamnes_services.push((
                        clef.value().to_vec(),
                        clef_de_nom(service.machine, service.nom.octets()),
                    ));
                }
            }
            for (clef_service, clef_nom) in &condamnes_services {
                services.remove(clef_service.as_slice())?;
                par_nom.remove(clef_nom.as_slice())?;
            }
            combien = combien.saturating_add(condamnes_services.len());

            let mut autorisations = ecriture.open_table(AUTORISATIONS)?;
            let mut recues = ecriture.open_table(AUTORISATIONS_RECUES)?;
            let mut accordees = ecriture.open_table(AUTORISATIONS_ACCORDEES)?;
            let mut condamnees_aretes = Vec::new();
            for entree in autorisations.iter()? {
                let (clef_brute, valeur) = entree?;
                let autorisation = Autorisation::lire(valeur.value())?;
                if autorisation.provenance.vient_de(annuaire) {
                    let quelle = depuis_clef(clef_brute.value())?;
                    condamnees_aretes.push((
                        clef_brute.value().to_vec(),
                        paire(autorisation.a, quelle),
                        paire(autorisation.par, quelle),
                    ));
                }
            }
            for (clef_autorisation, clef_recue, clef_accordee) in &condamnees_aretes {
                autorisations.remove(clef_autorisation.as_slice())?;
                recues.remove(clef_recue.as_slice())?;
                accordees.remove(clef_accordee.as_slice())?;
            }
            combien = combien.saturating_add(condamnees_aretes.len());

            // Un appareil ne vient jamais d'ailleurs aujourd'hui — il n'y a rien
            // à fédérer dans un téléphone. **Il porte sa provenance quand
            // même** : un champ qu'on omet parce qu'on croit savoir qu'il
            // vaudra toujours la même chose est un champ qu'on ajoutera trop
            // tard.
            let mut appareils = ecriture.open_table(APPAREILS)?;
            let mut appareils_par_compte = ecriture.open_table(APPAREILS_PAR_COMPTE)?;
            let mut poussees = ecriture.open_table(POUSSEES)?;
            let mut condamnes_appareils = Vec::new();
            for entree in appareils.iter()? {
                let (clef, valeur) = entree?;
                let appareil = Appareil::lire(valeur.value())?;
                if appareil.provenance.vient_de(annuaire) {
                    condamnes_appareils.push((
                        clef.value().to_vec(),
                        paire(appareil.proprietaire, depuis_clef(clef.value())?),
                    ));
                }
            }
            for (clef, clef_index) in &condamnes_appareils {
                appareils.remove(clef.as_slice())?;
                appareils_par_compte.remove(clef_index.as_slice())?;
                poussees.remove(clef.as_slice())?;
            }
            combien = combien.saturating_add(condamnes_appareils.len());

            let mut descriptions = ecriture.open_table(DESCRIPTIONS)?;
            let mut condamnees_descriptions = Vec::new();
            for entree in descriptions.iter()? {
                let (clef, valeur) = entree?;
                let description = Description::lire(valeur.value())?;
                if description.provenance.vient_de(annuaire) {
                    condamnees_descriptions.push(clef.value().to_vec());
                }
            }
            for clef in &condamnees_descriptions {
                descriptions.remove(clef.as_slice())?;
            }
            combien = combien.saturating_add(condamnees_descriptions.len());

            let mut codes = ecriture.open_table(ENROLEMENTS)?;
            let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
            let mut condamnes_codes = Vec::new();
            for entree in codes.iter()? {
                let (empreinte, valeur) = entree?;
                let enrolement = Enrolement::lire(valeur.value())?;
                if enrolement.provenance.vient_de(annuaire) {
                    condamnes_codes.push((empreinte.value().to_vec(), enrolement.machine));
                }
            }
            for (empreinte, machine) in &condamnes_codes {
                codes.remove(empreinte.as_slice())?;
                index.remove(clef(*machine).as_slice())?;
            }
            combien = combien.saturating_add(condamnes_codes.len());
        }
        ecriture.commit()?;
        Ok(combien)
    }
}

// ── L'application d'une opération, cas par cas (`docs/replication.md` §3.2) ──
//
// Ces fonctions vivent HORS de l'`impl` parce qu'elles écrivent dans une
// transaction qu'on leur prête, et ne touchent au compteur ni au curseur : la
// méthode [`Entrepot::appliquer`] les encadre.

/// Hisse le compteur de la racine au-dessus de ce compteur, dans cette
/// transaction (`docs/replication.md` §4).
fn hisser_dans(ecriture: &WriteTransaction, jusqu_a: u64) -> Result<(), Faute> {
    let mut table = ecriture.open_table(RACINE)?;
    let courant = table.get(CLEF_DU_COMPTEUR)?.map_or(0, |quoi| quoi.value());
    if jusqu_a > courant {
        table.insert(CLEF_DU_COMPTEUR, jusqu_a)?;
    }
    Ok(())
}

/// Avance le curseur de ce pair, dans cette transaction — jamais en arrière.
fn avancer_le_curseur(
    ecriture: &WriteTransaction,
    pair: Identifiant,
    compteur: u64,
) -> Result<(), Faute> {
    let mut table = ecriture.open_table(CURSEURS)?;
    let courant = table
        .get(clef(pair).as_slice())?
        .map_or(0, |quoi| quoi.value());
    if compteur > courant {
        table.insert(clef(pair).as_slice(), compteur)?;
    }
    Ok(())
}

/// Ce compte, tel qu'il est dans cette transaction — effacé compris.
fn compte_dans(ecriture: &WriteTransaction, qui: Identifiant) -> Result<Option<Compte>, Faute> {
    let comptes = ecriture.open_table(COMPTES)?;
    match comptes.get(clef(qui).as_slice())? {
        Some(brut) => Ok(Some(Compte::lire(brut.value())?)),
        None => Ok(None),
    }
}

/// Ce compte est-il marqué effacé, dans cette transaction ?
///
/// **C'est la garde de toute règle d'application qui écrit pour un compte**
/// (`docs/replication.md` §3.2) : une écriture du compte arrivée après son
/// effacement est refusée — le compte est effacé —, et le curseur avance. Un
/// compte ABSENT n'est pas effacé : son opération `compte` viendra peut-être
/// après celle de son appareil, et l'effacement, s'il vient, retirera les deux.
fn compte_efface_dans(ecriture: &WriteTransaction, qui: Identifiant) -> Result<bool, Faute> {
    Ok(compte_dans(ecriture, qui)?.is_some_and(|compte| compte.est_efface()))
}

/// Efface ce compte dans cette transaction : tout ce qu'il tient part, et
/// reste l'identifiant marqué, sous cette estampille. Rend ce qui est parti.
///
/// # C'EST LE SEUL CHEMIN, POUR LES TROIS CAUSES ET POUR L'AUTRE RACINE
///
/// `DELETE /v1/compte`, la règle des orphelins, `--forget` et l'application
/// de `compte-efface` passent tous ici (`protocole.md` §2.2). C'est le balayage
/// par compte que [`Entrepot::oublier_ce_qui_vient_de`] fait déjà par origine
/// — mais par les INDEX, pas par un parcours des tables : les appareils, les
/// machines et les autorisations d'un compte sont des intervalles.
///
/// **Le compte absent est marqué quand même** (`replication.md` §5.2) : ce
/// qui arriverait ensuite pour lui — son `compte`, un appareil — est refusé,
/// et les index sont balayés au cas où une écriture serait arrivée avant lui.
///
/// **La marque prend l'estampille qu'on lui donne, et non le maximum** : c'est
/// ce qui rend l'entrepôt identique dans les deux ordres — une écriture du
/// compte appliquée avant l'effacement a été retirée, appliquée après elle est
/// refusée, et l'estampille du compte est dans les deux cas celle de
/// l'effacement.
fn effacer_dans(
    ecriture: &WriteTransaction,
    qui: Identifiant,
    provenance: Provenance,
    marque: Effacement,
    estampille: Estampille,
) -> Result<Retrait, Faute> {
    let clef_compte = clef(qui);
    let mut retrait = Retrait::default();

    // ── LES APPAREILS : effacés, avec leur jeton et leur description ────────
    {
        let mut index = ecriture.open_table(APPAREILS_PAR_COMPTE)?;
        let mut appareils = ecriture.open_table(APPAREILS)?;
        let mut poussees = ecriture.open_table(POUSSEES)?;
        let mut descriptions = ecriture.open_table(DESCRIPTIONS)?;
        let (debut, fin) = intervalle(qui);
        let mut condamnes = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (clef_index, clef_appareil) = entree?;
            condamnes.push((clef_index.value().to_vec(), clef_appareil.value().to_vec()));
        }
        for (clef_index, clef_appareil) in &condamnes {
            index.remove(clef_index.as_slice())?;
            appareils.remove(clef_appareil.as_slice())?;
            poussees.remove(clef_appareil.as_slice())?;
            descriptions.remove(clef_appareil.as_slice())?;
            retrait.a_fermer.push(depuis_clef(clef_appareil)?);
        }
        retrait.appareils = condamnes.len();
    }

    // ── LES MACHINES : effacées, avec leur clé, leurs codes, leurs services ─
    {
        let mut index = ecriture.open_table(MACHINES_PAR_COMPTE)?;
        let mut machines = ecriture.open_table(MACHINES)?;
        let mut codes = ecriture.open_table(ENROLEMENTS)?;
        let mut codes_par_machine = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
        let mut services = ecriture.open_table(SERVICES)?;
        let mut par_nom = ecriture.open_table(SERVICES_PAR_NOM)?;
        let (debut, fin) = intervalle(qui);
        let mut condamnees = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (clef_index, clef_machine) = entree?;
            condamnees.push((clef_index.value().to_vec(), clef_machine.value().to_vec()));
        }
        for (clef_index, clef_machine) in &condamnees {
            let quelle = depuis_clef(clef_machine)?;
            index.remove(clef_index.as_slice())?;
            machines.remove(clef_machine.as_slice())?;
            if let Some(empreinte) = codes_par_machine.remove(clef_machine.as_slice())? {
                codes.remove(empreinte.value())?;
                retrait.codes = retrait.codes.saturating_add(1);
            }
            let (debut, fin) = intervalle(quelle);
            let mut siens = Vec::new();
            for entree in par_nom.range(debut.as_slice()..fin.as_slice())? {
                let (clef_nom, clef_service) = entree?;
                siens.push((clef_nom.value().to_vec(), clef_service.value().to_vec()));
            }
            for (clef_nom, clef_service) in &siens {
                par_nom.remove(clef_nom.as_slice())?;
                services.remove(clef_service.as_slice())?;
            }
            retrait.services = retrait.services.saturating_add(siens.len());
            retrait.a_fermer.push(quelle);
        }
        retrait.machines = condamnees.len();
    }

    // ── LES AUTORISATIONS, DANS LES DEUX SENS : retirées, non marquées ──────
    {
        let mut autorisations = ecriture.open_table(AUTORISATIONS)?;
        let mut recues = ecriture.open_table(AUTORISATIONS_RECUES)?;
        let mut accordees = ecriture.open_table(AUTORISATIONS_ACCORDEES)?;
        let (debut, fin) = intervalle(qui);
        let mut condamnees = Vec::new();
        for entree in accordees.range(debut.as_slice()..fin.as_slice())? {
            let (clef_index, clef_autorisation) = entree?;
            condamnees.push((
                clef_index.value().to_vec(),
                clef_autorisation.value().to_vec(),
            ));
        }
        for entree in recues.range(debut.as_slice()..fin.as_slice())? {
            let (clef_index, clef_autorisation) = entree?;
            condamnees.push((
                clef_index.value().to_vec(),
                clef_autorisation.value().to_vec(),
            ));
        }
        for (_, clef_autorisation) in &condamnees {
            // L'arête, puis ses deux entrées d'index — dont celle de l'AUTRE
            // compte, qui ne doit plus rien voir. Une arête vue par les deux
            // sens n'est retirée qu'une fois.
            let Some(brut) = autorisations.remove(clef_autorisation.as_slice())? else {
                continue;
            };
            let autorisation = Autorisation::lire(brut.value())?;
            let quelle = depuis_clef(clef_autorisation)?;
            recues.remove(paire(autorisation.a, quelle).as_slice())?;
            accordees.remove(paire(autorisation.par, quelle).as_slice())?;
            retrait.autorisations = retrait.autorisations.saturating_add(1);
        }
    }

    // ── LE COMPTE : sa réclamation retirée, sa marque posée ─────────────────
    {
        let mut comptes = ecriture.open_table(COMPTES)?;
        let mut reclamations = ecriture.open_table(ALIAS)?;
        if let Some(brut) = comptes.get(clef_compte.as_slice())? {
            let avant = Compte::lire(brut.value())?;
            if let Some(alias) = &avant.alias {
                reclamations
                    .remove(clef_de_reclamation(alias.octets(), avant.reclamation).as_slice())?;
                retrait.alias = true;
            }
        }
        let compte = Compte {
            provenance,
            estampille,
            alias: None,
            reclamation: estampille,
            efface: Some(marque),
        };
        let mut octets = [0_u8; COMPTE_OCTETS];
        compte.ecrire(&mut octets);
        comptes.insert(clef_compte.as_slice(), &octets)?;
    }
    Ok(retrait)
}

/// La provenance de l'enregistrement que porte cette opération, s'il en porte
/// un. Les opérations qui ne nomment qu'un identifiant (révocation, alias,
/// `PATCH`, effacement) n'ont pas de provenance à vérifier.
fn provenance_de(operation: &Operation) -> Option<Provenance> {
    match operation {
        Operation::Compte { enregistrement, .. } => Some(enregistrement.provenance),
        Operation::Appareil { enregistrement, .. } => Some(enregistrement.provenance),
        Operation::Description { enregistrement, .. } => Some(enregistrement.provenance),
        Operation::Poussee { enregistrement, .. } => Some(enregistrement.provenance),
        Operation::Machine { enregistrement, .. } => Some(enregistrement.provenance),
        Operation::Enrolement { enregistrement, .. } => Some(enregistrement.provenance),
        Operation::Service { enregistrement, .. } => Some(enregistrement.provenance),
        Operation::Autorisation { enregistrement, .. } => Some(enregistrement.provenance),
        Operation::Alias { .. }
        | Operation::AppareilRevoque { .. }
        | Operation::AppareilAtteste { .. }
        | Operation::MachineModifiee { .. }
        | Operation::CleMachine { .. }
        | Operation::CleMachineRevoquee { .. }
        | Operation::AutorisationRevoquee { .. }
        | Operation::CompteEfface { .. } => None,
    }
}

/// Applique cette opération dans cette transaction, sous cette estampille,
/// selon la règle de conflit de son genre — et note ce qu'il faut fermer ici.
///
/// **Chaque règle est une fonction de l'ENSEMBLE des opérations, pas de leur
/// ordre** (`docs/replication.md` §3.1) : ce qui remplace va au plus récent par
/// estampille, ce qui est unique va au plus ancien, une révocation est un
/// tombeau. Deux racines qui ont tout vu obtiennent le même entrepôt, quel que
/// soit l'ordre — et c'est l'essai des permutations qui le tient.
fn appliquer_dans(
    ecriture: &WriteTransaction,
    estampille: Estampille,
    operation: &Operation,
    effets: &mut EffetsVivants,
) -> Result<(), Faute> {
    match operation {
        Operation::Compte {
            compte,
            enregistrement,
        } => appliquer_compte(ecriture, *compte, enregistrement),
        Operation::Alias { compte, alias } => {
            appliquer_alias(ecriture, *compte, alias.as_ref(), estampille)
        }
        Operation::Appareil {
            appareil,
            enregistrement,
        } => appliquer_appareil(ecriture, *appareil, enregistrement),
        Operation::AppareilRevoque {
            appareil,
            revoque_le,
        } => appliquer_appareil_revoque(ecriture, *appareil, *revoque_le, estampille, effets),
        Operation::AppareilAtteste { appareil, atteste } => {
            appliquer_appareil_atteste(ecriture, *appareil, *atteste, estampille)
        }
        Operation::Description {
            appareil,
            enregistrement,
        } => appliquer_description(ecriture, *appareil, enregistrement),
        Operation::Poussee {
            appareil,
            enregistrement,
        } => appliquer_poussee(ecriture, *appareil, enregistrement),
        Operation::Machine {
            machine,
            enregistrement,
        } => appliquer_machine(ecriture, *machine, enregistrement),
        Operation::MachineModifiee {
            machine,
            nom,
            capacites,
        } => appliquer_machine_modifiee(ecriture, *machine, *nom, *capacites, estampille, effets),
        Operation::Enrolement {
            empreinte,
            enregistrement,
        } => appliquer_enrolement(ecriture, empreinte, enregistrement),
        Operation::CleMachine {
            machine,
            cle,
            empreinte,
            code,
        } => appliquer_cle_machine(ecriture, *machine, *cle, empreinte, *code, estampille),
        Operation::CleMachineRevoquee { machine, cle } => {
            appliquer_cle_revoquee(ecriture, *machine, *cle, estampille, effets)
        }
        Operation::Service {
            service,
            enregistrement,
        } => appliquer_service(ecriture, *service, enregistrement),
        Operation::Autorisation {
            autorisation,
            enregistrement,
        } => appliquer_autorisation(ecriture, *autorisation, enregistrement),
        Operation::AutorisationRevoquee { autorisation } => {
            appliquer_autorisation_revoquee(ecriture, *autorisation, estampille)
        }
        Operation::CompteEfface {
            compte,
            efface_le,
            cause,
        } => appliquer_compte_efface(
            ecriture,
            *compte,
            Effacement {
                le: *efface_le,
                cause: *cause,
            },
            estampille,
            effets,
        ),
    }
}

/// `compte-efface` — TOUJOURS (`docs/replication.md` §3.2, §5.2) : retirer
/// tout ce que le compte tient, poser la marque avec la date et la cause
/// portées, et fermer ici les connexions de ses machines et appareils (§3.3).
///
/// **Sur un compte déjà effacé, la plus PETITE estampille tient la marque.**
/// §3.2 dit « la marque porte la date et la cause du premier appliqué » ; le
/// premier au sens de l'arrivée dépendrait de l'ordre, et deux racines qui
/// s'effacent le même orphelin à la même minute doivent finir avec la même
/// marque. Le premier au sens des estampilles est le seul qui converge, et
/// c'est aussi, à horloge égale, celui qui a écrit le premier. Rien d'autre
/// ne bouge : il n'y a plus rien à retirer.
fn appliquer_compte_efface(
    ecriture: &WriteTransaction,
    qui: Identifiant,
    marque: Effacement,
    estampille: Estampille,
    effets: &mut EffetsVivants,
) -> Result<(), Faute> {
    if let Some(avant) = compte_dans(ecriture, qui)?
        && avant.est_efface()
    {
        if estampille < avant.estampille {
            let compte = Compte {
                estampille,
                reclamation: estampille,
                efface: Some(marque),
                ..avant
            };
            let mut octets = [0_u8; COMPTE_OCTETS];
            compte.ecrire(&mut octets);
            ecriture
                .open_table(COMPTES)?
                .insert(clef(qui).as_slice(), &octets)?;
        }
        return Ok(());
    }
    let retrait = effacer_dans(ecriture, qui, Provenance::Ici, marque, estampille)?;
    effets.a_fermer.extend(retrait.a_fermer);
    Ok(())
}

/// `compte` — insérer si absent, et poser sa réclamation d'alias initiale
/// (`docs/replication.md` §5.2). Un compte créé AVEC un alias arrive en une
/// seule opération : c'est ici que sa réclamation entre à l'index.
fn appliquer_compte(
    ecriture: &WriteTransaction,
    qui: Identifiant,
    enregistrement: &Compte,
) -> Result<(), Faute> {
    let clef_compte = clef(qui);
    let mut comptes = ecriture.open_table(COMPTES)?;
    if comptes.get(clef_compte.as_slice())?.is_some() {
        return Ok(());
    }
    let compte = Compte {
        provenance: Provenance::Ici,
        ..*enregistrement
    };
    let mut octets = [0_u8; COMPTE_OCTETS];
    compte.ecrire(&mut octets);
    comptes.insert(clef_compte.as_slice(), &octets)?;
    if let Some(alias) = &compte.alias {
        let mut reclamations = ecriture.open_table(ALIAS)?;
        reclamations.insert(
            clef_de_reclamation(alias.octets(), compte.reclamation).as_slice(),
            clef_compte.as_slice(),
        )?;
    }
    Ok(())
}

/// `alias` — la réclamation courante du compte, au plus récent
/// (`docs/replication.md` §3.2). L'index garde TOUTES les réclamations, et le
/// titulaire est la plus ancienne ; changer la sienne, c'est retirer l'ancienne
/// et poser la neuve.
fn appliquer_alias(
    ecriture: &WriteTransaction,
    qui: Identifiant,
    alias: Option<&AliasRange>,
    estampille: Estampille,
) -> Result<(), Faute> {
    let clef_compte = clef(qui);
    let mut comptes = ecriture.open_table(COMPTES)?;
    let ancien = match comptes.get(clef_compte.as_slice())? {
        Some(brut) => Compte::lire(brut.value())?,
        // Le compte n'existe pas encore — son opération `compte` viendra, et
        // portera sa réclamation de création. Rien à faire ici.
        None => return Ok(()),
    };
    // **UN COMPTE EFFACÉ NE RÉCLAME PLUS RIEN** : l'effacement l'emporte,
    // quel que soit l'ordre (§3.2).
    if ancien.est_efface() {
        return Ok(());
    }
    // **LE PLUS RÉCENT GAGNE** : une réclamation plus ancienne que celle qu'on
    // tient déjà ne change rien. C'est ce qui rend la règle indépendante de
    // l'ordre — deux réclamations d'un même compte convergent vers la plus
    // grande estampille.
    if estampille <= ancien.reclamation {
        return Ok(());
    }
    let mut reclamations = ecriture.open_table(ALIAS)?;
    if let Some(parti) = &ancien.alias {
        reclamations.remove(clef_de_reclamation(parti.octets(), ancien.reclamation).as_slice())?;
    }
    let compte = Compte {
        provenance: Provenance::Ici,
        estampille: ancien.estampille.max(estampille),
        alias: alias.copied(),
        reclamation: estampille,
        efface: None,
    };
    let mut octets = [0_u8; COMPTE_OCTETS];
    compte.ecrire(&mut octets);
    comptes.insert(clef_compte.as_slice(), &octets)?;
    if let Some(voulu) = alias {
        reclamations.insert(
            clef_de_reclamation(voulu.octets(), estampille).as_slice(),
            clef_compte.as_slice(),
        )?;
    }
    Ok(())
}

/// `appareil` — insérer si absent (`docs/replication.md` §5.2).
fn appliquer_appareil(
    ecriture: &WriteTransaction,
    quel: Identifiant,
    enregistrement: &Appareil,
) -> Result<(), Faute> {
    // **LE COMPTE EFFACÉ L'EMPORTE** (§3.2) : un appareil enrôlé sur l'autre
    // racine pendant la fenêtre n'entre pas — son porteur lira `401`.
    if compte_efface_dans(ecriture, enregistrement.proprietaire)? {
        return Ok(());
    }
    let clef_appareil = clef(quel);
    let mut table = ecriture.open_table(APPAREILS)?;
    if table.get(clef_appareil.as_slice())?.is_some() {
        return Ok(());
    }
    let appareil = Appareil {
        provenance: Provenance::Ici,
        ..*enregistrement
    };
    let mut octets = [0_u8; APPAREIL_OCTETS];
    appareil.ecrire(&mut octets);
    table.insert(clef_appareil.as_slice(), &octets)?;
    let mut par_compte = ecriture.open_table(APPAREILS_PAR_COMPTE)?;
    par_compte.insert(
        paire(appareil.proprietaire, quel).as_slice(),
        clef_appareil.as_slice(),
    )?;
    Ok(())
}

/// `appareil-revoque` — marquer, retirer le jeton, TOUJOURS
/// (`docs/replication.md` §5.2) ; et fermer les connexions de cet appareil ici
/// (§3.3).
///
/// **La date est celle de la racine qui a révoqué, et la plus ANCIENNE tient**
/// si deux révocations du même appareil se croisent : c'est ce qui fait lire
/// la même date aux deux racines, dans les deux ordres — et c'est de là que
/// la règle des orphelins compte.
fn appliquer_appareil_revoque(
    ecriture: &WriteTransaction,
    quel: Identifiant,
    revoque_le: u64,
    estampille: Estampille,
    effets: &mut EffetsVivants,
) -> Result<(), Faute> {
    let clef_appareil = clef(quel);
    let mut table = ecriture.open_table(APPAREILS)?;
    let avant = match table.get(clef_appareil.as_slice())? {
        Some(brut) => Appareil::lire(brut.value())?,
        None => return Ok(()),
    };
    let mut octets = [0_u8; APPAREIL_OCTETS];
    Appareil {
        estampille: avant.estampille.max(estampille),
        revoque_le: Some(
            avant
                .revoque_le
                .map_or(revoque_le, |deja| deja.min(revoque_le)),
        ),
        ..avant
    }
    .ecrire(&mut octets);
    table.insert(clef_appareil.as_slice(), &octets)?;
    ecriture
        .open_table(POUSSEES)?
        .remove(clef_appareil.as_slice())?;
    effets.a_fermer.push(quel);
    Ok(())
}

/// `appareil-atteste` — poser la valeur si l'appareil est `aucune` ou
/// `attendue`, rien s'il porte déjà une valeur prouvée, TOUJOURS — révoqué ou
/// non (`docs/replication.md` §3.2, §5.2, décision 25).
///
/// **Sur un appareil révoqué aussi**, et c'est ce qui converge : l'attestation
/// est un fait sur la clé, la révocation un fait sur l'appareil, et ne pas
/// poser l'une à cause de l'autre ferait diverger la valeur selon l'ordre
/// d'arrivée. Un `attendue` qui devient prouvé est vivant ici aussi : sa
/// prochaine preuve est servie. Sur un appareil qu'on n'a pas — son opération
/// `appareil` n'est pas encore là, ou son compte est effacé —, rien : celui
/// qui a écrit l'attestation tenait l'appareil, et l'instantané la redira.
fn appliquer_appareil_atteste(
    ecriture: &WriteTransaction,
    quel: Identifiant,
    atteste: Attestation,
    estampille: Estampille,
) -> Result<(), Faute> {
    let clef_appareil = clef(quel);
    let mut table = ecriture.open_table(APPAREILS)?;
    let avant = match table.get(clef_appareil.as_slice())? {
        Some(brut) => Appareil::lire(brut.value())?,
        None => return Ok(()),
    };
    // **L'ESTAMPILLE SE HISSE MÊME QUAND LA VALEUR NE BOUGE PAS**, comme pour
    // une révocation : deux attestations du même appareil, dans les deux
    // ordres, doivent laisser le même enregistrement — et « la dernière
    // écriture » est une fonction de l'ensemble, pas de l'arrivée.
    let mut octets = [0_u8; APPAREIL_OCTETS];
    Appareil {
        estampille: avant.estampille.max(estampille),
        atteste: if avant.atteste.prouvee() {
            avant.atteste
        } else {
            atteste
        },
        ..avant
    }
    .ecrire(&mut octets);
    table.insert(clef_appareil.as_slice(), &octets)?;
    Ok(())
}

/// `description` — le plus récent (`docs/replication.md` §5.2).
fn appliquer_description(
    ecriture: &WriteTransaction,
    appareil: Identifiant,
    enregistrement: &Description,
) -> Result<(), Faute> {
    let clef_appareil = clef(appareil);
    // **UN APPAREIL QU'ON N'A PAS NE SE DÉCRIT PAS** — révoqué, si ; effacé
    // avec son compte, non : c'est ce qui rend la description convergente
    // avec l'effacement, dans les deux ordres (§3.2).
    if ecriture
        .open_table(APPAREILS)?
        .get(clef_appareil.as_slice())?
        .is_none()
    {
        return Ok(());
    }
    let mut table = ecriture.open_table(DESCRIPTIONS)?;
    if let Some(brut) = table.get(clef_appareil.as_slice())?
        && Description::lire(brut.value())?.estampille >= enregistrement.estampille
    {
        return Ok(());
    }
    let description = Description {
        provenance: Provenance::Ici,
        ..*enregistrement
    };
    let mut octets = [0_u8; DESCRIPTION_OCTETS];
    description.ecrire(&mut octets);
    table.insert(clef_appareil.as_slice(), &octets)?;
    Ok(())
}

/// `poussee` — le plus récent ; refusé si l'appareil est révoqué
/// (`docs/replication.md` §5.2). Une poussée sur un appareil révoqué ne se pose
/// pas, et c'est ce qui la rend convergente avec la révocation : celle-ci a
/// retiré le jeton, celle-là ne le remet pas.
fn appliquer_poussee(
    ecriture: &WriteTransaction,
    appareil: Identifiant,
    enregistrement: &JetonPoussee,
) -> Result<(), Faute> {
    let clef_appareil = clef(appareil);
    match ecriture
        .open_table(APPAREILS)?
        .get(clef_appareil.as_slice())?
    {
        Some(brut) if !Appareil::lire(brut.value())?.revoque() => {}
        _ => return Ok(()),
    }
    let mut table = ecriture.open_table(POUSSEES)?;
    if let Some(brut) = table.get(clef_appareil.as_slice())?
        && JetonPoussee::lire(brut.value())?.estampille >= enregistrement.estampille
    {
        return Ok(());
    }
    let poussee = JetonPoussee {
        provenance: Provenance::Ici,
        ..*enregistrement
    };
    let mut octets = [0_u8; POUSSEE_OCTETS];
    poussee.ecrire(&mut octets);
    table.insert(clef_appareil.as_slice(), &octets)?;
    Ok(())
}

/// `machine` — insérer si absent, sans clé (`docs/replication.md` §5.2). Le nom
/// et les capacités de création sont ceux de l'enregistrement ; les `PATCH`
/// suivants les mènent, champ par champ.
fn appliquer_machine(
    ecriture: &WriteTransaction,
    quelle: Identifiant,
    enregistrement: &Machine,
) -> Result<(), Faute> {
    // **LE COMPTE EFFACÉ L'EMPORTE** (§3.2) : une machine déclarée sur l'autre
    // racine pendant la fenêtre n'entre pas.
    if compte_efface_dans(ecriture, enregistrement.proprietaire)? {
        return Ok(());
    }
    let clef_machine = clef(quelle);
    let mut machines = ecriture.open_table(MACHINES)?;
    if machines.get(clef_machine.as_slice())?.is_some() {
        return Ok(());
    }
    let machine = Machine {
        provenance: Provenance::Ici,
        cle: None,
        ..*enregistrement
    };
    let mut octets = [0_u8; MACHINE_OCTETS];
    machine.ecrire(&mut octets);
    machines.insert(clef_machine.as_slice(), &octets)?;
    let mut par_compte = ecriture.open_table(MACHINES_PAR_COMPTE)?;
    par_compte.insert(
        paire(machine.proprietaire, quelle).as_slice(),
        clef_machine.as_slice(),
    )?;
    Ok(())
}

/// `machine-modifiee` — le plus récent, CHAMP PAR CHAMP (`docs/replication.md`
/// §3.2). Le nom a son estampille, les capacités la leur ; chacune ne bouge que
/// pour une estampille plus grande. Retirer `annonce` ferme les connexions de
/// cette machine ici (§3.3).
fn appliquer_machine_modifiee(
    ecriture: &WriteTransaction,
    quelle: Identifiant,
    nom: Option<NomRange>,
    capacites: Option<Capacites>,
    estampille: Estampille,
    effets: &mut EffetsVivants,
) -> Result<(), Faute> {
    let clef_machine = clef(quelle);
    let mut machines = ecriture.open_table(MACHINES)?;
    let avant = match machines.get(clef_machine.as_slice())? {
        Some(brut) => Machine::lire(brut.value())?,
        None => return Ok(()),
    };
    let mut apres = avant;
    apres.provenance = Provenance::Ici;
    apres.estampille = avant.estampille.max(estampille);
    if let Some(nom) = nom
        && estampille > avant.nom_estampille
    {
        apres.nom = nom;
        apres.nom_estampille = estampille;
    }
    let mut perd_l_annonce = false;
    if let Some(capacites) = capacites
        && estampille > avant.capacites_estampille
    {
        perd_l_annonce = avant.annonce && !capacites.annonce;
        apres.annonce = capacites.annonce;
        apres.lecture = capacites.lecture;
        apres.capacites_estampille = estampille;
    }
    let mut octets = [0_u8; MACHINE_OCTETS];
    apres.ecrire(&mut octets);
    machines.insert(clef_machine.as_slice(), &octets)?;
    if perd_l_annonce {
        effets.a_fermer.push(quelle);
    }
    Ok(())
}

/// `enrolement` — le code courant de la machine, le plus récent ; le précédent
/// s'efface (`docs/replication.md` §5.2).
fn appliquer_enrolement(
    ecriture: &WriteTransaction,
    empreinte: &[u8; EMPREINTE_OCTETS],
    enregistrement: &Enrolement,
) -> Result<(), Faute> {
    let clef_machine = clef(enregistrement.machine);
    // **UN CODE POUR UNE MACHINE QU'ON N'A PAS NE SE RANGE PAS** : une machine
    // effacée avec son compte ne se ré-enrôle pas, dans aucun ordre (§3.2).
    if ecriture
        .open_table(MACHINES)?
        .get(clef_machine.as_slice())?
        .is_none()
    {
        return Ok(());
    }
    let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
    let mut codes = ecriture.open_table(ENROLEMENTS)?;
    if let Some(ancienne) = index.get(clef_machine.as_slice())? {
        let ancienne = ancienne.value().to_vec();
        if let Some(brut) = codes.get(ancienne.as_slice())? {
            // **LE PLUS RÉCENT GAGNE** : un code plus ancien que celui qu'on
            // tient déjà pour cette machine ne le remplace pas.
            if Enrolement::lire(brut.value())?.estampille >= enregistrement.estampille {
                return Ok(());
            }
        }
        codes.remove(ancienne.as_slice())?;
    }
    let enrolement = Enrolement {
        provenance: Provenance::Ici,
        ..*enregistrement
    };
    let mut octets = [0_u8; ENROLEMENT_OCTETS];
    enrolement.ecrire(&mut octets);
    codes.insert(empreinte.as_slice(), &octets)?;
    index.insert(clef_machine.as_slice(), empreinte.as_slice())?;
    Ok(())
}

/// `cle-machine` — supprimer le code s'il est là ; lier la clé selon §3.2 : le
/// code le plus récemment ÉMIS gagne, puis la première consommation
/// (`docs/replication.md` §3.2, §5.2).
fn appliquer_cle_machine(
    ecriture: &WriteTransaction,
    quelle: Identifiant,
    cle: [u8; CLE_OCTETS],
    empreinte: &[u8; EMPREINTE_OCTETS],
    code: Estampille,
    estampille: Estampille,
) -> Result<(), Faute> {
    let clef_machine = clef(quelle);
    let mut machines = ecriture.open_table(MACHINES)?;
    let avant = match machines.get(clef_machine.as_slice())? {
        Some(brut) => Machine::lire(brut.value())?,
        None => return Ok(()),
    };
    // Le code est consommé : on le retire s'il est là. Dans un instantané, son
    // empreinte est nulle et il n'y a rien à retirer (le code n'existe plus).
    {
        let mut codes = ecriture.open_table(ENROLEMENTS)?;
        if codes.remove(empreinte.as_slice())?.is_some() {
            let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
            if index
                .get(clef_machine.as_slice())?
                .is_some_and(|quoi| quoi.value() == empreinte.as_slice())
            {
                index.remove(clef_machine.as_slice())?;
            }
        }
    }
    let candidate = CleLiee {
        cle,
        liaison: estampille,
        code,
    };
    // **CODE LE PLUS RÉCENT, PUIS PREMIÈRE CONSOMMATION** : c'est un ordre
    // total, donc la même clé gagne dans les deux ordres d'arrivée.
    let gagne = match avant.cle {
        None => true,
        Some(tenue) => {
            candidate.code > tenue.code
                || (candidate.code == tenue.code && candidate.liaison < tenue.liaison)
        }
    };
    let mut apres = Machine {
        provenance: Provenance::Ici,
        estampille: avant.estampille.max(estampille),
        ..avant
    };
    if gagne {
        apres.cle = Some(candidate);
    }
    let mut octets = [0_u8; MACHINE_OCTETS];
    apres.ecrire(&mut octets);
    machines.insert(clef_machine.as_slice(), &octets)?;
    Ok(())
}

/// `cle-machine-revoquee` — retirer la clé si c'est bien celle-là ; fermer les
/// connexions (`docs/replication.md` §5.2, §3.3).
fn appliquer_cle_revoquee(
    ecriture: &WriteTransaction,
    quelle: Identifiant,
    cle: [u8; CLE_OCTETS],
    estampille: Estampille,
    effets: &mut EffetsVivants,
) -> Result<(), Faute> {
    let clef_machine = clef(quelle);
    let mut machines = ecriture.open_table(MACHINES)?;
    let avant = match machines.get(clef_machine.as_slice())? {
        Some(brut) => Machine::lire(brut.value())?,
        None => return Ok(()),
    };
    let etait_la = avant.cle.is_some_and(|liee| liee.cle == cle);
    let mut apres = Machine {
        provenance: Provenance::Ici,
        estampille: avant.estampille.max(estampille),
        ..avant
    };
    if etait_la {
        apres.cle = None;
    }
    let mut octets = [0_u8; MACHINE_OCTETS];
    apres.ecrire(&mut octets);
    machines.insert(clef_machine.as_slice(), &octets)?;
    // **TOUJOURS** : la connexion tombe même si la clé était déjà partie — c'est
    // une révocation, et ce qui est vivant se rejoue (§3.3).
    effets.a_fermer.push(quelle);
    Ok(())
}

/// `service` — insérer ; si `(machine, nom)` est déjà tenu, le plus ancien
/// reste (`docs/replication.md` §3.2, §5.2).
fn appliquer_service(
    ecriture: &WriteTransaction,
    quel: Identifiant,
    enregistrement: &Service,
) -> Result<(), Faute> {
    let clef_service = clef(quel);
    let clef_nom = clef_de_nom(enregistrement.machine, enregistrement.nom.octets());
    // **UN SERVICE D'UNE MACHINE QU'ON N'A PAS NE SE DÉCLARE PAS** : les
    // services partent avec la machine, et la machine avec son compte (§3.2).
    if ecriture
        .open_table(MACHINES)?
        .get(clef(enregistrement.machine).as_slice())?
        .is_none()
    {
        return Ok(());
    }
    let mut services = ecriture.open_table(SERVICES)?;
    let mut par_nom = ecriture.open_table(SERVICES_PAR_NOM)?;

    if let Some(tenu) = par_nom.get(clef_nom.as_slice())? {
        let tenu = tenu.value().to_vec();
        if tenu == clef_service.as_slice() {
            return Ok(());
        }
        let estampille_tenu = match services.get(tenu.as_slice())? {
            Some(brut) => Service::lire(brut.value())?.estampille,
            None => Estampille {
                compteur: u64::MAX,
                racine: enregistrement.estampille.racine,
            },
        };
        // **LE PLUS ANCIEN RESTE**, l'autre s'efface. Si l'entrant est plus
        // ancien, il prend la place ; sinon il ne s'écrit pas du tout.
        if enregistrement.estampille < estampille_tenu {
            services.remove(tenu.as_slice())?;
        } else {
            return Ok(());
        }
    } else if services.get(clef_service.as_slice())?.is_some() {
        // L'identifiant existe déjà sous un autre nom : un service ne bouge
        // jamais, donc rien à faire.
        return Ok(());
    }

    let service = Service {
        provenance: Provenance::Ici,
        ..*enregistrement
    };
    let mut octets = [0_u8; SERVICE_OCTETS];
    service.ecrire(&mut octets);
    services.insert(clef_service.as_slice(), &octets)?;
    par_nom.insert(clef_nom.as_slice(), clef_service.as_slice())?;
    Ok(())
}

/// `autorisation` — insérer si absent (`docs/replication.md` §5.2).
fn appliquer_autorisation(
    ecriture: &WriteTransaction,
    quelle: Identifiant,
    enregistrement: &Autorisation,
) -> Result<(), Faute> {
    // **UN COMPTE EFFACÉ N'ACCORDE NI NE REÇOIT PLUS RIEN** (§3.2) : l'autre
    // partie ne doit jamais voir une arête vers un compte qui n'existe plus.
    if compte_efface_dans(ecriture, enregistrement.par)?
        || compte_efface_dans(ecriture, enregistrement.a)?
    {
        return Ok(());
    }
    let clef_autorisation = clef(quelle);
    let mut table = ecriture.open_table(AUTORISATIONS)?;
    if table.get(clef_autorisation.as_slice())?.is_some() {
        return Ok(());
    }
    let autorisation = Autorisation {
        provenance: Provenance::Ici,
        ..*enregistrement
    };
    let mut octets = [0_u8; AUTORISATION_OCTETS];
    autorisation.ecrire(&mut octets);
    table.insert(clef_autorisation.as_slice(), &octets)?;
    let mut recues = ecriture.open_table(AUTORISATIONS_RECUES)?;
    recues.insert(
        paire(autorisation.a, quelle).as_slice(),
        clef_autorisation.as_slice(),
    )?;
    let mut accordees = ecriture.open_table(AUTORISATIONS_ACCORDEES)?;
    accordees.insert(
        paire(autorisation.par, quelle).as_slice(),
        clef_autorisation.as_slice(),
    )?;
    Ok(())
}

/// `autorisation-revoquee` — marquer, TOUJOURS (`docs/replication.md` §5.2).
fn appliquer_autorisation_revoquee(
    ecriture: &WriteTransaction,
    quelle: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    let clef_autorisation = clef(quelle);
    let mut table = ecriture.open_table(AUTORISATIONS)?;
    let avant = match table.get(clef_autorisation.as_slice())? {
        Some(brut) => Autorisation::lire(brut.value())?,
        None => return Ok(()),
    };
    let mut octets = [0_u8; AUTORISATION_OCTETS];
    Autorisation {
        estampille: avant.estampille.max(estampille),
        revoquee: true,
        ..avant
    }
    .ecrire(&mut octets);
    table.insert(clef_autorisation.as_slice(), &octets)?;
    Ok(())
}

/// Le titulaire de cet alias : la plus ancienne réclamation courante.
fn titulaire(
    reclamations: &impl ReadableTable<&'static [u8], &'static [u8]>,
    alias: &[u8],
) -> Result<Option<Identifiant>, Faute> {
    let (debut, fin) = intervalle_des_reclamations(alias);
    let mut premieres = reclamations.range(debut.as_slice()..fin.as_slice())?;
    match premieres.next() {
        Some(entree) => {
            let (_, compte) = entree?;
            depuis_clef(compte.value()).map(Some)
        }
        None => Ok(None),
    }
}

/// La borne d'un intervalle de temps, dans l'espace des clés du journal.
///
/// L'horodatage en gros-boutiste suivi de zéros : c'est la plus petite clé de
/// cette milliseconde, donc la première qui échappe à l'intervalle qui la
/// précède.
fn borne_de_temps(quand: u64) -> [u8; CLEF_JOURNAL_OCTETS] {
    let mut borne = [0_u8; CLEF_JOURNAL_OCTETS];
    for (place, octet) in borne.iter_mut().zip(quand.to_be_bytes().iter()) {
        *place = *octet;
    }
    borne
}

// ── La reprise d'une base ancienne (`replication.md` §11.4) ─────────────────

/// Attribue les estampilles de la reprise, en séquence.
struct Sequence {
    /// Le dernier compteur attribué.
    compteur: u64,
    /// La racine qui reprend.
    racine: Identifiant,
}

impl Sequence {
    /// L'estampille suivante.
    fn suivante(&mut self) -> Estampille {
        self.compteur = self.compteur.saturating_add(1);
        Estampille {
            compteur: self.compteur,
            racine: self.racine,
        }
    }
}

/// Reprend une table de la forme ancienne : la lit sous sa définition
/// d'hier, la supprime, la recrée sous celle d'aujourd'hui, et y range chaque
/// enregistrement avec l'estampille que la séquence lui attribue. Rend ce
/// qu'elle a repris, pour reconstruire les index.
///
/// **Tout est relevé avant d'être réécrit** : la table d'hier doit être fermée
/// avant d'être supprimée, et `redb` ne le permet qu'en lâchant sa poignée.
fn reprendre_table<const VIEUX: usize, const NEUF: usize, T>(
    ecriture: &WriteTransaction,
    ancienne: TableDefinition<'_, &[u8], &[u8; VIEUX]>,
    neuve: TableDefinition<'_, &[u8], &[u8; NEUF]>,
    sequence: &mut Sequence,
    lire: impl Fn(&[u8; VIEUX], Estampille) -> Result<T, asl_registre::Faute>,
    ecrire: impl Fn(&T, &mut [u8; NEUF]),
) -> Result<Vec<(Vec<u8>, T)>, Faute> {
    let mut relevees = Vec::new();
    {
        let table = ecriture.open_table(ancienne)?;
        for entree in table.iter()? {
            let (clef, valeur) = entree?;
            relevees.push((clef.value().to_vec(), *valeur.value()));
        }
    }
    ecriture.delete_table(ancienne)?;
    let mut table = ecriture.open_table(neuve)?;
    let mut reprises = Vec::with_capacity(relevees.len());
    for (clef, vieux) in relevees {
        let enregistrement = lire(&vieux, sequence.suivante())?;
        let mut octets = [0_u8; NEUF];
        ecrire(&enregistrement, &mut octets);
        table.insert(clef.as_slice(), &octets)?;
        reprises.push((clef, enregistrement));
    }
    Ok(reprises)
}

/// Vide cet index, pour le reconstruire.
fn vider(
    ecriture: &WriteTransaction,
    index: TableDefinition<'_, &[u8], &[u8]>,
) -> Result<(), Faute> {
    ecriture.delete_table(index)?;
    ecriture.open_table(index)?;
    Ok(())
}

/// Reprend une base d'avant l'estampille, dans cette transaction.
///
/// # CE QUE LA REPRISE FAIT, DANS L'ORDRE
///
/// 1. Chaque table d'enregistrements est relue sous sa forme d'hier et réécrite
///    sous celle d'aujourd'hui, **chaque enregistrement recevant une estampille
///    en séquence** — la racine qui reprend, un compteur qui part de un. Rien
///    n'est perdu : le corps d'un enregistrement d'hier est celui d'aujourd'hui
///    moins ses estampilles.
/// 2. **Tous les index sont reconstruits** depuis les enregistrements, y compris
///    ceux qu'une table née après coup n'avait jamais reçus.
/// 3. Le compteur de la racine est posé au-dessus de tout ce qui a été
///    estampillé, et **le journal d'opérations démarre vide — mais pas depuis
///    zéro** : il est marqué retiré jusqu'au compteur, pour qu'un rattrapage
///    depuis moins que cela soit refusé et que l'autre racine s'amorce par
///    instantané. Ce que la base reprise porte n'a pas d'opération ; ce qu'on
///    y écrira ensuite en aura.
///
/// Le journal des requêtes (C18) et son rang ne bougent pas : ils ne portent
/// pas d'estampille, et ne se répliquent pas.
///
/// **Elle reprend directement dans la forme d'aujourd'hui**, dates comprises :
/// un appareil déjà révoqué reçoit `quand` — la date de la reprise — pour
/// `révoqué le`, aucun compte n'est effacé. Rend combien d'appareils ont reçu
/// une date.
fn reprendre(ecriture: &WriteTransaction, racine: Identifiant, quand: u64) -> Result<usize, Faute> {
    let mut sequence = Sequence {
        compteur: 0,
        racine,
    };

    let comptes = reprendre_table(
        ecriture,
        anciennes::COMPTES,
        COMPTES,
        &mut sequence,
        Compte::lire_ancien,
        Compte::ecrire,
    )?;
    let machines = reprendre_table(
        ecriture,
        anciennes::MACHINES,
        MACHINES,
        &mut sequence,
        Machine::lire_ancien,
        Machine::ecrire,
    )?;
    let appareils = reprendre_table(
        ecriture,
        anciennes::APPAREILS,
        APPAREILS,
        &mut sequence,
        |octets, estampille| Appareil::lire_ancien(octets, estampille, quand),
        Appareil::ecrire,
    )?;
    let dates = appareils
        .iter()
        .filter(|(_, appareil)| appareil.revoque())
        .count();
    reprendre_table(
        ecriture,
        anciennes::POUSSEES,
        POUSSEES,
        &mut sequence,
        JetonPoussee::lire_ancien,
        JetonPoussee::ecrire,
    )?;
    reprendre_table(
        ecriture,
        anciennes::DESCRIPTIONS,
        DESCRIPTIONS,
        &mut sequence,
        Description::lire_ancien,
        Description::ecrire,
    )?;
    let enrolements = reprendre_table(
        ecriture,
        anciennes::ENROLEMENTS,
        ENROLEMENTS,
        &mut sequence,
        Enrolement::lire_ancien,
        Enrolement::ecrire,
    )?;
    let services = reprendre_table(
        ecriture,
        anciennes::SERVICES,
        SERVICES,
        &mut sequence,
        Service::lire_ancien,
        Service::ecrire,
    )?;
    let autorisations = reprendre_table(
        ecriture,
        anciennes::AUTORISATIONS,
        AUTORISATIONS,
        &mut sequence,
        Autorisation::lire_ancien,
        Autorisation::ecrire,
    )?;

    // ── LES INDEX, RECONSTRUITS DEPUIS LES ENREGISTREMENTS ──────────────────
    //
    // L'index des alias change de forme — il porte désormais la réclamation —,
    // donc il se supprime sous sa définition d'hier. Les autres gardent la leur
    // et se vident : ce qui compte est qu'ils soient COMPLETS, y compris pour
    // ce qui avait été écrit avant qu'ils n'existent.
    ecriture.delete_table(anciennes::ALIAS)?;
    {
        let mut reclamations = ecriture.open_table(ALIAS)?;
        for (clef, compte) in &comptes {
            if let Some(alias) = &compte.alias {
                reclamations.insert(
                    clef_de_reclamation(alias.octets(), compte.reclamation).as_slice(),
                    clef.as_slice(),
                )?;
            }
        }
    }
    vider(ecriture, MACHINES_PAR_COMPTE)?;
    {
        let mut index = ecriture.open_table(MACHINES_PAR_COMPTE)?;
        for (clef, machine) in &machines {
            let quelle = depuis_clef(clef)?;
            index.insert(
                paire(machine.proprietaire, quelle).as_slice(),
                clef.as_slice(),
            )?;
        }
    }
    vider(ecriture, APPAREILS_PAR_COMPTE)?;
    {
        let mut index = ecriture.open_table(APPAREILS_PAR_COMPTE)?;
        for (clef, appareil) in &appareils {
            let quel = depuis_clef(clef)?;
            index.insert(
                paire(appareil.proprietaire, quel).as_slice(),
                clef.as_slice(),
            )?;
        }
    }
    vider(ecriture, ENROLEMENTS_PAR_MACHINE)?;
    {
        let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
        for (empreinte, enrolement) in &enrolements {
            index.insert(clef(enrolement.machine).as_slice(), empreinte.as_slice())?;
        }
    }
    vider(ecriture, SERVICES_PAR_NOM)?;
    {
        let mut index = ecriture.open_table(SERVICES_PAR_NOM)?;
        for (clef, service) in &services {
            index.insert(
                clef_de_nom(service.machine, service.nom.octets()).as_slice(),
                clef.as_slice(),
            )?;
        }
    }
    vider(ecriture, AUTORISATIONS_RECUES)?;
    vider(ecriture, AUTORISATIONS_ACCORDEES)?;
    {
        let mut recues = ecriture.open_table(AUTORISATIONS_RECUES)?;
        let mut accordees = ecriture.open_table(AUTORISATIONS_ACCORDEES)?;
        for (clef, autorisation) in &autorisations {
            let quelle = depuis_clef(clef)?;
            recues.insert(paire(autorisation.a, quelle).as_slice(), clef.as_slice())?;
            accordees.insert(paire(autorisation.par, quelle).as_slice(), clef.as_slice())?;
        }
    }

    // ── LE COMPTEUR AU-DESSUS, ET LE JOURNAL VIDE ───────────────────────────
    let mut table = ecriture.open_table(RACINE)?;
    table.insert(CLEF_DU_COMPTEUR, sequence.compteur)?;
    table.insert(CLEF_DES_RETIREES, sequence.compteur)?;
    Ok(dates)
}

/// Reprend une base d'avant les dates (format 2), dans cette transaction, et
/// rend combien d'appareils ont reçu une date.
///
/// # CE QUE LA REPRISE FAIT, DANS L'ORDRE
///
/// 1. Les comptes sont relus sous leur forme d'hier et réécrits sous celle
///    d'aujourd'hui, **sans marque d'effacement** : aucun compte d'alors
///    n'est effacé. Les estampilles ne bougent pas, l'index des alias non plus.
/// 2. Les appareils de même ; **ceux qui sont déjà révoqués reçoivent `quand`
///    pour `révoqué le`** — la date de la reprise, faute de mieux (C6). Les
///    index ne bougent pas : les clés sont les mêmes.
/// 3. **Le journal d'opérations est vidé, et marqué retiré jusqu'au
///    compteur.** Ce qu'il portait — `compte`, `appareil`, `appareil-revoque`
///    — est de la forme d'hier, que l'autre racine ne saurait plus lire ; et
///    une base reprise s'amorce chez l'autre par instantané, comme à la
///    première reprise. Le compteur ne bouge pas, le curseur du pair non
///    plus : ce que le pair a écrit reste appliqué, ce qu'on a écrit reste
///    dans les tables — seule la trace à tirer repart d'ici.
fn reprendre_les_dates(ecriture: &WriteTransaction, quand: u64) -> Result<usize, Faute> {
    {
        let mut relevees = Vec::new();
        {
            let table = ecriture.open_table(anciennes::sans_dates::COMPTES)?;
            for entree in table.iter()? {
                let (clef, valeur) = entree?;
                relevees.push((
                    clef.value().to_vec(),
                    Compte::lire_sans_dates(valeur.value())?,
                ));
            }
        }
        ecriture.delete_table(anciennes::sans_dates::COMPTES)?;
        let mut table = ecriture.open_table(COMPTES)?;
        for (clef, compte) in relevees {
            let mut octets = [0_u8; COMPTE_OCTETS];
            compte.ecrire(&mut octets);
            table.insert(clef.as_slice(), &octets)?;
        }
    }
    let dates;
    {
        let mut relevees = Vec::new();
        {
            let table = ecriture.open_table(anciennes::sans_dates::APPAREILS)?;
            for entree in table.iter()? {
                let (clef, valeur) = entree?;
                relevees.push((
                    clef.value().to_vec(),
                    Appareil::lire_sans_dates(valeur.value(), quand)?,
                ));
            }
        }
        ecriture.delete_table(anciennes::sans_dates::APPAREILS)?;
        let mut table = ecriture.open_table(APPAREILS)?;
        dates = relevees
            .iter()
            .filter(|(_, appareil)| appareil.revoque())
            .count();
        for (clef, appareil) in relevees {
            let mut octets = [0_u8; APPAREIL_OCTETS];
            appareil.ecrire(&mut octets);
            table.insert(clef.as_slice(), &octets)?;
        }
    }
    // ── LE JOURNAL VIDE, ET PAS DEPUIS ZÉRO ─────────────────────────────────
    ecriture.delete_table(OPERATIONS)?;
    ecriture.open_table(OPERATIONS)?;
    let mut racine = ecriture.open_table(RACINE)?;
    let compteur = racine.get(CLEF_DU_COMPTEUR)?.map_or(0, |quoi| quoi.value());
    racine.insert(CLEF_DES_RETIREES, compteur)?;
    Ok(dates)
}

// ── Le ré-estampillage sous l'identité réelle (`replication.md` §11.4) ───────
//
// Une base reprise par une racine SANS clé porte des estampilles sous
// `RACINE_SANS_IDENTITE`. Au premier démarrage avec une clé, elles passent
// sous l'identité réelle — le compteur gardé, la racine seule change. Ce qui
// suit sait, type par type, où une estampille se cache : dans l'enregistrement,
// dans ses champs estampillés à part, dans la clé d'une réclamation d'alias,
// dans une opération du journal et dans l'enregistrement qu'elle porte.

/// Cette estampille, passée sous `vers` si elle était sous `de`.
fn sous(estampille: Estampille, de: Identifiant, vers: Identifiant) -> Estampille {
    if estampille.racine == de {
        Estampille {
            compteur: estampille.compteur,
            racine: vers,
        }
    } else {
        estampille
    }
}

/// Ce qui porte des estampilles, et sait les faire changer de racine.
trait Reestampillable {
    /// Passe sous `vers` chaque estampille sous `de`, et dit si l'une a bougé.
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool;
}

/// Passe ces champs d'estampille sous `vers`, et dit si l'un a bougé.
macro_rules! reestampiller_les_champs {
    ($soi:expr, $de:expr, $vers:expr, $($champ:ident),+ $(,)?) => {{
        let mut bouge = false;
        $(
            let apres = sous($soi.$champ, $de, $vers);
            bouge |= apres != $soi.$champ;
            $soi.$champ = apres;
        )+
        bouge
    }};
}

impl Reestampillable for Compte {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        reestampiller_les_champs!(self, de, vers, estampille, reclamation)
    }
}

impl Reestampillable for Machine {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        let mut bouge = reestampiller_les_champs!(
            self,
            de,
            vers,
            estampille,
            nom_estampille,
            capacites_estampille
        );
        if let Some(liee) = self.cle.as_mut() {
            bouge |= reestampiller_les_champs!(liee, de, vers, liaison, code);
        }
        bouge
    }
}

impl Reestampillable for Appareil {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        reestampiller_les_champs!(self, de, vers, estampille)
    }
}

impl Reestampillable for JetonPoussee {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        reestampiller_les_champs!(self, de, vers, estampille)
    }
}

impl Reestampillable for Description {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        reestampiller_les_champs!(self, de, vers, estampille)
    }
}

impl Reestampillable for Enrolement {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        reestampiller_les_champs!(self, de, vers, estampille)
    }
}

impl Reestampillable for Service {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        reestampiller_les_champs!(self, de, vers, estampille)
    }
}

impl Reestampillable for Autorisation {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        reestampiller_les_champs!(self, de, vers, estampille)
    }
}

impl Reestampillable for Operation {
    fn reestampiller(&mut self, de: Identifiant, vers: Identifiant) -> bool {
        match self {
            Self::Compte { enregistrement, .. } => enregistrement.reestampiller(de, vers),
            Self::Appareil { enregistrement, .. } => enregistrement.reestampiller(de, vers),
            Self::Description { enregistrement, .. } => enregistrement.reestampiller(de, vers),
            Self::Poussee { enregistrement, .. } => enregistrement.reestampiller(de, vers),
            Self::Machine { enregistrement, .. } => enregistrement.reestampiller(de, vers),
            Self::Enrolement { enregistrement, .. } => enregistrement.reestampiller(de, vers),
            Self::Service { enregistrement, .. } => enregistrement.reestampiller(de, vers),
            Self::Autorisation { enregistrement, .. } => enregistrement.reestampiller(de, vers),
            Self::CleMachine { code, .. } => {
                let apres = sous(*code, de, vers);
                let bouge = apres != *code;
                *code = apres;
                bouge
            }
            Self::Alias { .. }
            | Self::AppareilRevoque { .. }
            | Self::AppareilAtteste { .. }
            | Self::MachineModifiee { .. }
            | Self::CleMachineRevoquee { .. }
            | Self::AutorisationRevoquee { .. }
            | Self::CompteEfface { .. } => false,
        }
    }
}

/// Ré-estampille une table d'enregistrements, et rend ceux qui ont bougé —
/// tels qu'ils étaient, et tels qu'ils sont.
///
/// **Tout est relevé avant d'être réécrit** : on n'écrit pas dans une table
/// qu'on parcourt.
fn reestampiller_table<const N: usize, T: Reestampillable + Copy>(
    ecriture: &WriteTransaction,
    table: TableDefinition<'_, &[u8], &[u8; N]>,
    lire: impl Fn(&[u8; N]) -> Result<T, asl_registre::Faute>,
    ecrire: impl Fn(&T, &mut [u8; N]),
    de: Identifiant,
    vers: Identifiant,
) -> Result<Vec<(Vec<u8>, T, T)>, Faute> {
    let mut table = ecriture.open_table(table)?;
    let mut bouges = Vec::new();
    for entree in table.iter()? {
        let (clef, valeur) = entree?;
        let avant = lire(valeur.value())?;
        let mut apres = avant;
        if apres.reestampiller(de, vers) {
            bouges.push((clef.value().to_vec(), avant, apres));
        }
    }
    for (clef, _, apres) in &bouges {
        let mut octets = [0_u8; N];
        ecrire(apres, &mut octets);
        table.insert(clef.as_slice(), &octets)?;
    }
    Ok(bouges)
}

/// Passe sous `vers` tout ce que `de` a estampillé, dans cette transaction, et
/// rend combien d'enregistrements et d'opérations ont bougé.
///
/// # L'INDEX DES ALIAS SUIT, PARCE QUE L'ESTAMPILLE EST DANS SA CLÉ
///
/// [`ALIAS`] range la réclamation dans la clé, en gros-boutiste, pour que le
/// titulaire soit la première de l'intervalle. Une réclamation qui change de
/// racine change donc de clé : l'ancienne part, la neuve entre, et l'ordre
/// entre réclamations d'un même alias est recalculé par la table elle-même.
///
/// # LE JOURNAL D'OPÉRATIONS AUSSI, CADRE PAR CADRE
///
/// Une opération journalisée sans identité partirait sur la voie sous seize
/// zéros, et l'enregistrement qu'elle porte aussi. Chaque cadre est relu,
/// ré-estampillé — l'en-tête et la charge —, et réécrit sous le même compteur,
/// avec le même instant d'écriture : la rétention ne voit rien.
fn reestampiller(
    ecriture: &WriteTransaction,
    de: Identifiant,
    vers: Identifiant,
) -> Result<usize, Faute> {
    let mut combien = 0_usize;

    let comptes = reestampiller_table(ecriture, COMPTES, Compte::lire, Compte::ecrire, de, vers)?;
    {
        let mut reclamations = ecriture.open_table(ALIAS)?;
        for (clef, avant, apres) in &comptes {
            if let Some(alias) = &avant.alias
                && avant.reclamation != apres.reclamation
            {
                reclamations
                    .remove(clef_de_reclamation(alias.octets(), avant.reclamation).as_slice())?;
                reclamations.insert(
                    clef_de_reclamation(alias.octets(), apres.reclamation).as_slice(),
                    clef.as_slice(),
                )?;
            }
        }
    }
    combien = combien.saturating_add(comptes.len());
    combien = combien.saturating_add(
        reestampiller_table(ecriture, MACHINES, Machine::lire, Machine::ecrire, de, vers)?.len(),
    );
    combien = combien.saturating_add(
        reestampiller_table(
            ecriture,
            APPAREILS,
            Appareil::lire,
            Appareil::ecrire,
            de,
            vers,
        )?
        .len(),
    );
    combien = combien.saturating_add(
        reestampiller_table(
            ecriture,
            POUSSEES,
            JetonPoussee::lire,
            JetonPoussee::ecrire,
            de,
            vers,
        )?
        .len(),
    );
    combien = combien.saturating_add(
        reestampiller_table(
            ecriture,
            DESCRIPTIONS,
            Description::lire,
            Description::ecrire,
            de,
            vers,
        )?
        .len(),
    );
    combien = combien.saturating_add(
        reestampiller_table(
            ecriture,
            ENROLEMENTS,
            Enrolement::lire,
            Enrolement::ecrire,
            de,
            vers,
        )?
        .len(),
    );
    combien = combien.saturating_add(
        reestampiller_table(ecriture, SERVICES, Service::lire, Service::ecrire, de, vers)?.len(),
    );
    combien = combien.saturating_add(
        reestampiller_table(
            ecriture,
            AUTORISATIONS,
            Autorisation::lire,
            Autorisation::ecrire,
            de,
            vers,
        )?
        .len(),
    );

    // ── LE JOURNAL D'OPÉRATIONS ─────────────────────────────────────────────
    let mut journal = ecriture.open_table(OPERATIONS)?;
    let mut bouges = Vec::new();
    for entree in journal.iter()? {
        let (compteur, valeur) = entree?;
        let valeur = valeur.value();
        let (estampille, mut operation, _) = Operation::lire(valeur.get(8..).unwrap_or_default())?;
        let apres = sous(estampille, de, vers);
        let bouge = operation.reestampiller(de, vers);
        if bouge || apres != estampille {
            let mut cadre = [0_u8; OPERATION_OCTETS_MAX];
            let ecrits = operation.ecrire(apres, &mut cadre);
            let mut neuve = Vec::with_capacity(ecrits.saturating_add(8));
            neuve.extend_from_slice(valeur.get(..8).unwrap_or_default());
            neuve.extend_from_slice(cadre.get(..ecrits).unwrap_or_default());
            bouges.push((compteur.value(), neuve));
        }
    }
    for (compteur, valeur) in &bouges {
        journal.insert(*compteur, valeur.as_slice())?;
    }
    Ok(combien.saturating_add(bouges.len()))
}
