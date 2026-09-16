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
//! **L'application des opérations venues de l'autre racine n'est pas écrite.**
//! Elle a ses règles (`replication.md` §3.2), elle hisse le compteur
//! ([`Entrepot::hisser_le_compteur`]) et avance le curseur
//! ([`Entrepot::poser_curseur`]) ; ce fichier porte ce qu'elle trouvera en
//! arrivant, et rien de ce qu'elle décidera.

use std::path::Path;

use asl_id::{Genre, Identifiant};
use asl_registre::{
    APPAREIL_OCTETS, AUTORISATION_OCTETS, AliasRange, Appareil, Attestation, Autorisation,
    CLE_APPAREIL_OCTETS, CLE_OCTETS, CLEF_JOURNAL_OCTETS, COMPTE_OCTETS, Cadre, Capacites, CleLiee,
    Compte, DESCRIPTION_OCTETS, Description, EMPREINTE_OCTETS, ENROLEMENT_OCTETS, ENTREE_OCTETS,
    ESTAMPILLE_OCTETS, Enrolement, EntreeJournal, Estampille, IDENTIFIANT_OCTETS, JetonPoussee,
    JetonRange, MACHINE_OCTETS, Machine, NomRange, OPERATION_OCTETS_MAX, Operation, POUSSEE_OCTETS,
    Plateforme, Portee, Provenance, SERVICE_OCTETS, Service, Systeme,
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

/// Le format de cet entrepôt : le second, celui de l'estampille.
///
/// Le premier n'était pas numéroté — il n'y avait rien d'autre —, et c'est son
/// absence qui le désigne.
const FORMAT: u64 = 2;

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
    /// # Errors
    ///
    /// [`Faute::Base`] si le fichier ne peut être ni ouvert ni créé,
    /// [`Faute::Format`] s'il est d'un format inconnu, [`Faute::Enregistrement`]
    /// si une base ancienne porte un enregistrement illisible.
    pub fn ouvrir(chemin: &Path, racine: Identifiant) -> Result<Self, Faute> {
        let base = Database::create(chemin)?;
        {
            let ecriture = base.begin_write()?;
            let format = {
                let table = ecriture.open_table(RACINE)?;
                table.get(CLEF_DU_FORMAT)?.map(|quoi| quoi.value())
            };
            match format {
                Some(FORMAT) => {}
                Some(lu) => return Err(Faute::Format { lu }),
                None => {
                    // **PAS DE FORMAT, MAIS DES TABLES : C'EST UNE BASE
                    // ANCIENNE.** Une base neuve n'a rien du tout, et reçoit
                    // son format avec ses tables.
                    let ancienne = ecriture
                        .list_tables()?
                        .any(|table| table.name() == COMPTES.name());
                    if ancienne {
                        reprendre(&ecriture, racine)?;
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
        })
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
    /// Rend `false` si le compte n'existe pas.
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

    /// Rend ce compte, s'il existe.
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
                revoque: false,
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

    /// Marque cet appareil révoqué, et rend ce qu'il était.
    ///
    /// **LE JETON PART AVEC L'APPAREIL, ET DANS LA MÊME ÉCRITURE.**
    /// `docs/modele.md` §2.6 : il est lié à l'appareil et se révoque avec lui.
    /// L'appareil, lui, reste marqué : l'écran d'après une perte doit MONTRER
    /// ce qu'on a retiré. **La description reste** aussi, pour la même raison.
    ///
    /// Rend `None` si aucun appareil ne répond à cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn revoquer_appareil(&self, quel: Identifiant) -> Result<Option<Appareil>, Faute> {
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
            let estampille = estampiller(&ecriture, self.racine)?;
            let mut octets = [0_u8; APPAREIL_OCTETS];
            Appareil {
                estampille,
                revoque: true,
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
                &Operation::AppareilRevoque { appareil: quel },
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
            if appareil.revoque {
                suite.ajouter(
                    appareil.estampille,
                    &Operation::AppareilRevoque { appareil: quel },
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
fn reprendre(ecriture: &WriteTransaction, racine: Identifiant) -> Result<(), Faute> {
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
        Appareil::lire_ancien,
        Appareil::ecrire,
    )?;
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
    Ok(())
}
