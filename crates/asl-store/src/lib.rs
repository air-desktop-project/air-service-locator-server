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

use std::path::Path;

use asl_id::Identifiant;
use asl_registre::{
    APPAREIL_OCTETS, AUTORISATION_OCTETS, Appareil, Autorisation, CLEF_JOURNAL_OCTETS,
    COMPTE_OCTETS, Compte, ENROLEMENT_OCTETS, ENTREE_OCTETS, Enrolement, EntreeJournal,
    IDENTIFIANT_OCTETS, JetonPoussee, MACHINE_OCTETS, Machine, POUSSEE_OCTETS, SERVICE_OCTETS,
    Service,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

// ── Les tables ──────────────────────────────────────────────────────────────

/// Les comptes, par identifiant.
const COMPTES: TableDefinition<'_, &[u8], &[u8; COMPTE_OCTETS]> = TableDefinition::new("comptes");

/// Les machines, par identifiant.
const MACHINES: TableDefinition<'_, &[u8], &[u8; MACHINE_OCTETS]> =
    TableDefinition::new("machines");

/// L'index des alias : un alias vers le compte qui l'a choisi.
///
/// # C'EST UN INDEX, DONC UNE SECONDE VÉRITÉ — ET IL FAUT LE DIRE
///
/// L'alias vit AUSSI dans l'enregistrement du compte. Les deux doivent rester
/// d'accord, et c'est [`Entrepot::poser_compte`] qui en répond : il efface
/// l'ancienne entrée d'index avant d'écrire la nouvelle.
///
/// La règle est écrite là plutôt que confiée à l'appelant, parce qu'un index qui
/// désigne un compte dont l'alias a changé rendrait un identifiant à qui
/// demanderait l'ancien nom.
const ALIAS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("alias");

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
/// # POURQUOI IL A FALLU L'AJOUTER
///
/// `MACHINES` est indexée par machine, et porte son propriétaire à l'intérieur.
/// Répondre à « quelles sont les machines de ce compte ? » demandait donc de
/// balayer TOUTES les machines de l'annuaire — un balayage qui grandit avec
/// l'annuaire entier, quand la réponse ne dépend que d'un compte.
///
/// C'est la même forme que [`SERVICES_PAR_NOM`] : le compte en tête fait que ses
/// machines se suivent, donc qu'un intervalle remplace un balayage.
const MACHINES_PAR_COMPTE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("machines-par-compte");

/// L'index des appareils d'un compte : `compte ‖ appareil`.
///
/// # LA MÊME FORME QUE [`MACHINES_PAR_COMPTE`], ET POUR LA MÊME RAISON
///
/// `APPAREILS` est indexée par appareil, et porte son propriétaire à l'intérieur.
/// Répondre à « quels sont les appareils de ce compte ? » — ce que
/// `GET /v1/appareils` demande — imposait sinon un balayage de TOUS les appareils
/// de l'annuaire. Le compte en tête fait que les siens se suivent, donc qu'un
/// intervalle remplace le balayage.
///
/// **Un appareil créé AVANT cet index n'y figure pas**, et ne se listera qu'une
/// fois réécrit. C'est le même compromis que `MACHINES_PAR_COMPTE` a accepté à sa
/// naissance ; il est tenable ici parce qu'un appareil ne vient jamais d'ailleurs
/// et qu'aucun déploiement n'en porte encore de réel.
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
/// # LE SECOND SENS, QUE LA RÉSOLUTION N'AVAIT PAS BESOIN DE CONNAÎTRE
///
/// [`AUTORISATIONS_RECUES`] dit pourquoi l'on indexe par bénéficiaire : c'est le
/// sens dans lequel une résolution interroge. **`GET /v1/autorisations` demande
/// les DEUX** (`protocole.md` §2.2) — « ce que j'ai accordé, ce qu'on m'a
/// accordé » —, et le premier n'avait aucun index.
///
/// # CETTE TABLE EST NEUVE, ET RIEN NE LA REMPLIT RÉTROACTIVEMENT
///
/// Une autorisation posée avant ce commit n'y figure pas : elle se lira encore
/// par son identifiant et par le sens « reçue », mais pas dans « accordées ».
///
/// **C'EST SANS CONSÉQUENCE PARCE QUE RIEN N'EST DÉPLOYÉ**, et cela ne le serait
/// plus après la bascule. Le jour où une table s'ajoutera à un annuaire qui
/// tourne, il faudra une reprise — et elle ne s'improvise pas.
const AUTORISATIONS_ACCORDEES: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("autorisations-accordees");

/// Le journal des requêtes (C18).
const JOURNAL: TableDefinition<'_, &[u8], &[u8; ENTREE_OCTETS]> = TableDefinition::new("journal");

/// Le rang qui départage deux entrées de la même milliseconde.
const RANG: TableDefinition<'_, &str, u64> = TableDefinition::new("rang");

/// La clé sous laquelle le rang du journal est rangé.
const CLEF_DU_RANG: &str = "journal";

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
    /// Un identifiant rangé n'a pas la longueur d'un identifiant.
    Longueur {
        /// Ce qui a été trouvé.
        obtenue: usize,
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
            Self::Longueur { obtenue } => {
                write!(sortie, "un identifiant de {obtenue} octets a été trouvé")
            }
        }
    }
}

impl std::error::Error for Faute {}

impl<E: Into<redb::Error>> From<E> for Faute {
    fn from(quoi: E) -> Self {
        Self::Base(quoi.into())
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
        .and_then(asl_id::Genre::depuis_prefixe)
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

/// La clé d'une autorisation dans l'index des reçues : le bénéficiaire, puis
/// l'autorisation.
///
/// **L'AUTORISATION EN QUEUE EST CE QUI PERMET D'EN AVOIR PLUSIEURS.** Sans
/// elle, deux autorisations au même compte s'écraseraient, et l'on n'en verrait
/// qu'une — celle qui, par malchance, n'accorderait pas ce qu'il fallait.
fn clef_recue(beneficiaire: Identifiant, autorisation: Identifiant) -> Vec<u8> {
    paire(beneficiaire, autorisation)
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

// ── L'entrepôt ──────────────────────────────────────────────────────────────

/// L'entrepôt durable d'un annuaire.
pub struct Entrepot {
    /// La base, un seul fichier.
    base: Database,
}

impl Entrepot {
    /// Ouvre l'entrepôt à cet endroit, en le créant s'il n'existe pas.
    ///
    /// **LES TABLES SONT CRÉÉES ICI, ET PAS À LA PREMIÈRE ÉCRITURE.** Une table
    /// qui naîtrait au premier `insert` ferait échouer toute LECTURE antérieure
    /// avec « table inexistante » — une base neuve rendrait donc une erreur là
    /// où elle doit rendre « rien ».
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si le fichier ne peut être ni ouvert ni créé.
    pub fn ouvrir(chemin: &Path) -> Result<Self, Faute> {
        let base = Database::create(chemin)?;
        {
            let ecriture = base.begin_write()?;
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
            // **CES TROIS-LÀ MANQUAIENT, ET C'ÉTAIT UN DÉFAUT.** Une table que
            // redb n'a jamais vue n'existe pas, et l'ouvrir en LECTURE rend
            // `TableDoesNotExist` — pas un intervalle vide. Sur une base neuve,
            // lister les machines d'un compte qui n'en a aucune échouait donc,
            // et l'étage 3 traduisait cet échec en `404` là où le protocole
            // promet `200` et un tableau vide.
            //
            // Les créer ici les rend vides plutôt qu'absentes, ce qui est la
            // même chose pour un lecteur et pas du tout la même pour redb.
            ecriture.open_table(AUTORISATIONS_ACCORDEES)?;
            ecriture.open_table(MACHINES_PAR_COMPTE)?;
            ecriture.open_table(APPAREILS_PAR_COMPTE)?;
            ecriture.open_table(POUSSEES)?;
            ecriture.open_table(JOURNAL)?;
            ecriture.open_table(RANG)?;
            ecriture.commit()?;
        }
        Ok(Self { base })
    }

    // ── Les comptes ─────────────────────────────────────────────────────────

    /// Écrit ce compte, et met son index d'alias d'accord avec lui.
    ///
    /// # Errors
    ///
    /// [`Faute::AliasPris`] si l'alias demandé appartient à un autre compte, et
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_compte(&self, qui: Identifiant, compte: &Compte) -> Result<(), Faute> {
        let clef_compte = clef(qui);
        let ecriture = self.base.begin_write()?;
        {
            let mut comptes = ecriture.open_table(COMPTES)?;
            let mut alias = ecriture.open_table(ALIAS)?;

            // ── L'ALIAS DEMANDÉ EST-IL LIBRE ? ──────────────────────────────
            //
            // Libre, ou déjà le nôtre. Le refuser quand il est déjà le nôtre
            // rendrait impossible de réécrire un compte sans changer son alias.
            if let Some(voulu) = &compte.alias {
                let texte = core::str::from_utf8(voulu.octets()).unwrap_or("");
                if let Some(pris) = alias.get(texte)? {
                    let deja = depuis_clef(pris.value())?;
                    if deja != qui {
                        return Err(Faute::AliasPris);
                    }
                }
            }

            // ── L'ANCIEN ALIAS DE CE COMPTE DOIT PARTIR ─────────────────────
            //
            // Sans cela, l'index rendrait encore cet identifiant pour un nom que
            // son propriétaire n'a plus.
            if let Some(ancien) = comptes.get(clef_compte.as_slice())? {
                let ancien = Compte::lire(ancien.value()).map_err(Faute::Enregistrement)?;
                if let Some(parti) = &ancien.alias {
                    let texte = core::str::from_utf8(parti.octets()).unwrap_or("");
                    alias.remove(texte)?;
                }
            }

            let mut octets = [0_u8; COMPTE_OCTETS];
            compte.ecrire(&mut octets);
            comptes.insert(clef_compte.as_slice(), &octets)?;

            if let Some(voulu) = &compte.alias {
                let texte = core::str::from_utf8(voulu.octets()).unwrap_or("");
                alias.insert(texte, clef_compte.as_slice())?;
            }
        }
        ecriture.commit()?;
        Ok(())
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
            Some(trouve) => Compte::lire(trouve.value())
                .map(Some)
                .map_err(Faute::Enregistrement),
            None => Ok(None),
        }
    }

    /// À qui appartient cet alias ?
    ///
    /// **C'est tout ce que l'alias rend**, et c'est écrit dans les
    /// spécifications : un identifiant, jamais un profil.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Longueur`] si l'index est corrompu.
    pub fn compte_par_alias(&self, alias: &str) -> Result<Option<Identifiant>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(ALIAS)?;
        match table.get(alias)? {
            Some(trouve) => depuis_clef(trouve.value()).map(Some),
            None => Ok(None),
        }
    }

    // ── Les machines ────────────────────────────────────────────────────────

    /// Écrit cette machine.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_machine(&self, qui: Identifiant, machine: &Machine) -> Result<(), Faute> {
        let mut octets = [0_u8; MACHINE_OCTETS];
        machine.ecrire(&mut octets);
        let ecriture = self.base.begin_write()?;
        {
            let mut machines = ecriture.open_table(MACHINES)?;
            machines.insert(clef(qui).as_slice(), &octets)?;
            // **LE PROPRIÉTAIRE NE CHANGE JAMAIS** : une machine qu'on
            // réécrirait pour un autre compte serait une autre machine. Il n'y a
            // donc pas d'ancienne entrée d'index à retirer, contrairement à
            // l'alias d'un compte ou au nom d'un service.
            let mut par_compte = ecriture.open_table(MACHINES_PAR_COMPTE)?;
            par_compte.insert(
                paire(machine.proprietaire, qui).as_slice(),
                clef(qui).as_slice(),
            )?;
        }
        ecriture.commit()?;
        Ok(())
    }

    /// Rend cette machine, si elle existe.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn machine(&self, qui: Identifiant) -> Result<Option<Machine>, Faute> {
        let lecture = self.base.begin_read()?;
        let machines = lecture.open_table(MACHINES)?;
        match machines.get(clef(qui).as_slice())? {
            Some(trouve) => Machine::lire(trouve.value())
                .map(Some)
                .map_err(Faute::Enregistrement),
            None => Ok(None),
        }
    }

    // ── Les services ────────────────────────────────────────────────────────

    /// Les machines d'un compte, avec leur identifiant.
    ///
    /// **UN INTERVALLE, ET NON UN BALAYAGE** — voir [`MACHINES_PAR_COMPTE`].
    ///
    /// # Erreurs
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
                trouvees.push((
                    quelle,
                    Machine::lire(brute.value()).map_err(Faute::Enregistrement)?,
                ));
            }
        }
        Ok(trouvees)
    }

    /// Les appareils d'un compte, révoqués compris, avec leur identifiant.
    ///
    /// **UN INTERVALLE, ET NON UN BALAYAGE** — voir [`APPAREILS_PAR_COMPTE`]. Une
    /// entrée d'index qui a survécu à un appareil disparu est SAUTÉE, comme pour
    /// les machines : le magasin principal a le dernier mot.
    ///
    /// # Erreurs
    ///
    /// [`Faute::Base`], [`Faute::Enregistrement`].
    pub fn appareils_de_compte(
        &self,
        compte: Identifiant,
    ) -> Result<Vec<(Identifiant, Appareil)>, Faute> {
        let lecture = self.base.begin_read()?;
        let index = lecture.open_table(APPAREILS_PAR_COMPTE)?;
        let table = lecture.open_table(APPAREILS)?;

        let (debut, fin) = intervalle(compte);
        let mut trouves = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, valeur) = entree?;
            let quel = depuis_clef(valeur.value())?;
            if let Some(brut) = table.get(valeur.value())? {
                trouves.push((
                    quel,
                    Appareil::lire(brut.value()).map_err(Faute::Enregistrement)?,
                ));
            }
        }
        Ok(trouves)
    }

    /// Les services d'une machine, avec leur identifiant.
    ///
    /// **UN INTERVALLE, ET NON UN BALAYAGE** : [`SERVICES_PAR_NOM`] range la
    /// machine en tête, précisément pour que « tous les services de cette
    /// machine » en soit un.
    ///
    /// # Erreurs
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
                trouves.push((
                    quel,
                    Service::lire(brut.value()).map_err(Faute::Enregistrement)?,
                ));
            }
        }
        Ok(trouves)
    }

    /// Les autorisations qu'un compte a ACCORDÉES, avec leur identifiant.
    ///
    /// **RÉVOQUÉES COMPRISES** : `protocole.md` §2.2 veut que l'écran montre ce
    /// qu'on a retiré. Les filtrer ici les rendrait invisibles à l'application
    /// qui vient de les retirer.
    ///
    /// # Erreurs
    ///
    /// [`Faute::Base`], [`Faute::Enregistrement`].
    pub fn autorisations_accordees(
        &self,
        par: Identifiant,
    ) -> Result<Vec<(Identifiant, Autorisation)>, Faute> {
        self.autorisations_par(AUTORISATIONS_ACCORDEES, par)
    }

    /// Les autorisations qu'un compte a REÇUES, avec leur identifiant.
    ///
    /// [`autorisations_recues`](Entrepot::autorisations_recues) rend les mêmes
    /// enregistrements sans leur identifiant : c'est tout ce dont une résolution
    /// a besoin. **Une liste, elle, doit pouvoir se désigner** — c'est
    /// l'identifiant qu'on passe à `DELETE /v1/autorisations/{g}`.
    ///
    /// # Erreurs
    ///
    /// [`Faute::Base`], [`Faute::Enregistrement`].
    pub fn autorisations_recues_nommees(
        &self,
        a: Identifiant,
    ) -> Result<Vec<(Identifiant, Autorisation)>, Faute> {
        self.autorisations_par(AUTORISATIONS_RECUES, a)
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
                trouvees.push((
                    quelle,
                    Autorisation::lire(brute.value()).map_err(Faute::Enregistrement)?,
                ));
            }
        }
        Ok(trouvees)
    }

    /// Écrit ce service, et met son index de nom d'accord avec lui.
    ///
    /// # L'INDEX SUIT LE SERVICE, COMME L'ALIAS SUIT LE COMPTE
    ///
    /// Renommer un service doit retirer l'ancien nom : sans cela, l'ancien
    /// rendrait encore un identifiant, et deux noms désigneraient un service qui
    /// n'en revendique qu'un.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse, [`Faute::Enregistrement`] si l'ancien
    /// enregistrement est corrompu.
    pub fn poser_service(&self, quel: Identifiant, service: &Service) -> Result<(), Faute> {
        let clef_service = clef(quel);
        let ecriture = self.base.begin_write()?;
        {
            let mut services = ecriture.open_table(SERVICES)?;
            let mut par_nom = ecriture.open_table(SERVICES_PAR_NOM)?;

            if let Some(ancien) = services.get(clef_service.as_slice())? {
                let ancien = Service::lire(ancien.value()).map_err(Faute::Enregistrement)?;
                par_nom.remove(clef_de_nom(ancien.machine, ancien.nom.octets()).as_slice())?;
            }

            let mut octets = [0_u8; SERVICE_OCTETS];
            service.ecrire(&mut octets);
            services.insert(clef_service.as_slice(), &octets)?;
            par_nom.insert(
                clef_de_nom(service.machine, service.nom.octets()).as_slice(),
                clef_service.as_slice(),
            )?;
        }
        ecriture.commit()?;
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
            Some(trouve) => Service::lire(trouve.value())
                .map(Some)
                .map_err(Faute::Enregistrement),
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

    // ── Les autorisations ───────────────────────────────────────────────────

    /// Écrit cette autorisation, et l'indexe par son bénéficiaire.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_autorisation(
        &self,
        quelle: Identifiant,
        autorisation: &Autorisation,
    ) -> Result<(), Faute> {
        let mut octets = [0_u8; AUTORISATION_OCTETS];
        autorisation.ecrire(&mut octets);
        let clef_autorisation = clef(quelle);
        let ecriture = self.base.begin_write()?;
        {
            let mut table = ecriture.open_table(AUTORISATIONS)?;
            table.insert(clef_autorisation.as_slice(), &octets)?;
            let mut recues = ecriture.open_table(AUTORISATIONS_RECUES)?;
            // **LE BÉNÉFICIAIRE NE CHANGE JAMAIS** : une autorisation qu'on
            // réécrirait pour un autre compte serait une autre autorisation. Il
            // n'y a donc pas d'ancienne entrée d'index à retirer, contrairement
            // à l'alias d'un compte ou au nom d'un service.
            recues.insert(
                clef_recue(autorisation.a, quelle).as_slice(),
                clef_autorisation.as_slice(),
            )?;
            // L'autre sens, pour `GET /v1/autorisations`. Même remarque : le
            // donneur ne change pas plus que le bénéficiaire.
            let mut accordees = ecriture.open_table(AUTORISATIONS_ACCORDEES)?;
            accordees.insert(
                paire(autorisation.par, quelle).as_slice(),
                clef_autorisation.as_slice(),
            )?;
        }
        ecriture.commit()?;
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
            Some(brut) => Ok(Some(
                Autorisation::lire(brut.value()).map_err(Faute::Enregistrement)?,
            )),
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
    /// l'écarte, et à un seul endroit.
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
        let trouve;
        {
            let mut table = ecriture.open_table(AUTORISATIONS)?;
            trouve = match table.get(clef_autorisation.as_slice())? {
                Some(brut) => {
                    Some(Autorisation::lire(brut.value()).map_err(Faute::Enregistrement)?)
                }
                None => None,
            };
            if let Some(autorisation) = &trouve {
                let mut octets = [0_u8; AUTORISATION_OCTETS];
                Autorisation {
                    revoquee: true,
                    ..*autorisation
                }
                .ecrire(&mut octets);
                table.insert(clef_autorisation.as_slice(), &octets)?;
            }
            // **L'INDEX DES REÇUES NE BOUGE PAS**, et c'est voulu : le
            // bénéficiaire doit continuer de voir ce qu'on lui a retiré. C'est
            // `couvre` qui refuse, pas l'index qui cache.
        }
        ecriture.commit()?;
        Ok(trouve)
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
        let lecture = self.base.begin_read()?;
        let recues = lecture.open_table(AUTORISATIONS_RECUES)?;
        let table = lecture.open_table(AUTORISATIONS)?;

        // **UN INTERVALLE, ET NON UN BALAYAGE** : le bénéficiaire est en tête de
        // la clé, donc ses autorisations se suivent.
        let debut = clef(par);
        let mut fin = clef(par).to_vec();
        fin.push(0xFF);
        let mut trouvees = Vec::new();
        for entree in recues.range(debut.as_slice()..fin.as_slice())? {
            let (_, valeur) = entree?;
            if let Some(brute) = table.get(valeur.value())? {
                trouvees.push(Autorisation::lire(brute.value()).map_err(Faute::Enregistrement)?);
            }
        }
        Ok(trouvees)
    }

    // ── Les appareils ───────────────────────────────────────────────────────

    /// Écrit cet appareil.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_appareil(&self, quel: Identifiant, appareil: &Appareil) -> Result<(), Faute> {
        let mut octets = [0_u8; APPAREIL_OCTETS];
        appareil.ecrire(&mut octets);
        let ecriture = self.base.begin_write()?;
        {
            let mut table = ecriture.open_table(APPAREILS)?;
            table.insert(clef(quel).as_slice(), &octets)?;
            // **LE PROPRIÉTAIRE NE CHANGE JAMAIS**, comme pour une machine : un
            // appareil qu'on réécrirait pour un autre compte serait un autre
            // appareil. Il n'y a donc pas d'ancienne entrée d'index à retirer, et
            // réécrire le même appareil (une révocation) réinscrit la même paire.
            let mut par_compte = ecriture.open_table(APPAREILS_PAR_COMPTE)?;
            par_compte.insert(
                paire(appareil.proprietaire, quel).as_slice(),
                clef(quel).as_slice(),
            )?;
        }
        ecriture.commit()?;
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
            Some(brut) => Ok(Some(
                Appareil::lire(brut.value()).map_err(Faute::Enregistrement)?,
            )),
            None => Ok(None),
        }
    }

    /// Marque cet appareil révoqué, et rend ce qu'il était.
    ///
    /// # LIRE ET ÉCRIRE SONT UNE SEULE TRANSACTION
    ///
    /// La décision de révoquer se prend sur le propriétaire de l'appareil, qu'il
    /// faut donc lire ; l'écrire ensuite dans une autre transaction laisserait
    /// deux révocations concurrentes se croiser. Ce n'est pas grave ici — les
    /// deux écriraient la même chose — mais la forme est celle qu'il faudra le
    /// jour où le champ portera une date.
    ///
    /// Rend `None` si aucun appareil ne répond à cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn revoquer_appareil(&self, quel: Identifiant) -> Result<Option<Appareil>, Faute> {
        let clef_appareil = clef(quel);
        let ecriture = self.base.begin_write()?;
        let trouve;
        {
            let mut table = ecriture.open_table(APPAREILS)?;
            trouve = match table.get(clef_appareil.as_slice())? {
                Some(brut) => Some(Appareil::lire(brut.value()).map_err(Faute::Enregistrement)?),
                None => None,
            };
            if let Some(appareil) = &trouve {
                let mut octets = [0_u8; APPAREIL_OCTETS];
                Appareil {
                    revoque: true,
                    ..*appareil
                }
                .ecrire(&mut octets);
                table.insert(clef_appareil.as_slice(), &octets)?;
            }
        }
        // **LE JETON PART AVEC L'APPAREIL, ET DANS LA MÊME ÉCRITURE.**
        // `docs/modele.md` §2.6 : il est lié à l'appareil et se révoque avec
        // lui. Le laisser derrière ferait continuer les notifications d'un
        // compte vers un téléphone qu'on vient de déclarer perdu — c'est-à-dire
        // vers celui qui l'a.
        //
        // L'appareil, lui, reste marqué : l'écran d'après une perte doit
        // MONTRER ce qu'on a retiré. Le jeton n'a rien à montrer.
        {
            let mut table = ecriture.open_table(POUSSEES)?;
            table.remove(clef_appareil.as_slice())?;
        }
        ecriture.commit()?;
        Ok(trouve)
    }

    // ── Les jetons de poussée ───────────────────────────────────────────────

    /// Dépose ou renouvelle le jeton de cet appareil.
    ///
    /// **UN SEUL JETON PAR APPAREIL, ET LE NEUF REMPLACE L'ANCIEN.** Apple et
    /// Google font tourner les leurs : en garder deux ferait envoyer chaque
    /// notification en double, dont une à un jeton mort — et un jeton mort
    /// répété finit par faire retirer le droit d'en envoyer.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_jeton(&self, appareil: Identifiant, jeton: &JetonPoussee) -> Result<(), Faute> {
        let mut octets = [0_u8; POUSSEE_OCTETS];
        jeton.ecrire(&mut octets);
        let ecriture = self.base.begin_write()?;
        {
            let mut table = ecriture.open_table(POUSSEES)?;
            table.insert(clef(appareil).as_slice(), &octets)?;
        }
        ecriture.commit()?;
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
            Some(brut) => Ok(Some(
                JetonPoussee::lire(brut.value()).map_err(Faute::Enregistrement)?,
            )),
            None => Ok(None),
        }
    }

    /// Retire le jeton de cet appareil. Rend `true` s'il y en avait un.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn retirer_jeton(&self, appareil: Identifiant) -> Result<bool, Faute> {
        let ecriture = self.base.begin_write()?;
        let avait;
        {
            let mut table = ecriture.open_table(POUSSEES)?;
            avait = table.remove(clef(appareil).as_slice())?.is_some();
        }
        ecriture.commit()?;
        Ok(avait)
    }

    // ── Les codes d'enrôlement ──────────────────────────────────────────────

    /// Émet un code pour cette machine, **et retire celui qu'elle avait**.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] si la base refuse.
    pub fn poser_enrolement(&self, empreinte: &[u8], enrolement: &Enrolement) -> Result<(), Faute> {
        let mut octets = [0_u8; ENROLEMENT_OCTETS];
        enrolement.ecrire(&mut octets);
        let clef_machine = clef(enrolement.machine);
        let ecriture = self.base.begin_write()?;
        {
            let mut codes = ecriture.open_table(ENROLEMENTS)?;
            let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;

            // **LE PRÉCÉDENT MEURT AVEC L'ÉMISSION DU SUIVANT**, et dans la même
            // transaction : un administrateur qui redemande un code parce qu'il
            // a perdu le premier ne doit pas laisser derrière lui un secret
            // vivant que plus personne ne surveille.
            if let Some(ancienne) = index.get(clef_machine.as_slice())? {
                codes.remove(ancienne.value())?;
            }
            codes.insert(empreinte, &octets)?;
            index.insert(clef_machine.as_slice(), empreinte)?;
        }
        ecriture.commit()?;
        Ok(())
    }

    /// Consomme le code de cette empreinte, et rend ce qu'il désignait.
    ///
    /// # LIRE ET EFFACER SONT UNE SEULE TRANSACTION
    ///
    /// « À usage unique » ne se tient pas en deux temps : deux enrôlements
    /// simultanés avec le même code liraient tous deux un code vivant, et le
    /// second effacerait ce que le premier avait déjà consommé. Ils lieraient
    /// alors DEUX clés à la même machine, dont une que son propriétaire ignore.
    ///
    /// Rend `None` si rien ne répond à cette empreinte — un code inconnu et un
    /// code déjà consommé sont **le même fait**, puisqu'un code consommé est
    /// supprimé.
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
                Some(brut) => Some(Enrolement::lire(brut.value()).map_err(Faute::Enregistrement)?),
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
    /// grandir sans fin.
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
                let enrolement = Enrolement::lire(valeur.value()).map_err(Faute::Enregistrement)?;
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
    /// quatre-vingt-dix jours » est un intervalle de clés. Sans cet ordre, il
    /// faudrait lire le journal entier pour en effacer le début — et une
    /// rétention qui coûte cher est une rétention qu'on finit par désactiver.
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
        Ok(redb::ReadableTableMetadata::len(&journal)?)
    }

    // ── La rupture de confiance (C17) ───────────────────────────────────────

    /// Efface tout ce qui vient de cet annuaire, et rend combien.
    ///
    /// # LE JOURNAL N'EST PAS TOUCHÉ, ET C'EST UNE EXCEPTION ÉCRITE
    ///
    /// C17 dit « rompre une relation efface ce qui en vient — **sauf le
    /// journal** ». La raison est en tête de `docs/journal.md` : ce journal a
    /// une fonction DÉFENSIVE. C'est lui qui permet de constater qu'un pair a
    /// essayé de nous faire avaler ce dont il n'était pas l'autorité, et une
    /// rupture se décide sur des faits. L'effacer avec la relation effacerait la
    /// preuve de ce qui a motivé la rupture.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn oublier_ce_qui_vient_de(&self, annuaire: Identifiant) -> Result<usize, Faute> {
        let ecriture = self.base.begin_write()?;
        let mut combien = 0_usize;
        {
            let mut comptes = ecriture.open_table(COMPTES)?;
            let mut alias = ecriture.open_table(ALIAS)?;
            let mut condamnes = Vec::new();
            for entree in comptes.iter()? {
                let (clef, valeur) = entree?;
                let compte = Compte::lire(valeur.value()).map_err(Faute::Enregistrement)?;
                if compte.provenance.vient_de(annuaire) {
                    condamnes.push((clef.value().to_vec(), compte.alias));
                }
            }
            for (clef, porte) in &condamnes {
                comptes.remove(clef.as_slice())?;
                // **L'INDEX PART AVEC LE COMPTE.** Un alias resté seul rendrait
                // l'identifiant d'un compte qui n'existe plus.
                if let Some(nom) = porte {
                    alias.remove(core::str::from_utf8(nom.octets()).unwrap_or(""))?;
                }
            }
            combien = combien.saturating_add(condamnes.len());

            let mut machines = ecriture.open_table(MACHINES)?;
            let mut condamnees = Vec::new();
            for entree in machines.iter()? {
                let (clef, valeur) = entree?;
                let machine = Machine::lire(valeur.value()).map_err(Faute::Enregistrement)?;
                if machine.provenance.vient_de(annuaire) {
                    condamnees.push(clef.value().to_vec());
                }
            }
            for clef in &condamnees {
                machines.remove(clef.as_slice())?;
            }
            combien = combien.saturating_add(condamnees.len());

            // ── LES SERVICES, ET LEUR INDEX PAR NOM ─────────────────────────
            //
            // **Ils manquaient**, et C17 dit exactement comment cette contrainte
            // tombe : « par un `INSERT` ajouté à la hâte, jamais par une
            // décision ». C'était le cas — un service porte sa provenance depuis
            // le premier jour, et la rupture ne l'atteignait pas.
            let mut services = ecriture.open_table(SERVICES)?;
            let mut par_nom = ecriture.open_table(SERVICES_PAR_NOM)?;
            let mut condamnes_services = Vec::new();
            for entree in services.iter()? {
                let (clef, valeur) = entree?;
                let service = Service::lire(valeur.value()).map_err(Faute::Enregistrement)?;
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

            // ── LES AUTORISATIONS, ET L'INDEX DES REÇUES ────────────────────
            let mut autorisations = ecriture.open_table(AUTORISATIONS)?;
            let mut recues = ecriture.open_table(AUTORISATIONS_RECUES)?;
            let mut condamnees_aretes = Vec::new();
            for entree in autorisations.iter()? {
                let (clef_brute, valeur) = entree?;
                let autorisation =
                    Autorisation::lire(valeur.value()).map_err(Faute::Enregistrement)?;
                if autorisation.provenance.vient_de(annuaire) {
                    let quelle = depuis_clef(clef_brute.value())?;
                    condamnees_aretes.push((
                        clef_brute.value().to_vec(),
                        clef_recue(autorisation.a, quelle),
                    ));
                }
            }
            for (clef_autorisation, clef_index) in &condamnees_aretes {
                autorisations.remove(clef_autorisation.as_slice())?;
                recues.remove(clef_index.as_slice())?;
            }
            combien = combien.saturating_add(condamnees_aretes.len());

            // ── LES APPAREILS ───────────────────────────────────────────────
            //
            // Un appareil ne vient jamais d'ailleurs aujourd'hui — il n'y a rien
            // à fédérer dans un téléphone. **Il porte sa provenance quand même**,
            // parce que C17 ne dit pas « tout enregistrement susceptible de
            // venir d'ailleurs » : un champ qu'on omet parce qu'on croit savoir
            // qu'il vaudra toujours la même chose est un champ qu'on ajoutera
            // trop tard.
            let mut appareils = ecriture.open_table(APPAREILS)?;
            let mut condamnes_appareils = Vec::new();
            for entree in appareils.iter()? {
                let (clef, valeur) = entree?;
                let appareil = Appareil::lire(valeur.value()).map_err(Faute::Enregistrement)?;
                if appareil.provenance.vient_de(annuaire) {
                    condamnes_appareils.push(clef.value().to_vec());
                }
            }
            for clef in &condamnes_appareils {
                appareils.remove(clef.as_slice())?;
            }
            combien = combien.saturating_add(condamnes_appareils.len());

            // ── LES CODES D'ENRÔLEMENT EN ATTENTE ───────────────────────────
            let mut codes = ecriture.open_table(ENROLEMENTS)?;
            let mut index = ecriture.open_table(ENROLEMENTS_PAR_MACHINE)?;
            let mut condamnes_codes = Vec::new();
            for entree in codes.iter()? {
                let (empreinte, valeur) = entree?;
                let enrolement = Enrolement::lire(valeur.value()).map_err(Faute::Enregistrement)?;
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
