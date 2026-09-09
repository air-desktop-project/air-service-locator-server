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
    CLEF_JOURNAL_OCTETS, COMPTE_OCTETS, Compte, ENTREE_OCTETS, EntreeJournal, IDENTIFIANT_OCTETS,
    MACHINE_OCTETS, Machine,
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
            ecriture.open_table(ALIAS)?;
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
