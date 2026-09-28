//! Les droits dans l'entrepôt (`docs/modele.md` §2.13, `docs/replication.md`
//! décisions 40, 41 et 44) : les tables, la conversion des autorisations
//! d'hier, les écritures locales, les règles d'application, et ce que
//! l'effacement d'un compte, la suppression d'un groupe, l'instantané, le
//! ré-estampillage et la rupture de confiance en font.
//!
//! # CE QUI S'ÉCRIT, CE QUI SE LIT — LA DISCIPLINE DES DÉCISIONS 42 ET 43
//!
//! **Un droit s'écrit tel qu'on l'accorde, et son retrait le marque** : rien
//! d'autre ne s'écrit. Ce qu'un compte PEUT sur un élément se calcule à la
//! lecture, sur l'ensemble des enregistrements que les deux racines finissent
//! par tenir à l'identique :
//!
//! - **la réunion** de tous les droits vivants reçus par les groupes vivants
//!   dont il est membre, sur l'élément et sur ce qui le contient — le service,
//!   sa machine, le domaine où elle est rangée, le compte qui la possède ;
//! - **un droit sur une machine ou un service ne vaut que tant que celui qui
//!   l'a accordé en a encore le pouvoir** : il en est le propriétaire, ou il
//!   administre le domaine où elle est rangée (décision 44). Sortir sa machine
//!   d'un domaine retire, à la lecture, ce que ses administrateurs en avaient
//!   partagé ; l'y remettre le rend.
//!
//! # POURQUOI UN DROIT REÇU SE REFUSE À L'APPLICATION, ET QUAND
//!
//! Pour la même raison que l'adhésion (`groupes.rs`) : ce qui est regardé ne
//! dépend d'aucun ordre entre les deux racines. Un droit arrive toujours après
//! son groupe et son élément — la racine qui l'a écrit les connaissait, et
//! les a reçus avant de pouvoir le lui accorder. Il ne se refuse donc que
//! pour ce qui ne revient jamais : un donneur effacé, un groupe marqué ou
//! effacé, un élément effacé avec son compte. Et ce qui les efface emporte
//! aussi les droits qui étaient déjà là : les deux ordres arrivent au même.

use asl_id::{Genre, Identifiant};
use asl_registre::{
    AUTORISATION_OCTETS, Autorisation, DROIT_OCTETS, Droit, Droits, Estampille, Operation, Portee,
    Provenance, domaine_racine,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::{
    AUTORISATIONS, AUTORISATIONS_ACCORDEES, AUTORISATIONS_RECUES, COMPTES, Entrepot, Faute,
    MACHINES, RACINE, SERVICES, Suite, clef, compte_efface_dans, depuis_clef, domaines,
    estampiller, groupes, intervalle, journaliser_l_operation, paire,
};

/// Les droits, par leur identifiant `g-…`.
pub(crate) const DROITS: TableDefinition<'_, &[u8], &[u8; DROIT_OCTETS]> =
    TableDefinition::new("droits");

/// Index : `groupe ‖ droit` → droit. Ce qu'un groupe a reçu se suit.
pub(crate) const DROITS_PAR_GROUPE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("droits-par-groupe");

/// Index : `donneur ‖ droit` → droit. Ce qu'un compte a accordé se suit.
pub(crate) const DROITS_ACCORDES: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("droits-accordes");

/// Index : `élément ‖ droit` → droit. Ce qui vise un élément se suit — c'est
/// ce que l'effacement d'un compte balaie, et ce que « qui voit ma machine ? »
/// lit.
pub(crate) const DROITS_PAR_ELEMENT: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("droits-par-element");

/// La clé de la conversion des autorisations, dans la table de la racine.
pub(crate) const CLEF_DES_DROITS: &str = "autorisations-converties";

// ── Ranger, retirer ─────────────────────────────────────────────────────────

/// Le droit rangé sous cet identifiant, s'il y en a un.
fn droit_dans(ecriture: &WriteTransaction, droit: Identifiant) -> Result<Option<Droit>, Faute> {
    let table = ecriture.open_table(DROITS)?;
    let lu = table.get(clef(droit).as_slice())?;
    Ok(match lu {
        Some(brut) => Some(Droit::lire(brut.value())?),
        None => None,
    })
}

/// Écrit ce droit et ses trois entrées d'index. **Le groupe, le donneur et
/// l'élément ne changent jamais** : un retrait réécrit l'enregistrement sous
/// les mêmes clés.
fn ranger(
    ecriture: &WriteTransaction,
    droit: Identifiant,
    enregistrement: &Droit,
) -> Result<(), Faute> {
    let mut octets = [0_u8; DROIT_OCTETS];
    enregistrement.ecrire(&mut octets);
    ecriture
        .open_table(DROITS)?
        .insert(clef(droit).as_slice(), &octets)?;
    let valeur = clef(droit);
    ecriture.open_table(DROITS_PAR_GROUPE)?.insert(
        paire(enregistrement.groupe, droit).as_slice(),
        valeur.as_slice(),
    )?;
    ecriture.open_table(DROITS_ACCORDES)?.insert(
        paire(enregistrement.par, droit).as_slice(),
        valeur.as_slice(),
    )?;
    ecriture.open_table(DROITS_PAR_ELEMENT)?.insert(
        paire(enregistrement.element, droit).as_slice(),
        valeur.as_slice(),
    )?;
    Ok(())
}

/// Range ce droit s'il est absent. Rend `false` s'il existait.
fn inserer(
    ecriture: &WriteTransaction,
    droit: Identifiant,
    enregistrement: &Droit,
) -> Result<bool, Faute> {
    if droit_dans(ecriture, droit)?.is_some() {
        return Ok(false);
    }
    ranger(ecriture, droit, enregistrement)?;
    Ok(true)
}

/// Retire ce droit entièrement — l'enregistrement et ses trois entrées.
fn oublier(ecriture: &WriteTransaction, droit: Identifiant) -> Result<bool, Faute> {
    let Some(avant) = droit_dans(ecriture, droit)? else {
        return Ok(false);
    };
    ecriture
        .open_table(DROITS)?
        .remove(clef(droit).as_slice())?;
    ecriture
        .open_table(DROITS_PAR_GROUPE)?
        .remove(paire(avant.groupe, droit).as_slice())?;
    ecriture
        .open_table(DROITS_ACCORDES)?
        .remove(paire(avant.par, droit).as_slice())?;
    ecriture
        .open_table(DROITS_PAR_ELEMENT)?
        .remove(paire(avant.element, droit).as_slice())?;
    Ok(true)
}

/// Les identifiants rangés sous cette clé dans cet index.
fn sous(
    ecriture: &WriteTransaction,
    index: TableDefinition<'_, &[u8], &[u8]>,
    par_quoi: Identifiant,
) -> Result<Vec<Identifiant>, Faute> {
    let (debut, fin) = intervalle(par_quoi);
    let mut rendus = Vec::new();
    for entree in ecriture
        .open_table(index)?
        .range(debut.as_slice()..fin.as_slice())?
    {
        let (_, droit) = entree?;
        rendus.push(depuis_clef(droit.value())?);
    }
    Ok(rendus)
}

/// Retire tout ce que ce groupe a reçu — celui d'un groupe supprimé ou effacé
/// avec son domaine ou son compte. Rend combien.
pub(crate) fn oublier_les_droits_du_groupe(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
) -> Result<usize, Faute> {
    let mut partis = 0_usize;
    for droit in sous(ecriture, DROITS_PAR_GROUPE, groupe)? {
        if oublier(ecriture, droit)? {
            partis = partis.saturating_add(1);
        }
    }
    Ok(partis)
}

/// Retire tout ce qui vise cet élément — un compte effacé, ses domaines, ses
/// machines, ses services. Rend combien.
pub(crate) fn oublier_ce_qui_vise(
    ecriture: &WriteTransaction,
    element: Identifiant,
) -> Result<usize, Faute> {
    let mut partis = 0_usize;
    for droit in sous(ecriture, DROITS_PAR_ELEMENT, element)? {
        if oublier(ecriture, droit)? {
            partis = partis.saturating_add(1);
        }
    }
    Ok(partis)
}

/// Ce qui visait `ancien` vise désormais `derive` — la migration des `s-…`
/// (décision 72). **Rien d'autre ne change** : ni l'identifiant du droit, ni
/// son estampille, ni son retrait. Rend combien.
pub(crate) fn renommer_l_element(
    ecriture: &WriteTransaction,
    ancien: Identifiant,
    derive: Identifiant,
) -> Result<usize, Faute> {
    let mut suivis = 0_usize;
    for droit in sous(ecriture, DROITS_PAR_ELEMENT, ancien)? {
        if let Some(avant) = droit_dans(ecriture, droit)? {
            oublier(ecriture, droit)?;
            ranger(
                ecriture,
                droit,
                &Droit {
                    element: derive,
                    ..avant
                },
            )?;
            suivis = suivis.saturating_add(1);
        }
    }
    Ok(suivis)
}

/// Ce que l'effacement d'un compte fait des droits : **ceux qu'il a accordés,
/// et ceux qui visent son compte** — ceux qui visent ses domaines, ses
/// machines, ses services et ceux que ses groupes recevaient partent avec
/// eux, là où ils s'effacent. Rend combien.
pub(crate) fn effacer_les_droits_du_compte(
    ecriture: &WriteTransaction,
    compte: Identifiant,
) -> Result<usize, Faute> {
    let mut partis = oublier_ce_qui_vise(ecriture, compte)?;
    for droit in sous(ecriture, DROITS_ACCORDES, compte)? {
        if oublier(ecriture, droit)? {
            partis = partis.saturating_add(1);
        }
    }
    Ok(partis)
}

// ── Appliquer ce que l'autre racine a écrit (§5.2) ──────────────────────────

/// Ce droit peut-il entrer, dans cette transaction ? **Refusé pour ce qui ne
/// revient jamais** (voir l'en-tête) : un donneur effacé, un groupe marqué ou
/// inconnu, un élément inconnu ou effacé — et le domaine racine, qui ne
/// transmet rien (`docs/modele.md` §2.11).
fn peut_entrer(ecriture: &WriteTransaction, droit: &Droit) -> Result<bool, Faute> {
    if compte_efface_dans(ecriture, droit.par)? {
        return Ok(false);
    }
    if ecriture
        .open_table(groupes::MARQUES_DE_GROUPES)?
        .get(clef(droit.groupe).as_slice())?
        .is_some()
        || ecriture
            .open_table(groupes::GROUPES)?
            .get(clef(droit.groupe).as_slice())?
            .is_none()
    {
        return Ok(false);
    }
    let element = clef(droit.element);
    Ok(match droit.element.genre() {
        Genre::Utilisateur => {
            ecriture
                .open_table(COMPTES)?
                .get(element.as_slice())?
                .is_some()
                && !compte_efface_dans(ecriture, droit.element)?
        }
        Genre::Domaine => {
            droit.element != domaine_racine()
                && ecriture
                    .open_table(domaines::DOMAINES)?
                    .get(element.as_slice())?
                    .is_some()
        }
        Genre::Machine => ecriture
            .open_table(MACHINES)?
            .get(element.as_slice())?
            .is_some(),
        Genre::Service => ecriture
            .open_table(SERVICES)?
            .get(element.as_slice())?
            .is_some(),
        _ => false,
    })
}

/// `droit` — insérer si absent ; refusé pour ce qui ne revient jamais.
pub(crate) fn appliquer_droit(
    ecriture: &WriteTransaction,
    droit: Identifiant,
    enregistrement: &Droit,
) -> Result<(), Faute> {
    // **UN `s-…` D'HIER SE TRADUIT** (0.37.0, décision 72) : un pair pas
    // encore migré nomme le service sous son ancien identifiant, que la
    // correspondance connaît — le nôtre d'avant la migration, ou celui que
    // son opération `service` nous a appris.
    let enregistrement = Droit {
        provenance: Provenance::Ici,
        element: crate::identifiants::traduire(ecriture, enregistrement.element)?,
        ..*enregistrement
    };
    if !peut_entrer(ecriture, &enregistrement)? {
        return Ok(());
    }
    inserer(ecriture, droit, &enregistrement)?;
    Ok(())
}

/// `droit-retire` — **toujours** : la plus petite estampille de retrait. Sur
/// un droit inconnu, rien : effacé avec ce qu'il visait, il ne revient pas.
pub(crate) fn appliquer_droit_retire(
    ecriture: &WriteTransaction,
    droit: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    let Some(avant) = droit_dans(ecriture, droit)? else {
        return Ok(());
    };
    ranger(
        ecriture,
        droit,
        &Droit {
            retire: Some(avant.retire.map_or(estampille, |deja| deja.min(estampille))),
            ..avant
        },
    )
}

/// `autorisation` — **lue encore, convertie à l'application** (décision 41) :
/// un journal d'avant la conversion, tiré par une racine en retard, la porte.
pub(crate) fn appliquer_autorisation(
    ecriture: &WriteTransaction,
    droit: Identifiant,
    autorisation: &Autorisation,
) -> Result<(), Faute> {
    appliquer_droit(ecriture, droit, &Droit::depuis_autorisation(autorisation))
}

// ── La conversion (décision 41) ─────────────────────────────────────────────

/// **Les autorisations d'hier deviennent des droits**, sous le même `g-…` :
/// chacune par [`Droit::depuis_autorisation`], une fonction de ses seuls
/// octets. Une fois, marquée dans la table de la racine ; les tables d'hier
/// sont vidées. Rend combien de droits sont nés.
///
/// # ELLE NE VIDE PAS LE JOURNAL D'OPÉRATIONS
///
/// La spec le prévoyait par prudence ; ce n'est pas nécessaire, et c'est dit
/// dans la décision 44. Les deux racines convertissent chacune de son côté,
/// à l'identique, et une opération `autorisation` encore au journal de
/// l'autre se convertit à l'application par la même fonction : la tirer après
/// la conversion ne change rien — le droit est déjà là, sous le même `g-…`,
/// avec les mêmes octets.
pub(crate) fn reprendre_les_autorisations(ecriture: &WriteTransaction) -> Result<usize, Faute> {
    let fait = ecriture.open_table(RACINE)?.get(CLEF_DES_DROITS)?.is_some();
    if fait {
        return Ok(0);
    }
    let mut hier = Vec::new();
    for entree in ecriture.open_table(AUTORISATIONS)?.iter()? {
        let (clef_brute, valeur) = entree?;
        let brut: &[u8; AUTORISATION_OCTETS] = valeur.value();
        hier.push((depuis_clef(clef_brute.value())?, Autorisation::lire(brut)?));
    }
    let mut nes = 0_usize;
    for (droit, autorisation) in &hier {
        if inserer(ecriture, *droit, &Droit::depuis_autorisation(autorisation))? {
            nes = nes.saturating_add(1);
        }
    }
    for table in [AUTORISATIONS_RECUES, AUTORISATIONS_ACCORDEES] {
        let mut ouverte = ecriture.open_table(table)?;
        let clefs: Vec<Vec<u8>> = ouverte
            .iter()?
            .map(|entree| entree.map(|(clef_brute, _)| clef_brute.value().to_vec()))
            .collect::<Result<_, _>>()?;
        for une in &clefs {
            ouverte.remove(une.as_slice())?;
        }
    }
    {
        let mut table = ecriture.open_table(AUTORISATIONS)?;
        for (droit, _) in &hier {
            table.remove(clef(*droit).as_slice())?;
        }
    }
    ecriture.open_table(RACINE)?.insert(CLEF_DES_DROITS, 1)?;
    Ok(nes)
}

// ── L'instantané, le ré-estampillage, la rupture ────────────────────────────

/// Ce que les droits ajoutent à un instantané — APRÈS les groupes et les
/// machines qu'un droit exige chez le lecteur : **chaque droit, retrait
/// compris**, en une opération qui porte l'enregistrement entier.
pub(crate) fn instantane_des_droits(
    lecture: &redb::ReadTransaction,
    suite: &mut Suite,
) -> Result<(), Faute> {
    for entree in lecture.open_table(DROITS)?.iter()? {
        let (clef_droit, valeur) = entree?;
        let droit = Droit::lire(valeur.value())?;
        if droit.provenance != Provenance::Ici {
            continue;
        }
        suite.ajouter(
            droit.estampille,
            &Operation::Droit {
                droit: depuis_clef(clef_droit.value())?,
                enregistrement: droit,
            },
        );
    }
    Ok(())
}

/// Passe sous `vers` ce que `de` a estampillé dans la table des droits, et
/// rend combien d'enregistrements ont bougé.
pub(crate) fn reestampiller(
    ecriture: &WriteTransaction,
    de: Identifiant,
    vers: Identifiant,
) -> Result<usize, Faute> {
    let sous_vers = |estampille: Estampille| {
        if estampille.racine == de {
            Estampille {
                compteur: estampille.compteur,
                racine: vers,
            }
        } else {
            estampille
        }
    };
    let mut changes = Vec::new();
    for entree in ecriture.open_table(DROITS)?.iter()? {
        let (clef_droit, valeur) = entree?;
        let avant = Droit::lire(valeur.value())?;
        let apres = Droit {
            estampille: sous_vers(avant.estampille),
            retire: avant.retire.map(sous_vers),
            ..avant
        };
        if apres != avant {
            changes.push((depuis_clef(clef_droit.value())?, apres));
        }
    }
    for (droit, apres) in &changes {
        ranger(ecriture, *droit, apres)?;
    }
    Ok(changes.len())
}

/// Ce qui vient de cet annuaire, dans la table des droits (C17). Rend combien
/// est parti.
pub(crate) fn oublier_ce_qui_vient_de(
    ecriture: &WriteTransaction,
    annuaire: Identifiant,
) -> Result<usize, Faute> {
    let mut condamnes = Vec::new();
    for entree in ecriture.open_table(DROITS)?.iter()? {
        let (clef_droit, valeur) = entree?;
        if Droit::lire(valeur.value())?.provenance.vient_de(annuaire) {
            condamnes.push(depuis_clef(clef_droit.value())?);
        }
    }
    for droit in &condamnes {
        oublier(ecriture, *droit)?;
    }
    Ok(condamnes.len())
}

// ── Ce que la lecture calcule ───────────────────────────────────────────────

/// Ce qu'on veut pouvoir faire d'un élément : le voir, ou le localiser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Voulu {
    /// Lister machines et services.
    Voir,
    /// Obtenir l'adresse et le port d'un service.
    Localiser,
}

impl Voulu {
    /// Ces droits le permettent-ils ?
    const fn permis_par(self, droits: Droits) -> bool {
        match self {
            Self::Voir => droits.permettent_de_voir(),
            Self::Localiser => droits.permettent_de_localiser(),
        }
    }
}

/// Un accès qu'un compte tient sur ce qu'un AUTRE possède, dans la forme
/// qu'`asl-auth` décide : le propriétaire, et ce que la portée couvre. C'est
/// le calcul des droits ramené à la forme d'hier, pour que l'étage 2 garde
/// une seule façon de juger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acces {
    /// Le compte qui possède ce qui est ouvert.
    pub proprietaire: Identifiant,
    /// Ce qui est ouvert : tout son compte, une machine, un service.
    pub portee: Portee,
}

/// Ce qu'une écriture locale sur un droit a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcritureDeDroit {
    /// Fait.
    Faite,
    /// Le droit, son groupe ou son élément n'existe pas ou plus.
    Absent,
}

impl Entrepot {
    /// Ce droit, rangé, vivant ou retiré.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn droit(&self, droit: Identifiant) -> Result<Option<Droit>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(DROITS)?;
        let lu = table.get(clef(droit).as_slice())?;
        Ok(match lu {
            Some(brut) => Some(Droit::lire(brut.value())?),
            None => None,
        })
    }

    /// Les droits rangés sous cette clé dans cet index, dans l'ordre de leurs
    /// identifiants.
    fn droits_par(
        &self,
        index: TableDefinition<'_, &[u8], &[u8]>,
        par_quoi: Identifiant,
    ) -> Result<Vec<(Identifiant, Droit)>, Faute> {
        let lecture = self.base.begin_read()?;
        let index = lecture.open_table(index)?;
        let table = lecture.open_table(DROITS)?;
        let (debut, fin) = intervalle(par_quoi);
        let mut trouves = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, valeur) = entree?;
            if let Some(brut) = table.get(valeur.value())? {
                trouves.push((depuis_clef(valeur.value())?, Droit::lire(brut.value())?));
            }
        }
        Ok(trouves)
    }

    /// Les droits que ce compte a accordés, retirés compris.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn droits_accordes(&self, compte: Identifiant) -> Result<Vec<(Identifiant, Droit)>, Faute> {
        self.droits_par(DROITS_ACCORDES, compte)
    }

    /// Les droits qui visent cet élément, retirés compris.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn droits_sur(&self, element: Identifiant) -> Result<Vec<(Identifiant, Droit)>, Faute> {
        self.droits_par(DROITS_PAR_ELEMENT, element)
    }

    /// Les droits que les groupes vivants de ce compte ont reçus, retirés
    /// compris, **une fois chacun**, dans l'ordre de leurs identifiants.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn droits_recus(&self, compte: Identifiant) -> Result<Vec<(Identifiant, Droit)>, Faute> {
        let mut recus = Vec::new();
        for groupe in self.groupes_dont_membre(compte)? {
            recus.extend(self.droits_par(DROITS_PAR_GROUPE, groupe)?);
        }
        recus.sort_by_key(|(droit, _)| clef(*droit));
        recus.dedup_by_key(|(droit, _)| *droit);
        Ok(recus)
    }

    /// La réunion des droits VIVANTS que ce compte a reçus sur cet élément
    /// précis — sans ce qui le contient, sans ce que la propriété donne.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn droits_recus_sur(
        &self,
        compte: Identifiant,
        element: Identifiant,
    ) -> Result<Droits, Faute> {
        Ok(self
            .droits_recus(compte)?
            .into_iter()
            .filter(|(_, droit)| droit.retire.is_none() && droit.element == element)
            .fold(Droits::AUCUN, |tous, (_, droit)| tous.union(droit.droits)))
    }

    /// Ce compte peut-il ranger SES machines dans ce domaine ? Il
    /// l'administre, ou l'un de ses groupes a reçu `rattacher` sur lui.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn peut_ranger(&self, compte: Identifiant, domaine: Identifiant) -> Result<bool, Faute> {
        if domaine == domaine_racine() || self.domaine(domaine)?.is_none() {
            return Ok(false);
        }
        Ok(self.administre(compte, domaine)?
            || self
                .droits_recus_sur(compte, domaine)?
                .croise(Droits::RATTACHER))
    }

    /// Ce que ce compte peut sur ce domaine vivant : **la réunion** de ce que
    /// la propriété donne (les quatre), de ce que son groupe d'administrateurs
    /// donne (`administrer`, `rattacher`, `voir`), et des droits reçus sur lui
    /// — `administrer` emportant `rattacher` et `voir`, `localiser` emportant
    /// `voir`. Aucun pour un domaine mort ou le domaine racine, qui a sa
    /// propre règle.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn droits_sur_domaine(
        &self,
        compte: Identifiant,
        domaine: Identifiant,
    ) -> Result<Droits, Faute> {
        if domaine == domaine_racine() {
            return Ok(Droits::AUCUN);
        }
        let Some(rangee) = self.domaine(domaine)? else {
            return Ok(Droits::AUCUN);
        };
        if rangee.proprietaire == compte {
            return Ok(Droits::TOUS);
        }
        let mut droits = self.droits_recus_sur(compte, domaine)?;
        if self.administre(compte, domaine)? {
            droits = droits.union(Droits::ADMINISTRER);
        }
        if droits.croise(Droits::ADMINISTRER) {
            droits = droits.union(Droits::RATTACHER).union(Droits::VOIR);
        }
        if droits.croise(Droits::LOCALISER) {
            droits = droits.union(Droits::VOIR);
        }
        Ok(droits)
    }

    /// Les domaines vivants où ce compte tient un droit sans les posséder,
    /// administrés compris, dans l'ordre de leurs identifiants.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn domaines_ou_j_ai_un_droit(
        &self,
        compte: Identifiant,
    ) -> Result<Vec<Identifiant>, Faute> {
        let mut domaines: Vec<Identifiant> = self
            .droits_recus(compte)?
            .into_iter()
            .filter(|(_, droit)| droit.retire.is_none() && droit.element.genre() == Genre::Domaine)
            .map(|(_, droit)| droit.element)
            .collect();
        domaines.extend(self.domaines_administres(compte)?);
        domaines.sort_by_key(|domaine| clef(*domaine));
        domaines.dedup();
        let mut rendus = Vec::new();
        for domaine in domaines {
            if domaine == domaine_racine() {
                rendus.push(domaine);
            } else if let Some(rangee) = self.domaine(domaine)?
                && rangee.proprietaire != compte
                && !self.droits_sur_domaine(compte, domaine)?.est_vide()
            {
                rendus.push(domaine);
            }
        }
        Ok(rendus)
    }

    /// Le pouvoir d'accorder sur cette machine — ou sur ses services : en être
    /// le propriétaire, ou administrer le domaine où elle est rangée
    /// (décision 40 : ranger sa machine, c'est confier à ses administrateurs
    /// le droit de la partager).
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn peut_accorder_sur_la_machine(
        &self,
        compte: Identifiant,
        machine: Identifiant,
    ) -> Result<bool, Faute> {
        let Some(rangee) = self.machine(machine)? else {
            return Ok(false);
        };
        if rangee.proprietaire == compte {
            return Ok(true);
        }
        match self.domaine_de_machine(machine)? {
            Some(domaine) => self.administre(compte, domaine),
            None => Ok(false),
        }
    }

    /// La machine que cet élément désigne ou porte : elle-même, ou celle du
    /// service. Rien pour un compte ou un domaine.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn machine_de_l_element(&self, element: Identifiant) -> Result<Option<Identifiant>, Faute> {
        Ok(match element.genre() {
            Genre::Machine => self.machine(element)?.map(|_| element),
            Genre::Service => self.service(element)?.map(|service| service.machine),
            _ => None,
        })
    }

    /// Ce droit VAUT-il encore, lu maintenant ? Non retiré, son groupe vivant
    /// (l'appelant l'a tiré d'un groupe vivant), son élément vivant, et **son
    /// donneur encore en pouvoir** sur une machine ou un service (décision
    /// 44).
    fn vaut(&self, droit: &Droit) -> Result<bool, Faute> {
        if droit.retire.is_some() {
            return Ok(false);
        }
        match droit.element.genre() {
            Genre::Utilisateur => {
                Ok(droit.element == droit.par && self.compte_vivant(droit.element)?.is_some())
            }
            Genre::Domaine => Ok(self.domaine(droit.element)?.is_some()),
            Genre::Machine | Genre::Service => match self.machine_de_l_element(droit.element)? {
                Some(machine) => self.peut_accorder_sur_la_machine(droit.par, machine),
                None => Ok(false),
            },
            _ => Ok(false),
        }
    }

    /// **Ce que ce compte peut voir, ou localiser, de ce que d'AUTRES
    /// possèdent** (décision 40) — ramené à la forme d'`asl-auth` : un
    /// propriétaire et une portée. C'est ce que `GET /v1/ou`, la résolution
    /// par nom et `GET /v1/utilisateurs/{u}/machines` examinent : chacun
    /// calculé depuis le DEMANDEUR (C10), jamais depuis ce qu'il désigne.
    ///
    /// - un droit sur un compte (une autorisation convertie) : tout ce que ce
    ///   compte possède, présent et à venir ;
    /// - sur une machine ou un service : lui, s'il vaut encore ;
    /// - sur un domaine : chaque machine qui y vaut rangée ;
    /// - et, pour VOIR seulement, chaque machine rangée dans un domaine qu'il
    ///   administre — `administrer` emporte `voir`.
    ///
    /// Ce qu'il possède lui-même n'y figure pas : `asl-auth` le sert sans
    /// arête.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn acces(&self, compte: Identifiant, voulu: Voulu) -> Result<Vec<Acces>, Faute> {
        let mut rendus = Vec::new();
        let par_machine = |machine: Identifiant, rendus: &mut Vec<Acces>| -> Result<(), Faute> {
            if let Some(rangee) = self.machine(machine)?
                && rangee.proprietaire != compte
            {
                rendus.push(Acces {
                    proprietaire: rangee.proprietaire,
                    portee: Portee::UneMachine(machine),
                });
            }
            Ok(())
        };
        for (_, droit) in self.droits_recus(compte)? {
            if !voulu.permis_par(droit.droits) || !self.vaut(&droit)? {
                continue;
            }
            match droit.element.genre() {
                Genre::Utilisateur if droit.element != compte => rendus.push(Acces {
                    proprietaire: droit.element,
                    portee: Portee::ToutLeCompte,
                }),
                Genre::Domaine => {
                    for machine in self.machines_du_domaine(droit.element)? {
                        par_machine(machine, &mut rendus)?;
                    }
                }
                Genre::Machine => par_machine(droit.element, &mut rendus)?,
                Genre::Service => {
                    if let Some(service) = self.service(droit.element)?
                        && let Some(rangee) = self.machine(service.machine)?
                        && rangee.proprietaire != compte
                    {
                        rendus.push(Acces {
                            proprietaire: rangee.proprietaire,
                            portee: Portee::UnService(droit.element),
                        });
                    }
                }
                _ => {}
            }
        }
        if voulu == Voulu::Voir {
            let mut administres: Vec<Identifiant> = self
                .domaines_de_compte(compte)?
                .into_iter()
                .map(|(domaine, _)| domaine)
                .collect();
            administres.extend(self.domaines_administres(compte)?);
            for domaine in administres {
                for machine in self.machines_du_domaine(domaine)? {
                    par_machine(machine, &mut rendus)?;
                }
            }
        }
        rendus.dedup();
        Ok(rendus)
    }

    /// Accorde ce droit — **le pouvoir a été jugé avant**, à l'étage 3. Rend
    /// [`EcritureDeDroit::Absent`] si le groupe n'est pas vivant, ou si
    /// l'élément n'existe pas.
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si l'identifiant est déjà pris, [`Faute::Base`] ou
    /// [`Faute::Enregistrement`].
    pub fn accorder_droit(
        &self,
        droit: Identifiant,
        par: Identifiant,
        groupe: Identifiant,
        element: Identifiant,
        droits: Droits,
        etiquette: asl_registre::NomRange,
    ) -> Result<EcritureDeDroit, Faute> {
        if self.groupe(groupe)?.is_none() {
            return Ok(EcritureDeDroit::Absent);
        }
        let ecriture = self.base.begin_write()?;
        let estampille = estampiller(&ecriture, self.racine)?;
        let enregistrement = Droit {
            provenance: Provenance::Ici,
            estampille,
            par,
            groupe,
            element,
            droits,
            retire: None,
            etiquette,
        };
        if !peut_entrer(&ecriture, &enregistrement)? {
            return Ok(EcritureDeDroit::Absent);
        }
        if !inserer(&ecriture, droit, &enregistrement)? {
            return Err(Faute::Existe);
        }
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::Droit {
                droit,
                enregistrement,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(EcritureDeDroit::Faite)
    }

    /// Retire ce droit, et rend ce qu'il était — **le pouvoir a été jugé
    /// avant**. Un droit déjà retiré garde son retrait, et n'écrit rien.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn retirer_droit(&self, droit: Identifiant) -> Result<Option<Droit>, Faute> {
        let ecriture = self.base.begin_write()?;
        let Some(avant) = droit_dans(&ecriture, droit)? else {
            return Ok(None);
        };
        if avant.retire.is_some() {
            return Ok(Some(avant));
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        ranger(
            &ecriture,
            droit,
            &Droit {
                retire: Some(estampille),
                ..avant
            },
        )?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::DroitRetire { droit },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(Some(avant))
    }

    /// Ce groupe porte-t-il un droit vivant ? C'est ce qui décide si ajouter un
    /// compte à ce groupe le réveille (`docs/modele.md` §2.13).
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn groupe_porte_des_droits(&self, groupe: Identifiant) -> Result<bool, Faute> {
        Ok(self
            .droits_par(DROITS_PAR_GROUPE, groupe)?
            .iter()
            .any(|(_, droit)| droit.retire.is_none()))
    }
}

// ── La forme d'hier (décision 41) ───────────────────────────────────────────
//
// **LES VERBES `/v1/autorisations` RESTENT SERVIS**, comme une vue des droits
// : les applications déployées accordent, listent et retirent par eux. Ce qui
// suit est cette vue, du côté de l'entrepôt — les mêmes signatures qu'avant la
// conversion, pour que l'étage 3 et ses essais n'aient qu'un modèle à tenir.

impl Entrepot {
    /// Le titulaire de ce groupe s'il est un groupe personnel — vivant ou non.
    fn titulaire(&self, groupe: Identifiant) -> Result<Option<Identifiant>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(groupes::GROUPES)?;
        let lu = table.get(clef(groupe).as_slice())?;
        Ok(match lu {
            Some(brut) => {
                let rangee = asl_registre::Groupe::lire(brut.value())?;
                (rangee.sorte == asl_registre::SorteDeGroupe::Personnel).then_some(rangee.rattache)
            }
            None => None,
        })
    }

    /// Accorde une autorisation **dans la forme d'hier** : un droit `voir` +
    /// `localiser` au groupe personnel du bénéficiaire, sur l'élément que la
    /// portée nomme — le compte du donneur pour « tout mon compte ».
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si l'identifiant est pris, [`Faute::Base`] si la base
    /// refuse.
    pub fn accorder_autorisation(
        &self,
        quelle: Identifiant,
        provenance: Provenance,
        par: Identifiant,
        a: Identifiant,
        portee: Portee,
        etiquette: asl_registre::NomRange,
    ) -> Result<(), Faute> {
        let ecriture = self.base.begin_write()?;
        let estampille = estampiller(&ecriture, self.racine)?;
        let enregistrement = Droit::depuis_autorisation(&Autorisation {
            provenance,
            estampille,
            par,
            a,
            portee,
            revoquee: false,
            etiquette,
        });
        if !inserer(&ecriture, quelle, &enregistrement)? {
            return Err(Faute::Existe);
        }
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            provenance,
            &Operation::Droit {
                droit: quelle,
                enregistrement,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(())
    }

    /// Ce droit dit dans la forme d'hier, s'il s'y laisse dire : accordé au
    /// groupe personnel d'un compte, sur un compte, une machine ou un service,
    /// avec `localiser`.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn autorisation(&self, quelle: Identifiant) -> Result<Option<Autorisation>, Faute> {
        let Some(droit) = self.droit(quelle)? else {
            return Ok(None);
        };
        Ok(self
            .titulaire(droit.groupe)?
            .and_then(|a| droit.en_autorisation(a)))
    }

    /// Retire une autorisation — le droit qui la porte —, et rend ce qu'elle
    /// était dans la forme d'hier. `None` si aucun droit ne s'y laisse dire
    /// sous cet identifiant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn revoquer_autorisation(
        &self,
        quelle: Identifiant,
    ) -> Result<Option<Autorisation>, Faute> {
        let Some(avant) = self.autorisation(quelle)? else {
            return Ok(None);
        };
        self.retirer_droit(quelle)?;
        Ok(Some(avant))
    }

    /// Les autorisations que ce compte a reçues, dans la forme d'hier —
    /// **retirées comprises** : c'est `asl-auth` qui les écarte.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn autorisations_recues(&self, a: Identifiant) -> Result<Vec<Autorisation>, Faute> {
        Ok(self
            .autorisations_recues_nommees(a)?
            .into_iter()
            .map(|(_, autorisation)| autorisation)
            .collect())
    }

    /// Les autorisations que ce compte a reçues, avec leur identifiant : **les
    /// droits que ses groupes ont reçus et qui se disent dans la forme
    /// d'hier**, lui pour bénéficiaire. Ceux qu'il s'est accordés à lui-même,
    /// par un groupe dont il est membre, n'y sont pas : ils sont de l'autre
    /// côté du tableau.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn autorisations_recues_nommees(
        &self,
        a: Identifiant,
    ) -> Result<Vec<(Identifiant, Autorisation)>, Faute> {
        Ok(self
            .droits_recus(a)?
            .into_iter()
            .filter(|(_, droit)| droit.par != a)
            .filter_map(|(quel, droit)| droit.en_autorisation(a).map(|vue| (quel, vue)))
            .collect())
    }

    /// Les autorisations que ce compte a accordées, avec leur identifiant :
    /// **les droits qu'il a accordés à des groupes personnels**, et qui se
    /// disent dans la forme d'hier, leur titulaire pour bénéficiaire.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn autorisations_accordees(
        &self,
        par: Identifiant,
    ) -> Result<Vec<(Identifiant, Autorisation)>, Faute> {
        let mut rendues = Vec::new();
        for (quel, droit) in self.droits_accordes(par)? {
            if let Some(a) = self.titulaire(droit.groupe)?
                && let Some(vue) = droit.en_autorisation(a)
            {
                rendues.push((quel, vue));
            }
        }
        Ok(rendues)
    }
}
