//! Les domaines dans l'entrepôt (`docs/modele.md` §2.11, `docs/replication.md`
//! §3.2 et §5.2, 2026-09-26) : les tables, les écritures locales, les règles
//! d'application, et ce que l'effacement d'un compte, l'instantané, la reprise
//! et le ré-estampillage en font.
//!
//! # SIX TABLES, ET AUCUNE NE CHANGE LA FORME D'UNE AUTRE
//!
//! Le domaine, son alias et le rattachement d'une machine vivent chacun dans
//! sa table, avec deux index — les domaines d'un compte, les machines d'un
//! domaine — et l'index des alias pliés. **Aucun enregistrement existant ne
//! change de taille** : une base d'hier les reçoit vides à l'ouverture, et le
//! format reste 3 (voir `Entrepot::amorcer`). La seule reprise est celle du
//! premier domaine de chaque compte, qui se DÉDUIT du compte — voir
//! [`reprendre_les_premiers_domaines`].

use asl_id::Identifiant;
use asl_registre::{
    ALIAS_DE_DOMAINE_RANGE_OCTETS, ALIAS_DE_MACHINE_RANGE_OCTETS, AliasDeDomaine,
    AliasDeDomaineRange, AliasDeMachine, AliasDeMachineRange, DOMAINE_OCTETS, Domaine, Estampille,
    Operation, Provenance, RATTACHEMENT_OCTETS, Rattachement, domaine_racine, premier_domaine,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::{
    COMPTES, Entrepot, Faute, MACHINES, RACINE, Suite, clef, compte_efface_dans, depuis_clef,
    estampiller, groupes, intervalle, journaliser_l_operation, paire,
};
use asl_registre::Compte;

/// Les domaines, par leur identifiant — supprimés compris, marqués.
pub(crate) const DOMAINES: TableDefinition<'_, &[u8], &[u8; DOMAINE_OCTETS]> =
    TableDefinition::new("domaines");

/// Index : `compte ‖ domaine` → domaine. Les domaines d'un compte se suivent.
pub(crate) const DOMAINES_PAR_COMPTE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("domaines-par-compte");

/// L'alias posé de chaque domaine, avec son estampille.
pub(crate) const ALIAS_DE_DOMAINES: TableDefinition<
    '_,
    &[u8],
    &[u8; ALIAS_DE_DOMAINE_RANGE_OCTETS],
> = TableDefinition::new("alias-de-domaines");

/// Index : `longueur ‖ clé pliée ‖ domaine` → domaine.
///
/// **La longueur en tête**, pour qu'une clé qui en préfixe une autre —
/// « maison », « maisons » — ne se trouve pas dans son intervalle : la
/// recherche est EXACTE (`docs/modele.md` §2.11).
pub(crate) const DOMAINES_PAR_ALIAS: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("domaines-par-alias");

/// Le rattachement de chaque machine qui en a un — ou qui en a eu un, et
/// l'a perdu (`domaine: None`, qui garde son estampille).
pub(crate) const RATTACHEMENTS: TableDefinition<'_, &[u8], &[u8; RATTACHEMENT_OCTETS]> =
    TableDefinition::new("rattachements");

/// Index : `domaine ‖ machine` → machine. Les machines d'un domaine se
/// suivent.
pub(crate) const MACHINES_PAR_DOMAINE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("machines-par-domaine");

/// Les alias de machine, par machine (0.26.0) : la dernière pose ou le
/// dernier retrait. Une machine sans entrée n'a pas d'alias.
pub(crate) const ALIAS_DE_MACHINES: TableDefinition<
    '_,
    &[u8],
    &[u8; ALIAS_DE_MACHINE_RANGE_OCTETS],
> = TableDefinition::new("alias-de-machines");

/// La clé de la reprise de l'index des alias de domaine, dans la table de la
/// racine : posée une fois, quand l'index est passé de la clé pliée à la clé
/// exacte (0.26.0, décision 45).
pub(crate) const CLEF_DES_ALIAS_EXACTS: &str = "alias-de-domaine-exacts";

/// La clé de la reprise des premiers domaines, dans la table de la racine :
/// posée une fois, quand chaque compte a reçu le sien.
pub(crate) const CLEF_DES_PREMIERS_DOMAINES: &str = "premiers-domaines";

/// Ce que la suppression locale d'un domaine a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionDeDomaine {
    /// Supprimé : ses machines détachées, son alias retiré.
    Faite,
    /// **C'était le dernier domaine vivant de son compte**, et rien n'a été
    /// écrit : un compte a toujours au moins un domaine — `409`.
    Derniere,
    /// Inconnu, ou déjà supprimé.
    Absent,
}

// ── Les clés ────────────────────────────────────────────────────────────────

/// La clé de l'index des alias : la longueur de l'alias rangé, ses octets —
/// **exacts, sensibles à la casse** (décision 45) —, le domaine.
fn clef_d_alias(recherche: &AliasDeDomaine, domaine: Identifiant) -> Vec<u8> {
    let mut composee = prefixe_d_alias(recherche);
    composee.extend_from_slice(&clef(domaine));
    composee
}

/// Ce par quoi commencent toutes les entrées d'un même alias.
fn prefixe_d_alias(recherche: &AliasDeDomaine) -> Vec<u8> {
    let octets = recherche.octets();
    let mut prefixe = Vec::with_capacity(octets.len().saturating_add(1));
    // Soixante-quatre octets au plus : la longueur tient sur un octet.
    prefixe.push(u8::try_from(octets.len()).unwrap_or(u8::MAX));
    prefixe.extend_from_slice(octets);
    prefixe
}

// ── Qui est vivant — une fonction de l'ensemble ─────────────────────────────

/// Ce domaine est-il vivant, parmi les domaines de son compte ?
///
/// # LA RÈGLE DES SUPPRESSIONS CONCURRENTES, CALCULÉE À LA LECTURE
///
/// `docs/replication.md` §3.2 : deux racines qui ont chacune supprimé un
/// domaine différent du même compte, là où il en restait deux, laisseraient
/// le compte sans domaine. **Si tous les domaines d'un compte sont marqués
/// supprimés, le plus ancien — la plus petite naissance — est vivant quand
/// même.**
///
/// **Elle se calcule ici, et ne s'écrit jamais.** Une première version
/// « ranimait » le survivant en effaçant sa marque, à l'arrivée de la
/// suppression qui vidait le compte. Ce n'était pas une fonction de l'ensemble :
/// un domaine né de l'autre côté pendant la fenêtre, arrivé APRÈS la
/// réanimation, laissait le survivant ranimé ; arrivé AVANT, il l'en
/// dispensait — deux racines, deux états. Une marque ne s'efface donc jamais,
/// et la vie se lit sur l'ensemble des enregistrements, que les deux racines
/// finissent par tenir à l'identique.
///
/// Les rattachements et les alias suivent la même lecture : ils restent rangés
/// tels que leur règle — le plus récent — les a laissés, et c'est le lecteur
/// qui écarte ce qui vise un domaine mort. Un survivant retrouve donc ses
/// machines et son alias, sans qu'aucune écriture ait eu à les lui rendre.
fn vivant(quel: Identifiant, rangee: &Domaine, freres: &[(Identifiant, Domaine)]) -> bool {
    if rangee.supprime.is_none() {
        return true;
    }
    if freres.iter().any(|(_, frere)| frere.supprime.is_none()) {
        return false;
    }
    freres
        .iter()
        .min_by_key(|(id, frere)| (frere.estampille, *id))
        .is_some_and(|(id, _)| *id == quel)
}

/// Les domaines de ce compte, marqués compris, lus dans ces deux tables.
fn freres<I, D>(
    index: &I,
    domaines: &D,
    compte: Identifiant,
) -> Result<Vec<(Identifiant, Domaine)>, Faute>
where
    I: ReadableTable<&'static [u8], &'static [u8]>,
    D: ReadableTable<&'static [u8], &'static [u8; DOMAINE_OCTETS]>,
{
    let (debut, fin) = intervalle(compte);
    let mut rendus = Vec::new();
    for entree in index.range(debut.as_slice()..fin.as_slice())? {
        let (_, clef_domaine) = entree?;
        if let Some(brut) = domaines.get(clef_domaine.value())? {
            rendus.push((
                depuis_clef(clef_domaine.value())?,
                Domaine::lire(brut.value())?,
            ));
        }
    }
    Ok(rendus)
}

/// Ce domaine, s'il est VIVANT, lu dans ces deux tables.
pub(crate) fn vivant_dans<I, D>(
    index: &I,
    domaines: &D,
    domaine: Identifiant,
) -> Result<Option<Domaine>, Faute>
where
    I: ReadableTable<&'static [u8], &'static [u8]>,
    D: ReadableTable<&'static [u8], &'static [u8; DOMAINE_OCTETS]>,
{
    let rangee = match domaines.get(clef(domaine).as_slice())? {
        Some(brut) => Domaine::lire(brut.value())?,
        None => return Ok(None),
    };
    let tous = freres(index, domaines, rangee.proprietaire)?;
    Ok(vivant(domaine, &rangee, &tous).then_some(rangee))
}

// ── Lire et écrire, dans une transaction d'écriture ─────────────────────────

/// Le domaine rangé sous cet identifiant, marqué ou non.
fn domaine_dans(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
) -> Result<Option<Domaine>, Faute> {
    let table = ecriture.open_table(DOMAINES)?;
    let lu = table.get(clef(domaine).as_slice())?;
    Ok(match lu {
        Some(brut) => Some(Domaine::lire(brut.value())?),
        None => None,
    })
}

/// Ce domaine, s'il est vivant, dans cette transaction.
pub(crate) fn vivant_dans_l_ecriture(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
) -> Result<Option<Domaine>, Faute> {
    let index = ecriture.open_table(DOMAINES_PAR_COMPTE)?;
    let domaines = ecriture.open_table(DOMAINES)?;
    vivant_dans(&index, &domaines, domaine)
}

/// Les domaines de ce compte, marqués compris, dans cette transaction.
fn domaines_du_compte_dans(
    ecriture: &WriteTransaction,
    compte: Identifiant,
) -> Result<Vec<(Identifiant, Domaine)>, Faute> {
    let index = ecriture.open_table(DOMAINES_PAR_COMPTE)?;
    let domaines = ecriture.open_table(DOMAINES)?;
    freres(&index, &domaines, compte)
}

/// Écrit ce domaine.
fn ranger_domaine(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    enregistrement: &Domaine,
) -> Result<(), Faute> {
    let mut octets = [0_u8; DOMAINE_OCTETS];
    enregistrement.ecrire(&mut octets);
    ecriture
        .open_table(DOMAINES)?
        .insert(clef(domaine).as_slice(), &octets)?;
    Ok(())
}

// ── Faire naître ────────────────────────────────────────────────────────────

/// Fait naître un domaine, s'il n'existe pas : l'enregistrement et l'index du
/// compte. Rend `false` s'il existait déjà — **insérer si absent**, pour une
/// écriture locale comme pour une opération reçue.
fn inserer_domaine(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    enregistrement: &Domaine,
) -> Result<bool, Faute> {
    if domaine_dans(ecriture, domaine)?.is_some() {
        return Ok(false);
    }
    ranger_domaine(ecriture, domaine, enregistrement)?;
    ecriture.open_table(DOMAINES_PAR_COMPTE)?.insert(
        paire(enregistrement.proprietaire, domaine).as_slice(),
        clef(domaine).as_slice(),
    )?;
    // **SON GROUPE D'ADMINISTRATEURS NAÎT AVEC LUI**, sous son estampille, à
    // chaque naissance — locale, reçue, reprise (`docs/modele.md` §2.12).
    groupes::naitre_le_groupe_d_administrateurs(ecriture, domaine, enregistrement.estampille)?;
    Ok(true)
}

/// Fait naître le premier domaine de ce compte, **sous l'estampille du
/// compte** (`docs/modele.md` §2.11).
///
/// # SOUS L'ESTAMPILLE DU COMPTE, ET NON UNE NEUVE
///
/// Chaque racine l'appelle de son côté — à la création locale, à
/// l'application de l'opération `compte`, à la reprise —, et les deux doivent
/// arriver au même enregistrement, octet pour octet. L'identifiant se déduit
/// du compte ([`premier_domaine`]), l'estampille est celle du compte : il n'y
/// a rien à départager, et rien à journaliser.
pub(crate) fn naitre_premier_domaine(
    ecriture: &WriteTransaction,
    compte: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    inserer_domaine(
        ecriture,
        premier_domaine(compte),
        &Domaine {
            provenance: Provenance::Ici,
            estampille,
            proprietaire: compte,
            supprime: None,
        },
    )?;
    Ok(())
}

/// **La reprise des comptes d'avant les domaines** (`docs/modele.md` §2.11) :
/// chaque compte vivant qui n'a aucun domaine reçoit son premier, déduit, sous
/// son estampille. Une fois, marquée dans la table de la racine ; rend combien
/// de comptes l'ont reçu.
///
/// **Pas une reprise de FORMAT** : les enregistrements existants ne changent
/// pas, des tables s'ajoutent. Mais sans elle, l'invariant « au moins un
/// domaine » ne tiendrait pas pour les comptes d'hier — et chaque racine la
/// fait de son côté, au même résultat, parce que tout y est déduit.
pub(crate) fn reprendre_les_premiers_domaines(ecriture: &WriteTransaction) -> Result<usize, Faute> {
    let fait = ecriture
        .open_table(RACINE)?
        .get(CLEF_DES_PREMIERS_DOMAINES)?
        .is_some();
    if fait {
        return Ok(0);
    }
    let mut comptes = Vec::new();
    {
        let table = ecriture.open_table(COMPTES)?;
        for entree in table.iter()? {
            let (clef_compte, valeur) = entree?;
            let compte = Compte::lire(valeur.value())?;
            if !compte.est_efface() {
                comptes.push((depuis_clef(clef_compte.value())?, compte.estampille));
            }
        }
    }
    let mut combien = 0_usize;
    for (compte, estampille) in comptes {
        if domaines_du_compte_dans(ecriture, compte)?.is_empty() {
            naitre_premier_domaine(ecriture, compte, estampille)?;
            combien = combien.saturating_add(1);
        }
    }
    ecriture
        .open_table(RACINE)?
        .insert(CLEF_DES_PREMIERS_DOMAINES, 1)?;
    Ok(combien)
}

/// **La reprise de l'index des alias de domaine** (0.26.0, décision 45) :
/// jusqu'à 0.25.0, l'index rangeait la clé PLIÉE ; il range désormais
/// l'alias exact. Les alias eux-mêmes ne changent pas — ils ont toujours été
/// rangés tels qu'ils ont été posés, en NFC, la casse gardée —, seul l'index
/// se refait, depuis eux. Une fois, marquée dans la table de la racine ; rend
/// combien d'entrées ont été réindexées.
///
/// **Rien ne voyage** : l'index est local à chaque racine, il ne se réplique
/// pas, et chacune le refait de son côté depuis les mêmes alias. Le journal
/// n'est pas touché.
pub(crate) fn reindexer_les_alias_de_domaines(ecriture: &WriteTransaction) -> Result<usize, Faute> {
    let fait = ecriture
        .open_table(RACINE)?
        .get(CLEF_DES_ALIAS_EXACTS)?
        .is_some();
    if fait {
        return Ok(0);
    }
    {
        let mut index = ecriture.open_table(DOMAINES_PAR_ALIAS)?;
        let anciennes: Vec<Vec<u8>> = index
            .iter()?
            .map(|entree| entree.map(|(clef_index, _)| clef_index.value().to_vec()))
            .collect::<Result<_, _>>()?;
        for ancienne in &anciennes {
            index.remove(ancienne.as_slice())?;
        }
    }
    let mut poses = Vec::new();
    for entree in ecriture.open_table(ALIAS_DE_DOMAINES)?.iter()? {
        let (clef_domaine, valeur) = entree?;
        if let Some(alias) = AliasDeDomaineRange::lire(valeur.value())?.alias {
            poses.push((depuis_clef(clef_domaine.value())?, alias));
        }
    }
    {
        let mut index = ecriture.open_table(DOMAINES_PAR_ALIAS)?;
        for (domaine, alias) in &poses {
            index.insert(
                clef_d_alias(alias, *domaine).as_slice(),
                clef(*domaine).as_slice(),
            )?;
        }
    }
    ecriture
        .open_table(RACINE)?
        .insert(CLEF_DES_ALIAS_EXACTS, 1)?;
    Ok(poses.len())
}

// ── L'alias ─────────────────────────────────────────────────────────────────

/// L'alias posé de ce domaine, s'il y en a un rangé.
fn alias_dans(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
) -> Result<Option<AliasDeDomaineRange>, Faute> {
    let table = ecriture.open_table(ALIAS_DE_DOMAINES)?;
    let lu = table.get(clef(domaine).as_slice())?;
    Ok(match lu {
        Some(brut) => Some(AliasDeDomaineRange::lire(brut.value())?),
        None => None,
    })
}

/// Range cet alias posé pour ce domaine, et tient l'index : l'ancienne entrée
/// part, la neuve entre.
fn ranger_alias(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    pose: &AliasDeDomaineRange,
) -> Result<(), Faute> {
    retirer_l_entree_d_alias(ecriture, domaine)?;
    let mut octets = [0_u8; ALIAS_DE_DOMAINE_RANGE_OCTETS];
    pose.ecrire(&mut octets);
    ecriture
        .open_table(ALIAS_DE_DOMAINES)?
        .insert(clef(domaine).as_slice(), &octets)?;
    if let Some(alias) = &pose.alias {
        ecriture.open_table(DOMAINES_PAR_ALIAS)?.insert(
            clef_d_alias(alias, domaine).as_slice(),
            clef(domaine).as_slice(),
        )?;
    }
    Ok(())
}

/// Retire l'entrée d'index de l'alias rangé de ce domaine, s'il en a une.
fn retirer_l_entree_d_alias(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
) -> Result<(), Faute> {
    if let Some(AliasDeDomaineRange {
        alias: Some(alias), ..
    }) = alias_dans(ecriture, domaine)?
    {
        ecriture
            .open_table(DOMAINES_PAR_ALIAS)?
            .remove(clef_d_alias(&alias, domaine).as_slice())?;
    }
    Ok(())
}

/// Retire l'alias de ce domaine entièrement : l'enregistrement et l'index.
/// C'est ce que l'effacement d'un compte fait des alias de ses domaines.
fn effacer_l_alias(ecriture: &WriteTransaction, domaine: Identifiant) -> Result<(), Faute> {
    retirer_l_entree_d_alias(ecriture, domaine)?;
    ecriture
        .open_table(ALIAS_DE_DOMAINES)?
        .remove(clef(domaine).as_slice())?;
    Ok(())
}

// ── Le rattachement ─────────────────────────────────────────────────────────

/// Le rattachement rangé de cette machine, s'il y en a un.
fn rattachement_dans(
    ecriture: &WriteTransaction,
    machine: Identifiant,
) -> Result<Option<Rattachement>, Faute> {
    let table = ecriture.open_table(RATTACHEMENTS)?;
    let lu = table.get(clef(machine).as_slice())?;
    Ok(match lu {
        Some(brut) => Some(Rattachement::lire(brut.value())?),
        None => None,
    })
}

/// Range ce rattachement pour cette machine, et tient l'index des machines
/// par domaine.
fn ranger_rattachement(
    ecriture: &WriteTransaction,
    machine: Identifiant,
    rattachement: &Rattachement,
) -> Result<(), Faute> {
    let avant = rattachement_dans(ecriture, machine)?.and_then(|quoi| quoi.domaine);
    let mut index = ecriture.open_table(MACHINES_PAR_DOMAINE)?;
    if let Some(ancien) = avant {
        index.remove(paire(ancien, machine).as_slice())?;
    }
    if let Some(neuf) = rattachement.domaine {
        index.insert(paire(neuf, machine).as_slice(), clef(machine).as_slice())?;
    }
    drop(index);
    let mut octets = [0_u8; RATTACHEMENT_OCTETS];
    rattachement.ecrire(&mut octets);
    ecriture
        .open_table(RATTACHEMENTS)?
        .insert(clef(machine).as_slice(), &octets)?;
    Ok(())
}

/// Oublie le rattachement de cette machine : l'enregistrement et l'index.
/// C'est ce qu'on fait d'une machine qui part — effacée avec son compte.
pub(crate) fn oublier_le_rattachement(
    ecriture: &WriteTransaction,
    machine: Identifiant,
) -> Result<(), Faute> {
    if let Some(Rattachement {
        domaine: Some(domaine),
        ..
    }) = rattachement_dans(ecriture, machine)?
    {
        ecriture
            .open_table(MACHINES_PAR_DOMAINE)?
            .remove(paire(domaine, machine).as_slice())?;
    }
    ecriture
        .open_table(RATTACHEMENTS)?
        .remove(clef(machine).as_slice())?;
    Ok(())
}

// ── L'alias d'une machine ───────────────────────────────────────────────────

/// L'alias posé de cette machine, s'il y en a un rangé.
fn alias_de_machine_dans(
    ecriture: &WriteTransaction,
    machine: Identifiant,
) -> Result<Option<AliasDeMachineRange>, Faute> {
    let table = ecriture.open_table(ALIAS_DE_MACHINES)?;
    let lu = table.get(clef(machine).as_slice())?;
    Ok(match lu {
        Some(brut) => Some(AliasDeMachineRange::lire(brut.value())?),
        None => None,
    })
}

/// Range cet alias posé pour cette machine. Pas d'index : on ne cherche pas
/// une machine par son alias (`docs/modele.md` §6).
fn ranger_alias_de_machine(
    ecriture: &WriteTransaction,
    machine: Identifiant,
    pose: &AliasDeMachineRange,
) -> Result<(), Faute> {
    let mut octets = [0_u8; ALIAS_DE_MACHINE_RANGE_OCTETS];
    pose.ecrire(&mut octets);
    ecriture
        .open_table(ALIAS_DE_MACHINES)?
        .insert(clef(machine).as_slice(), &octets)?;
    Ok(())
}

/// Oublie l'alias de cette machine. C'est ce qu'on fait d'une machine qui
/// part — effacée avec son compte.
pub(crate) fn oublier_l_alias_de_machine(
    ecriture: &WriteTransaction,
    machine: Identifiant,
) -> Result<(), Faute> {
    ecriture
        .open_table(ALIAS_DE_MACHINES)?
        .remove(clef(machine).as_slice())?;
    Ok(())
}

// ── Supprimer ───────────────────────────────────────────────────────────────

/// Marque ce domaine supprimé sous cette estampille — **ou garde la plus
/// petite**, s'il l'était déjà : deux racines qui suppriment le même domaine
/// dans la fenêtre doivent finir avec la même marque, et « la première
/// appliquée » dépendrait de l'ordre. Rend `false` si le domaine est inconnu.
///
/// **Rien d'autre ne s'écrit** : ni ses machines ni son alias ne bougent. Un
/// domaine mort n'abrite rien et ne se trouve pas — le lecteur l'écarte (voir
/// [`vivant`]) —, et c'est ce qui laisse la règle des suppressions
/// concurrentes se calculer sur l'ensemble.
pub(crate) fn supprimer_dans(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    estampille: Estampille,
) -> Result<bool, Faute> {
    let Some(avant) = domaine_dans(ecriture, domaine)? else {
        return Ok(false);
    };
    let marque = avant
        .supprime
        .map_or(estampille, |deja| deja.min(estampille));
    ranger_domaine(
        ecriture,
        domaine,
        &Domaine {
            provenance: Provenance::Ici,
            supprime: Some(marque),
            ..avant
        },
    )?;
    Ok(true)
}

// ── L'effacement d'un compte ────────────────────────────────────────────────

/// Ce que l'effacement d'un compte fait de ses domaines
/// (`docs/modele.md` §2.11) : ils partent, avec leur alias et leurs index.
/// **Les machines d'AUTRES comptes qui y étaient rangées gardent leur
/// rattachement**, qui désigne désormais un domaine qui n'existe plus : le
/// lecteur les voit sans domaine, et aucune écriture sous l'estampille de
/// l'effacement ne dépend de laquelle des deux racines l'a voulu la première.
/// Les machines du compte, elles, partent avec lui par ailleurs. Rend
/// combien.
pub(crate) fn effacer_les_domaines(
    ecriture: &WriteTransaction,
    compte: Identifiant,
) -> Result<usize, Faute> {
    let siens = domaines_du_compte_dans(ecriture, compte)?;
    for (domaine, _) in &siens {
        effacer_l_alias(ecriture, *domaine)?;
        // Ce qui visait ce domaine part avec lui (décision 44).
        crate::droits::oublier_ce_qui_vise(ecriture, *domaine)?;
        ecriture
            .open_table(DOMAINES)?
            .remove(clef(*domaine).as_slice())?;
        ecriture
            .open_table(DOMAINES_PAR_COMPTE)?
            .remove(paire(compte, *domaine).as_slice())?;
    }
    Ok(siens.len())
}

// ── Appliquer ce que l'autre racine a écrit (§5.2) ──────────────────────────

/// `domaine` — insérer si absent ; refusé pour un compte effacé.
pub(crate) fn appliquer_domaine(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    enregistrement: &Domaine,
) -> Result<(), Faute> {
    if compte_efface_dans(ecriture, enregistrement.proprietaire)? {
        return Ok(());
    }
    inserer_domaine(
        ecriture,
        domaine,
        &Domaine {
            provenance: Provenance::Ici,
            // **La naissance, pas la suppression** : une suppression voyage
            // par sa propre opération, que l'instantané émet après.
            supprime: None,
            ..*enregistrement
        },
    )?;
    Ok(())
}

/// `domaine-supprime` — toujours ; voir [`supprimer_dans`].
pub(crate) fn appliquer_domaine_supprime(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    supprimer_dans(ecriture, domaine, estampille)?;
    Ok(())
}

/// `domaine-alias` — le plus récent, **mort ou vif** : un alias posé sur un
/// domaine supprimé reste rangé, et le lecteur ne le trouve pas tant que le
/// domaine est mort. **Ignoré pour un domaine inconnu** : effacé avec son
/// compte, il ne revient pas par son alias. **Sauf le domaine racine**
/// (décision 43) : calculé, il n'a jamais de rangée, et son alias doit
/// pourtant passer d'une racine à l'autre — l'ignorer, c'était ne le voir que
/// sur la racine où on l'a posé.
pub(crate) fn appliquer_domaine_alias(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    enregistrement: &AliasDeDomaineRange,
) -> Result<(), Faute> {
    if domaine != domaine_racine() && domaine_dans(ecriture, domaine)?.is_none() {
        return Ok(());
    }
    if alias_dans(ecriture, domaine)?
        .is_some_and(|avant| avant.estampille >= enregistrement.estampille)
    {
        return Ok(());
    }
    ranger_alias(
        ecriture,
        domaine,
        &AliasDeDomaineRange {
            provenance: Provenance::Ici,
            ..*enregistrement
        },
    )
}

/// `machine-domaine` — le plus récent ; **ignoré pour une machine qu'on n'a
/// pas** (effacée avec son compte : c'est ce qui rend le rattachement
/// convergent avec l'effacement). Le domaine visé, lui, n'est pas regardé :
/// mort, inconnu ou vif, le lecteur en décide.
pub(crate) fn appliquer_machine_domaine(
    ecriture: &WriteTransaction,
    machine: Identifiant,
    enregistrement: &Rattachement,
) -> Result<(), Faute> {
    if ecriture
        .open_table(MACHINES)?
        .get(clef(machine).as_slice())?
        .is_none()
    {
        return Ok(());
    }
    if rattachement_dans(ecriture, machine)?
        .is_some_and(|avant| avant.estampille >= enregistrement.estampille)
    {
        return Ok(());
    }
    ranger_rattachement(
        ecriture,
        machine,
        &Rattachement {
            provenance: Provenance::Ici,
            ..*enregistrement
        },
    )
}

/// `machine-alias` — le plus récent ; **ignoré pour une machine qu'on n'a
/// pas** (effacée avec son compte), comme `machine-domaine`.
pub(crate) fn appliquer_machine_alias(
    ecriture: &WriteTransaction,
    machine: Identifiant,
    enregistrement: &AliasDeMachineRange,
) -> Result<(), Faute> {
    if ecriture
        .open_table(MACHINES)?
        .get(clef(machine).as_slice())?
        .is_none()
    {
        return Ok(());
    }
    if alias_de_machine_dans(ecriture, machine)?
        .is_some_and(|avant| avant.estampille >= enregistrement.estampille)
    {
        return Ok(());
    }
    ranger_alias_de_machine(
        ecriture,
        machine,
        &AliasDeMachineRange {
            provenance: Provenance::Ici,
            ..*enregistrement
        },
    )
}

// ── L'instantané ────────────────────────────────────────────────────────────

/// Ce que les domaines ajoutent à un instantané : **chaque domaine, puis
/// chaque marque** — sous l'estampille de la marque.
pub(crate) fn instantane_des_domaines(
    lecture: &redb::ReadTransaction,
    suite: &mut Suite,
) -> Result<(), Faute> {
    let domaines = lecture.open_table(DOMAINES)?;
    let mut supprimes = Vec::new();
    for entree in domaines.iter()? {
        let (clef_domaine, valeur) = entree?;
        let domaine = Domaine::lire(valeur.value())?;
        if domaine.provenance != Provenance::Ici {
            continue;
        }
        let quel = depuis_clef(clef_domaine.value())?;
        suite.ajouter(
            domaine.estampille,
            &Operation::Domaine {
                domaine: quel,
                enregistrement: Domaine {
                    supprime: None,
                    ..domaine
                },
            },
        );
        if let Some(quand) = domaine.supprime {
            supprimes.push((quel, quand));
        }
    }
    for (quel, quand) in supprimes {
        suite.ajouter(quand, &Operation::DomaineSupprime { domaine: quel });
    }
    Ok(())
}

/// Ce que les alias et les rattachements ajoutent à un instantané — APRÈS
/// les machines, qu'un rattachement exige chez le lecteur.
pub(crate) fn instantane_des_alias_et_rattachements(
    lecture: &redb::ReadTransaction,
    suite: &mut Suite,
) -> Result<(), Faute> {
    let alias = lecture.open_table(ALIAS_DE_DOMAINES)?;
    for entree in alias.iter()? {
        let (clef_domaine, valeur) = entree?;
        let pose = AliasDeDomaineRange::lire(valeur.value())?;
        if pose.provenance != Provenance::Ici {
            continue;
        }
        suite.ajouter(
            pose.estampille,
            &Operation::DomaineAlias {
                domaine: depuis_clef(clef_domaine.value())?,
                enregistrement: pose,
            },
        );
    }
    let alias_de_machines = lecture.open_table(ALIAS_DE_MACHINES)?;
    for entree in alias_de_machines.iter()? {
        let (clef_machine, valeur) = entree?;
        let pose = AliasDeMachineRange::lire(valeur.value())?;
        if pose.provenance != Provenance::Ici {
            continue;
        }
        suite.ajouter(
            pose.estampille,
            &Operation::MachineAlias {
                machine: depuis_clef(clef_machine.value())?,
                enregistrement: pose,
            },
        );
    }
    let rattachements = lecture.open_table(RATTACHEMENTS)?;
    for entree in rattachements.iter()? {
        let (clef_machine, valeur) = entree?;
        let rattachement = Rattachement::lire(valeur.value())?;
        if rattachement.provenance != Provenance::Ici {
            continue;
        }
        suite.ajouter(
            rattachement.estampille,
            &Operation::MachineDomaine {
                machine: depuis_clef(clef_machine.value())?,
                enregistrement: rattachement,
            },
        );
    }
    Ok(())
}

// ── Les verbes de l'entrepôt ────────────────────────────────────────────────

impl Entrepot {
    /// Crée ce domaine pour ce compte, avec cet alias s'il en a un.
    ///
    /// Rend `false` si le compte n'est pas vivant. Deux opérations
    /// journalisées quand un alias l'accompagne — `domaine`, puis
    /// `domaine-alias` —, chacune sous son estampille, dans une transaction.
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si l'identifiant est déjà pris, [`Faute::Base`] ou
    /// [`Faute::Enregistrement`].
    pub fn creer_domaine(
        &self,
        domaine: Identifiant,
        proprietaire: Identifiant,
        alias: Option<AliasDeDomaine>,
    ) -> Result<bool, Faute> {
        let ecriture = self.base.begin_write()?;
        if compte_vivant_dans(&ecriture, proprietaire)?.is_none() {
            return Ok(false);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        let enregistrement = Domaine {
            provenance: Provenance::Ici,
            estampille,
            proprietaire,
            supprime: None,
        };
        if !inserer_domaine(&ecriture, domaine, &enregistrement)? {
            return Err(Faute::Existe);
        }
        let mut journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::Domaine {
                domaine,
                enregistrement,
            },
        )?;
        if let Some(alias) = alias {
            let estampille = estampiller(&ecriture, self.racine)?;
            let pose = AliasDeDomaineRange {
                provenance: Provenance::Ici,
                estampille,
                alias: Some(alias),
            };
            ranger_alias(&ecriture, domaine, &pose)?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                Provenance::Ici,
                &Operation::DomaineAlias {
                    domaine,
                    enregistrement: pose,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(true)
    }

    /// Le domaine rangé sous cet identifiant — **vivant seulement** : un
    /// domaine supprimé n'existe plus pour qui le demande (voir [`vivant`]).
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn domaine(&self, domaine: Identifiant) -> Result<Option<Domaine>, Faute> {
        let lecture = self.base.begin_read()?;
        let index = lecture.open_table(DOMAINES_PAR_COMPTE)?;
        let domaines = lecture.open_table(DOMAINES)?;
        vivant_dans(&index, &domaines, domaine)
    }

    /// Les domaines vivants de ce compte, dans l'ordre de leurs identifiants.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn domaines_de_compte(
        &self,
        compte: Identifiant,
    ) -> Result<Vec<(Identifiant, Domaine)>, Faute> {
        let lecture = self.base.begin_read()?;
        let index = lecture.open_table(DOMAINES_PAR_COMPTE)?;
        let domaines = lecture.open_table(DOMAINES)?;
        let tous = freres(&index, &domaines, compte)?;
        Ok(tous
            .iter()
            .filter(|(quel, rangee)| vivant(*quel, rangee, &tous))
            .copied()
            .collect())
    }

    /// L'alias rangé de ce domaine, s'il en porte un.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn alias_de_domaine(&self, domaine: Identifiant) -> Result<Option<AliasDeDomaine>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(ALIAS_DE_DOMAINES)?;
        let lu = table.get(clef(domaine).as_slice())?;
        Ok(match lu {
            Some(brut) => AliasDeDomaineRange::lire(brut.value())?.alias,
            None => None,
        })
    }

    /// Pose — ou retire, avec `None` — l'alias de ce domaine. Rend `false` si
    /// le domaine n'est pas vivant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn poser_alias_de_domaine(
        &self,
        domaine: Identifiant,
        alias: Option<AliasDeDomaine>,
    ) -> Result<bool, Faute> {
        let ecriture = self.base.begin_write()?;
        // **LE DOMAINE RACINE N'EST ÉCRIT NULLE PART** (décision 43) : il se
        // calcule. Il porte pourtant un alias comme les autres — c'est le
        // verbe qui décide qui peut le poser (ses administrateurs) ; ici, on
        // ne refuse que ce qui n'existe pas.
        if domaine != domaine_racine() && vivant_dans_l_ecriture(&ecriture, domaine)?.is_none() {
            return Ok(false);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        let pose = AliasDeDomaineRange {
            provenance: Provenance::Ici,
            estampille,
            alias,
        };
        ranger_alias(&ecriture, domaine, &pose)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::DomaineAlias {
                domaine,
                enregistrement: pose,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(true)
    }

    /// Les domaines VIVANTS qui portent exactement cet alias — en NFC, **la
    /// casse comptant** (décision 45).
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn domaines_par_alias(
        &self,
        recherche: &AliasDeDomaine,
    ) -> Result<Vec<Identifiant>, Faute> {
        let lecture = self.base.begin_read()?;
        let par_alias = lecture.open_table(DOMAINES_PAR_ALIAS)?;
        let index = lecture.open_table(DOMAINES_PAR_COMPTE)?;
        let domaines = lecture.open_table(DOMAINES)?;
        let debut = prefixe_d_alias(recherche);
        let mut fin = debut.clone();
        fin.push(0xFF);
        let mut trouves = Vec::new();
        for entree in par_alias.range(debut.as_slice()..fin.as_slice())? {
            let (_, domaine) = entree?;
            let quel = depuis_clef(domaine.value())?;
            // Le domaine racine, calculé, n'a pas de rangée : son alias suffit.
            if quel == domaine_racine() || vivant_dans(&index, &domaines, quel)?.is_some() {
                trouves.push(quel);
            }
        }
        Ok(trouves)
    }

    /// Supprime ce domaine — **jamais le dernier vivant de son compte**.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn supprimer_domaine(&self, domaine: Identifiant) -> Result<SuppressionDeDomaine, Faute> {
        let ecriture = self.base.begin_write()?;
        let Some(rangee) = vivant_dans_l_ecriture(&ecriture, domaine)? else {
            return Ok(SuppressionDeDomaine::Absent);
        };
        let tous = domaines_du_compte_dans(&ecriture, rangee.proprietaire)?;
        let vivants = tous
            .iter()
            .filter(|(quel, frere)| vivant(*quel, frere, &tous))
            .count();
        if vivants < 2 {
            return Ok(SuppressionDeDomaine::Derniere);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        supprimer_dans(&ecriture, domaine, estampille)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::DomaineSupprime { domaine },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(SuppressionDeDomaine::Faite)
    }

    /// Range cette machine dans ce domaine — ou l'en sort, avec `None`.
    /// Rend `false` si la machine n'existe pas, ou si le domaine nommé n'est
    /// pas vivant. **Les droits se jugent avant** : l'entrepôt ne décide pas.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn rattacher_machine(
        &self,
        machine: Identifiant,
        domaine: Option<Identifiant>,
    ) -> Result<bool, Faute> {
        let ecriture = self.base.begin_write()?;
        if ecriture
            .open_table(MACHINES)?
            .get(clef(machine).as_slice())?
            .is_none()
        {
            return Ok(false);
        }
        if let Some(quel) = domaine
            && vivant_dans_l_ecriture(&ecriture, quel)?.is_none()
        {
            return Ok(false);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        let rattachement = Rattachement {
            provenance: Provenance::Ici,
            estampille,
            domaine,
        };
        ranger_rattachement(&ecriture, machine, &rattachement)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::MachineDomaine {
                machine,
                enregistrement: rattachement,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(true)
    }

    /// Pose — ou retire, avec `None` — l'alias de cette machine. Rend `false`
    /// si la machine n'existe pas. **Les droits se jugent avant** : l'entrepôt
    /// ne décide pas.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn poser_alias_de_machine(
        &self,
        machine: Identifiant,
        alias: Option<AliasDeMachine>,
    ) -> Result<bool, Faute> {
        let ecriture = self.base.begin_write()?;
        if ecriture
            .open_table(MACHINES)?
            .get(clef(machine).as_slice())?
            .is_none()
        {
            return Ok(false);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        let pose = AliasDeMachineRange {
            provenance: Provenance::Ici,
            estampille,
            alias,
        };
        ranger_alias_de_machine(&ecriture, machine, &pose)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::MachineAlias {
                machine,
                enregistrement: pose,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(true)
    }

    /// L'alias de cette machine, s'il en a un.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn alias_de_machine(&self, machine: Identifiant) -> Result<Option<AliasDeMachine>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(ALIAS_DE_MACHINES)?;
        let lu = table.get(clef(machine).as_slice())?;
        Ok(match lu {
            Some(brut) => AliasDeMachineRange::lire(brut.value())?.alias,
            None => None,
        })
    }

    /// Le domaine VIVANT de cette machine, si elle en a un.
    ///
    /// # UNE MACHINE N'EST RANGÉE QUE LÀ OÙ SON PROPRIÉTAIRE PEUT RANGER
    ///
    /// `docs/modele.md` §2.11 : retirer un compte du groupe qui lui donnait de
    /// quoi ranger **détache ses machines**. Ce détachement ne s'écrit pas —
    /// il dépendrait de laquelle des deux racines a vu le retrait la première
    /// (décision 42) : il se LIT. Le rattachement reste rangé tel que sa règle
    /// l'a laissé, et il ne vaut que tant que le propriétaire de la machine
    /// administre le domaine ; rajouté au groupe, il retrouve sa machine.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn domaine_de_machine(&self, machine: Identifiant) -> Result<Option<Identifiant>, Faute> {
        let rattache = {
            let lecture = self.base.begin_read()?;
            let table = lecture.open_table(RATTACHEMENTS)?;
            let lu = table.get(clef(machine).as_slice())?;
            match lu {
                Some(brut) => Rattachement::lire(brut.value())?.domaine,
                None => None,
            }
        };
        match rattache {
            Some(domaine) if self.rangee_la(machine, domaine)? => Ok(Some(domaine)),
            _ => Ok(None),
        }
    }

    /// Cette machine vaut-elle rangée dans ce domaine ? Le domaine vivant, et
    /// son propriétaire à elle qui peut y ranger — il l'administre, ou l'un de
    /// ses groupes a reçu `rattacher` sur lui (décision 43, étendue par la
    /// 44).
    fn rangee_la(&self, machine: Identifiant, domaine: Identifiant) -> Result<bool, Faute> {
        let Some(rangee) = self.machine(machine)? else {
            return Ok(false);
        };
        self.peut_ranger(rangee.proprietaire, domaine)
    }

    /// Les machines rangées dans ce domaine, s'il est vivant — celles dont le
    /// propriétaire l'administre encore (voir [`Entrepot::domaine_de_machine`]).
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn machines_du_domaine(&self, domaine: Identifiant) -> Result<Vec<Identifiant>, Faute> {
        if self.domaine(domaine)?.is_none() {
            return Ok(Vec::new());
        }
        let candidates = {
            let lecture = self.base.begin_read()?;
            let index = lecture.open_table(MACHINES_PAR_DOMAINE)?;
            let (debut, fin) = intervalle(domaine);
            let mut candidates = Vec::new();
            for entree in index.range(debut.as_slice()..fin.as_slice())? {
                let (_, machine) = entree?;
                candidates.push(depuis_clef(machine.value())?);
            }
            candidates
        };
        let mut machines = Vec::new();
        for machine in candidates {
            if self.rangee_la(machine, domaine)? {
                machines.push(machine);
            }
        }
        Ok(machines)
    }
}

/// Le compte, s'il est vivant, dans cette transaction.
fn compte_vivant_dans(
    ecriture: &WriteTransaction,
    qui: Identifiant,
) -> Result<Option<Compte>, Faute> {
    let table = ecriture.open_table(COMPTES)?;
    let lu = table.get(clef(qui).as_slice())?;
    Ok(match lu {
        Some(brut) => Some(Compte::lire(brut.value())?).filter(|compte| !compte.est_efface()),
        None => None,
    })
}

/// Ce qui vient de cet annuaire, dans les tables des domaines (C17). **Rien
/// aujourd'hui** : les domaines ne voyagent qu'entre racines, de provenance
/// locale. Les enregistrements portent leur provenance quand même, et la
/// rupture les regarde — un champ qu'on omet parce qu'on croit savoir qu'il
/// vaudra toujours la même chose est un champ qu'on ajoutera trop tard.
pub(crate) fn oublier_ce_qui_vient_de(
    ecriture: &WriteTransaction,
    annuaire: Identifiant,
) -> Result<usize, Faute> {
    let mut combien = 0_usize;
    let mut domaines = Vec::new();
    for entree in ecriture.open_table(DOMAINES)?.iter()? {
        let (clef_domaine, valeur) = entree?;
        let domaine = Domaine::lire(valeur.value())?;
        if domaine.provenance.vient_de(annuaire) {
            domaines.push((depuis_clef(clef_domaine.value())?, domaine.proprietaire));
        }
    }
    for (domaine, proprietaire) in &domaines {
        effacer_l_alias(ecriture, *domaine)?;
        ecriture
            .open_table(DOMAINES)?
            .remove(clef(*domaine).as_slice())?;
        ecriture
            .open_table(DOMAINES_PAR_COMPTE)?
            .remove(paire(*proprietaire, *domaine).as_slice())?;
    }
    combien = combien.saturating_add(domaines.len());
    let mut alias = Vec::new();
    for entree in ecriture.open_table(ALIAS_DE_DOMAINES)?.iter()? {
        let (clef_domaine, valeur) = entree?;
        if AliasDeDomaineRange::lire(valeur.value())?
            .provenance
            .vient_de(annuaire)
        {
            alias.push(depuis_clef(clef_domaine.value())?);
        }
    }
    for domaine in &alias {
        effacer_l_alias(ecriture, *domaine)?;
    }
    combien = combien.saturating_add(alias.len());
    let mut machines = Vec::new();
    for entree in ecriture.open_table(RATTACHEMENTS)?.iter()? {
        let (clef_machine, valeur) = entree?;
        if Rattachement::lire(valeur.value())?
            .provenance
            .vient_de(annuaire)
        {
            machines.push(depuis_clef(clef_machine.value())?);
        }
    }
    for machine in &machines {
        oublier_le_rattachement(ecriture, *machine)?;
    }
    combien = combien.saturating_add(machines.len());
    let mut alias_de_machines = Vec::new();
    for entree in ecriture.open_table(ALIAS_DE_MACHINES)?.iter()? {
        let (clef_machine, valeur) = entree?;
        if AliasDeMachineRange::lire(valeur.value())?
            .provenance
            .vient_de(annuaire)
        {
            alias_de_machines.push(depuis_clef(clef_machine.value())?);
        }
    }
    for machine in &alias_de_machines {
        oublier_l_alias_de_machine(ecriture, *machine)?;
    }
    Ok(combien.saturating_add(alias_de_machines.len()))
}
