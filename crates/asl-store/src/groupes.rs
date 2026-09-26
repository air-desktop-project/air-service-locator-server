//! Les groupes dans l'entrepôt (`docs/modele.md` §2.12, `docs/replication.md`
//! §3.2 et §5.2) : les tables, les naissances déduites, les écritures locales,
//! les règles d'application, et ce que l'effacement d'un compte, l'instantané,
//! la reprise et le ré-estampillage en font.
//!
//! # CE QUI S'ÉCRIT ET CE QUI SE LIT — LA DISCIPLINE DE LA DÉCISION 42
//!
//! **Une appartenance ne s'écrit jamais « par réparation ».** Qui est membre
//! d'un groupe, qui administre un domaine, où une machine est rangée : tout se
//! calcule à la lecture, sur l'ensemble des enregistrements, que les deux
//! racines finissent par tenir à l'identique. Ce qui s'écrit n'est que ce que
//! les opérations disent :
//!
//! - **une adhésion par AJOUT**, sous l'estampille de l'ajout, dans la clé ;
//!   son retrait la marque, et ne l'efface pas — un retrait arrivé avant
//!   l'ajout qu'il nomme se range quand même, déjà retiré ;
//! - **une marque par groupe supprimé**, jamais effacée, la plus petite ;
//! - **le groupe d'administrateurs d'un domaine et le groupe personnel d'un
//!   compte naissent avec lui**, identifiants déduits, sous son estampille :
//!   les deux racines les font naître chacune de son côté, au même
//!   enregistrement octet pour octet, et aucune opération ne les porte.
//!
//! Le propriétaire d'un domaine est membre d'office de son groupe
//! d'administrateurs, et le titulaire d'un groupe personnel du sien : **ces
//! deux appartenances ne sont écrites nulle part**, elles se lisent.

use asl_id::Identifiant;
use asl_registre::{
    ADHESION_OCTETS, Adhesion, COMPTE_OCTETS, Compte, DOMAINE_OCTETS, Domaine, Estampille,
    GROUPE_OCTETS, Groupe, MARQUE_DE_GROUPE_OCTETS, MarqueDeGroupe, NomRange, Operation,
    Provenance, SorteDeGroupe, domaine_racine, groupe_d_administrateurs, groupe_personnel,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::{
    COMPTES, Entrepot, Faute, RACINE, Suite, clef, compte_efface_dans, depuis_clef, domaines,
    droits, estampiller, intervalle, journaliser_l_operation, paire,
};

/// Les groupes, par leur identifiant — ceux qui se déduisent comme ceux qu'on
/// crée.
pub(crate) const GROUPES: TableDefinition<'_, &[u8], &[u8; GROUPE_OCTETS]> =
    TableDefinition::new("groupes");

/// Index : `rattaché ‖ groupe` → groupe. Les groupes d'un domaine se suivent ;
/// le groupe personnel d'un compte est sous le compte.
pub(crate) const GROUPES_PAR_RATTACHE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("groupes-par-rattache");

/// Les marques des groupes supprimés.
pub(crate) const MARQUES_DE_GROUPES: TableDefinition<'_, &[u8], &[u8; MARQUE_DE_GROUPE_OCTETS]> =
    TableDefinition::new("marques-de-groupes");

/// Les adhésions : `groupe ‖ compte ‖ estampille de l'ajout` → l'adhésion.
pub(crate) const ADHESIONS: TableDefinition<'_, &[u8], &[u8; ADHESION_OCTETS]> =
    TableDefinition::new("adhesions");

/// Index : `compte ‖ groupe ‖ estampille de l'ajout` → groupe. Les adhésions
/// d'un compte se suivent — c'est ce que l'effacement d'un compte balaie, et
/// ce que « mes groupes » lit.
pub(crate) const ADHESIONS_PAR_COMPTE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("adhesions-par-compte");

/// La clé de la reprise des groupes déduits, dans la table de la racine.
pub(crate) const CLEF_DES_GROUPES_DEDUITS: &str = "groupes-deduits";

/// Ce qu'une estampille occupe dans une clé : le compteur en gros-boutiste,
/// puis la racine. **Le compteur d'abord**, pour que l'ordre des octets soit
/// celui des estampilles.
const ESTAMPILLE_EN_CLEF: usize = 8 + asl_registre::IDENTIFIANT_OCTETS;

// ── Les clés ────────────────────────────────────────────────────────────────

/// Une estampille, en clé.
fn estampille_en_clef(estampille: Estampille) -> Vec<u8> {
    let mut octets = estampille.compteur.to_be_bytes().to_vec();
    octets.extend_from_slice(&clef(estampille.racine));
    octets
}

/// Relit une estampille rangée en clé.
fn estampille_de_clef(octets: &[u8]) -> Result<Estampille, Faute> {
    let mut compteur = [0_u8; 8];
    for (place, octet) in compteur.iter_mut().zip(octets.iter()) {
        *place = *octet;
    }
    Ok(Estampille {
        compteur: u64::from_be_bytes(compteur),
        racine: depuis_clef(octets.get(8..).unwrap_or_default())?,
    })
}

/// La clé d'une adhésion : le groupe, le compte, l'ajout.
fn clef_d_adhesion(groupe: Identifiant, compte: Identifiant, ajout: Estampille) -> Vec<u8> {
    let mut composee = paire(groupe, compte);
    composee.extend_from_slice(&estampille_en_clef(ajout));
    composee
}

/// La clé de l'index des adhésions par compte : le compte, le groupe, l'ajout.
fn clef_d_adhesion_par_compte(
    groupe: Identifiant,
    compte: Identifiant,
    ajout: Estampille,
) -> Vec<u8> {
    let mut composee = paire(compte, groupe);
    composee.extend_from_slice(&estampille_en_clef(ajout));
    composee
}

/// Relit une clé d'adhésion : le groupe, le compte, l'ajout.
fn lire_clef_d_adhesion(octets: &[u8]) -> Result<(Identifiant, Identifiant, Estampille), Faute> {
    let taille = asl_registre::IDENTIFIANT_OCTETS;
    let attendue = taille.saturating_mul(2).saturating_add(ESTAMPILLE_EN_CLEF);
    if octets.len() != attendue {
        return Err(Faute::Longueur {
            obtenue: octets.len(),
        });
    }
    Ok((
        depuis_clef(octets.get(..taille).unwrap_or_default())?,
        depuis_clef(
            octets
                .get(taille..taille.saturating_mul(2))
                .unwrap_or_default(),
        )?,
        estampille_de_clef(octets.get(taille.saturating_mul(2)..).unwrap_or_default())?,
    ))
}

/// Le groupe des administrateurs des racines : celui du domaine racine.
fn groupe_des_administrateurs_des_racines() -> Identifiant {
    groupe_d_administrateurs(domaine_racine())
}

// ── Ce qu'un groupe est, lu ─────────────────────────────────────────────────

/// Un groupe VIVANT, tel qu'on le lit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupeLu {
    /// Son identifiant.
    pub groupe: Identifiant,
    /// Sa sorte.
    pub sorte: SorteDeGroupe,
    /// Son domaine — rien pour un groupe personnel.
    pub domaine: Option<Identifiant>,
    /// Le compte dont c'est le groupe personnel — rien sinon.
    pub titulaire: Option<Identifiant>,
    /// Son étiquette, s'il en porte une.
    pub etiquette: Option<NomRange>,
}

/// Ce que les lectures des groupes demandent, ouvert dans UNE transaction —
/// de lecture pour les verbes qui lisent, d'écriture pour ceux qui écrivent
/// après avoir jugé.
struct Vue<'t, G, M, A, C, I, D> {
    /// Les groupes.
    groupes: &'t G,
    /// Les marques.
    marques: &'t M,
    /// Les adhésions.
    adhesions: &'t A,
    /// Les comptes.
    comptes: &'t C,
    /// Les domaines d'un compte.
    index: &'t I,
    /// Les domaines.
    domaines: &'t D,
}

impl<G, M, A, C, I, D> Vue<'_, G, M, A, C, I, D>
where
    G: ReadableTable<&'static [u8], &'static [u8; GROUPE_OCTETS]>,
    M: ReadableTable<&'static [u8], &'static [u8; MARQUE_DE_GROUPE_OCTETS]>,
    A: ReadableTable<&'static [u8], &'static [u8; ADHESION_OCTETS]>,
    C: ReadableTable<&'static [u8], &'static [u8; COMPTE_OCTETS]>,
    I: ReadableTable<&'static [u8], &'static [u8]>,
    D: ReadableTable<&'static [u8], &'static [u8; DOMAINE_OCTETS]>,
{
    /// Le groupe rangé, vivant ou non.
    fn rangee(&self, groupe: Identifiant) -> Result<Option<Groupe>, Faute> {
        match self.groupes.get(clef(groupe).as_slice())? {
            Some(brut) => Ok(Some(Groupe::lire(brut.value())?)),
            None => Ok(None),
        }
    }

    /// Ce groupe est-il marqué supprimé ?
    fn marque(&self, groupe: Identifiant) -> Result<bool, Faute> {
        Ok(self.marques.get(clef(groupe).as_slice())?.is_some())
    }

    /// Ce compte est-il vivant — connu et non effacé ?
    fn compte_vivant(&self, compte: Identifiant) -> Result<bool, Faute> {
        match self.comptes.get(clef(compte).as_slice())? {
            Some(brut) => Ok(!Compte::lire(brut.value())?.est_efface()),
            None => Ok(false),
        }
    }

    /// Ce domaine, s'il est vivant.
    fn domaine_vivant(&self, domaine: Identifiant) -> Result<Option<Domaine>, Faute> {
        domaines::vivant_dans(self.index, self.domaines, domaine)
    }

    /// Les adhésions de ce groupe : le compte, l'ajout, et l'adhésion.
    fn adhesions(
        &self,
        groupe: Identifiant,
    ) -> Result<Vec<(Identifiant, Estampille, Adhesion)>, Faute> {
        let (debut, fin) = intervalle(groupe);
        let mut rendues = Vec::new();
        for entree in self.adhesions.range(debut.as_slice()..fin.as_slice())? {
            let (clef_adhesion, valeur) = entree?;
            let (_, compte, ajout) = lire_clef_d_adhesion(clef_adhesion.value())?;
            rendues.push((compte, ajout, Adhesion::lire(valeur.value())?));
        }
        Ok(rendues)
    }

    /// Ce groupe, s'il est VIVANT.
    ///
    /// Un groupe créé : rangé, sans marque, dans un domaine vivant. Un groupe
    /// d'administrateurs : son domaine vivant — la marque ne le vise jamais.
    /// Un groupe personnel : son compte vivant. Celui des administrateurs des
    /// racines : toujours, sans enregistrement — il se déduit d'un domaine qui
    /// se déduit lui-même.
    fn lire(&self, groupe: Identifiant) -> Result<Option<GroupeLu>, Faute> {
        if groupe == groupe_des_administrateurs_des_racines() {
            return Ok(Some(GroupeLu {
                groupe,
                sorte: SorteDeGroupe::Administrateurs,
                domaine: Some(domaine_racine()),
                titulaire: None,
                etiquette: None,
            }));
        }
        let Some(rangee) = self.rangee(groupe)? else {
            return Ok(None);
        };
        let vivant = match rangee.sorte {
            SorteDeGroupe::Domaine => {
                !self.marque(groupe)? && self.domaine_vivant(rangee.rattache)?.is_some()
            }
            SorteDeGroupe::Administrateurs => self.domaine_vivant(rangee.rattache)?.is_some(),
            SorteDeGroupe::Personnel => self.compte_vivant(rangee.rattache)?,
        };
        if !vivant {
            return Ok(None);
        }
        let personnel = rangee.sorte == SorteDeGroupe::Personnel;
        Ok(Some(GroupeLu {
            groupe,
            sorte: rangee.sorte,
            domaine: (!personnel).then_some(rangee.rattache),
            titulaire: personnel.then_some(rangee.rattache),
            etiquette: (rangee.etiquette.longueur() > 0).then_some(rangee.etiquette),
        }))
    }

    /// Les membres de ce groupe vivant, dans l'ordre de leurs identifiants.
    ///
    /// **Ceux d'office d'abord** — le propriétaire du domaine dans son groupe
    /// d'administrateurs, le titulaire dans son groupe personnel —, **puis
    /// chaque ajout que rien n'a retiré**, d'un compte vivant. Un groupe
    /// personnel n'a pas d'autre membre que son titulaire, quoi qu'on y ait
    /// rangé.
    fn membres(&self, lu: &GroupeLu) -> Result<Vec<Identifiant>, Faute> {
        let mut membres = Vec::new();
        if let Some(titulaire) = lu.titulaire {
            membres.push(titulaire);
            return Ok(membres);
        }
        if lu.sorte == SorteDeGroupe::Administrateurs
            && let Some(domaine) = lu.domaine
            && let Some(rangee) = self.domaine_vivant(domaine)?
        {
            membres.push(rangee.proprietaire);
        }
        for (compte, _, adhesion) in self.adhesions(lu.groupe)? {
            if adhesion.retire.is_none() && self.compte_vivant(compte)? {
                membres.push(compte);
            }
        }
        membres.sort();
        membres.dedup();
        Ok(membres)
    }

    /// Les administrateurs des racines, et le propriétaire du domaine racine :
    /// **le premier nommé**, celui dont l'ajout encore vivant est le plus
    /// ancien (`docs/modele.md` §2.11). Calculé, jamais écrit.
    fn administrateurs_des_racines(
        &self,
    ) -> Result<(Vec<Identifiant>, Option<Identifiant>), Faute> {
        let mut vivants = Vec::new();
        for (compte, ajout, adhesion) in self.adhesions(groupe_des_administrateurs_des_racines())? {
            if adhesion.retire.is_none() && self.compte_vivant(compte)? {
                vivants.push((ajout, compte));
            }
        }
        let premier = vivants.iter().min().map(|&(_, compte)| compte);
        let mut membres: Vec<Identifiant> = vivants.into_iter().map(|(_, compte)| compte).collect();
        membres.sort();
        membres.dedup();
        Ok((membres, premier))
    }

    /// Ce compte administre-t-il ce domaine ?
    ///
    /// Le domaine racine : s'il est l'un des administrateurs des racines. Un
    /// autre : si le domaine est vivant, et que le compte en est le
    /// propriétaire ou un membre de son groupe d'administrateurs.
    fn administre(&self, compte: Identifiant, domaine: Identifiant) -> Result<bool, Faute> {
        let admins = groupe_d_administrateurs(domaine);
        let Some(lu) = self.lire(admins)? else {
            return Ok(false);
        };
        Ok(self.membres(&lu)?.contains(&compte))
    }
}

/// Ouvre, dans cette transaction, ce qu'une [`Vue`] demande, et la construit
/// sous ce nom.
macro_rules! vue {
    ($transaction:expr, $nom:ident) => {
        let groupes = $transaction.open_table(GROUPES)?;
        let marques = $transaction.open_table(MARQUES_DE_GROUPES)?;
        let adhesions = $transaction.open_table(ADHESIONS)?;
        let comptes = $transaction.open_table(COMPTES)?;
        let index = $transaction.open_table(domaines::DOMAINES_PAR_COMPTE)?;
        let tables_des_domaines = $transaction.open_table(domaines::DOMAINES)?;
        let $nom = Vue {
            groupes: &groupes,
            marques: &marques,
            adhesions: &adhesions,
            comptes: &comptes,
            index: &index,
            domaines: &tables_des_domaines,
        };
    };
}

// ── Faire naître les groupes déduits ────────────────────────────────────────

/// Range ce groupe et son entrée d'index, s'il n'existe pas. Rend `false`
/// s'il existait.
fn inserer_groupe(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    enregistrement: &Groupe,
) -> Result<bool, Faute> {
    if ecriture
        .open_table(GROUPES)?
        .get(clef(groupe).as_slice())?
        .is_some()
    {
        return Ok(false);
    }
    ranger_groupe(ecriture, groupe, enregistrement)?;
    ecriture.open_table(GROUPES_PAR_RATTACHE)?.insert(
        paire(enregistrement.rattache, groupe).as_slice(),
        clef(groupe).as_slice(),
    )?;
    Ok(true)
}

/// Écrit ce groupe.
fn ranger_groupe(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    enregistrement: &Groupe,
) -> Result<(), Faute> {
    let mut octets = [0_u8; GROUPE_OCTETS];
    enregistrement.ecrire(&mut octets);
    ecriture
        .open_table(GROUPES)?
        .insert(clef(groupe).as_slice(), &octets)?;
    Ok(())
}

/// Un groupe déduit, sans étiquette, né sous cette estampille.
fn deduit(
    sorte: SorteDeGroupe,
    rattache: Identifiant,
    estampille: Estampille,
) -> Result<Groupe, Faute> {
    Ok(Groupe {
        provenance: Provenance::Ici,
        estampille,
        sorte,
        rattache,
        etiquette_estampille: estampille,
        etiquette: NomRange::nouveau("")?,
    })
}

/// Fait naître le groupe d'administrateurs de ce domaine, **sous
/// l'estampille du domaine** — à chaque naissance d'un domaine, locale ou
/// reçue, et à la reprise. Les deux racines arrivent au même enregistrement.
pub(crate) fn naitre_le_groupe_d_administrateurs(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    inserer_groupe(
        ecriture,
        groupe_d_administrateurs(domaine),
        &deduit(SorteDeGroupe::Administrateurs, domaine, estampille)?,
    )?;
    Ok(())
}

/// Fait naître le groupe personnel de ce compte, **sous l'estampille du
/// compte** — à chaque naissance d'un compte, locale ou reçue, et à la
/// reprise.
pub(crate) fn naitre_le_groupe_personnel(
    ecriture: &WriteTransaction,
    compte: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    inserer_groupe(
        ecriture,
        groupe_personnel(compte),
        &deduit(SorteDeGroupe::Personnel, compte, estampille)?,
    )?;
    Ok(())
}

/// **La reprise des groupes déduits** : chaque compte vivant reçoit son groupe
/// personnel, chaque domaine rangé son groupe d'administrateurs — sous leur
/// estampille, identifiants déduits. Une fois, marquée dans la table de la
/// racine ; rend combien de groupes sont nés.
///
/// **Pas une reprise de FORMAT, et elle ne vide pas le journal** : comme celle
/// des premiers domaines, elle n'écrit rien qu'une opération reçue ferait
/// autrement, et les deux racines la font à l'identique.
pub(crate) fn reprendre_les_groupes_deduits(ecriture: &WriteTransaction) -> Result<usize, Faute> {
    let fait = ecriture
        .open_table(RACINE)?
        .get(CLEF_DES_GROUPES_DEDUITS)?
        .is_some();
    if fait {
        return Ok(0);
    }
    let mut comptes = Vec::new();
    for entree in ecriture.open_table(COMPTES)?.iter()? {
        let (clef_compte, valeur) = entree?;
        let compte = Compte::lire(valeur.value())?;
        if !compte.est_efface() {
            comptes.push((depuis_clef(clef_compte.value())?, compte.estampille));
        }
    }
    let mut domaines_ranges = Vec::new();
    for entree in ecriture.open_table(domaines::DOMAINES)?.iter()? {
        let (clef_domaine, valeur) = entree?;
        domaines_ranges.push((
            depuis_clef(clef_domaine.value())?,
            Domaine::lire(valeur.value())?.estampille,
        ));
    }
    let mut combien = 0_usize;
    for (compte, estampille) in comptes {
        if inserer_groupe(
            ecriture,
            groupe_personnel(compte),
            &deduit(SorteDeGroupe::Personnel, compte, estampille)?,
        )? {
            combien = combien.saturating_add(1);
        }
    }
    for (domaine, estampille) in domaines_ranges {
        if inserer_groupe(
            ecriture,
            groupe_d_administrateurs(domaine),
            &deduit(SorteDeGroupe::Administrateurs, domaine, estampille)?,
        )? {
            combien = combien.saturating_add(1);
        }
    }
    ecriture
        .open_table(RACINE)?
        .insert(CLEF_DES_GROUPES_DEDUITS, 1)?;
    Ok(combien)
}

// ── Les adhésions, les marques ──────────────────────────────────────────────

/// L'adhésion rangée sous cet ajout, s'il y en a une.
fn adhesion_dans(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    compte: Identifiant,
    ajout: Estampille,
) -> Result<Option<Adhesion>, Faute> {
    let table = ecriture.open_table(ADHESIONS)?;
    let lue = table.get(clef_d_adhesion(groupe, compte, ajout).as_slice())?;
    Ok(match lue {
        Some(brut) => Some(Adhesion::lire(brut.value())?),
        None => None,
    })
}

/// Range cette adhésion et son entrée d'index.
fn ranger_adhesion(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    compte: Identifiant,
    ajout: Estampille,
    adhesion: &Adhesion,
) -> Result<(), Faute> {
    let mut octets = [0_u8; ADHESION_OCTETS];
    adhesion.ecrire(&mut octets);
    ecriture
        .open_table(ADHESIONS)?
        .insert(clef_d_adhesion(groupe, compte, ajout).as_slice(), &octets)?;
    ecriture.open_table(ADHESIONS_PAR_COMPTE)?.insert(
        clef_d_adhesion_par_compte(groupe, compte, ajout).as_slice(),
        clef(groupe).as_slice(),
    )?;
    Ok(())
}

/// Retire toutes les adhésions de ce groupe — celles d'un groupe supprimé ou
/// effacé avec son domaine.
fn oublier_les_adhesions_du_groupe(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
) -> Result<usize, Faute> {
    let (debut, fin) = intervalle(groupe);
    let mut condamnees = Vec::new();
    for entree in ecriture
        .open_table(ADHESIONS)?
        .range(debut.as_slice()..fin.as_slice())?
    {
        let (clef_adhesion, _) = entree?;
        condamnees.push(lire_clef_d_adhesion(clef_adhesion.value())?);
    }
    let mut adhesions = ecriture.open_table(ADHESIONS)?;
    let mut index = ecriture.open_table(ADHESIONS_PAR_COMPTE)?;
    for (quel, compte, ajout) in &condamnees {
        adhesions.remove(clef_d_adhesion(*quel, *compte, *ajout).as_slice())?;
        index.remove(clef_d_adhesion_par_compte(*quel, *compte, *ajout).as_slice())?;
    }
    Ok(condamnees.len())
}

/// Marque ce groupe supprimé sous cette estampille — ou garde la plus petite
/// — et retire ses adhésions.
fn marquer(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    let avant = {
        let table = ecriture.open_table(MARQUES_DE_GROUPES)?;
        let lue = table.get(clef(groupe).as_slice())?;
        match lue {
            Some(brut) => Some(MarqueDeGroupe::lire(brut.value())?.estampille),
            None => None,
        }
    };
    let marque = MarqueDeGroupe {
        provenance: Provenance::Ici,
        estampille: avant.map_or(estampille, |deja| deja.min(estampille)),
    };
    let mut octets = [0_u8; MARQUE_DE_GROUPE_OCTETS];
    marque.ecrire(&mut octets);
    ecriture
        .open_table(MARQUES_DE_GROUPES)?
        .insert(clef(groupe).as_slice(), &octets)?;
    oublier_les_adhesions_du_groupe(ecriture, groupe)?;
    // Et ce qu'il avait reçu : un droit à un groupe marqué ne revient pas.
    droits::oublier_les_droits_du_groupe(ecriture, groupe)?;
    Ok(())
}

/// Ce groupe peut-il recevoir des adhésions, dans cette transaction ? Rend sa
/// sorte et son rattaché, ou rien.
///
/// **Ce qu'on regarde est ce qui ne dépend d'aucun ordre** : la marque (jamais
/// effacée), la sorte (jamais changée), l'existence du groupe (née avec son
/// domaine, ou par sa propre opération, toujours avant ce qui la vise chez
/// l'autre racine). La VIE du domaine n'est pas regardée : un domaine mort
/// garde ses adhésions, que le lecteur écarte — et qu'il retrouve si la règle
/// des suppressions concurrentes le garde en vie.
fn peut_recevoir(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
) -> Result<Option<(SorteDeGroupe, Identifiant)>, Faute> {
    if ecriture
        .open_table(MARQUES_DE_GROUPES)?
        .get(clef(groupe).as_slice())?
        .is_some()
    {
        return Ok(None);
    }
    if groupe == groupe_des_administrateurs_des_racines() {
        return Ok(Some((SorteDeGroupe::Administrateurs, domaine_racine())));
    }
    let table = ecriture.open_table(GROUPES)?;
    let lu = table.get(clef(groupe).as_slice())?;
    Ok(match lu {
        Some(brut) => {
            let rangee = Groupe::lire(brut.value())?;
            (rangee.sorte != SorteDeGroupe::Personnel).then_some((rangee.sorte, rangee.rattache))
        }
        None => None,
    })
}

/// Ce compte est-il le propriétaire du domaine de ce groupe d'administrateurs ?
fn proprietaire_d_office(
    ecriture: &WriteTransaction,
    (sorte, rattache): (SorteDeGroupe, Identifiant),
    compte: Identifiant,
) -> Result<bool, Faute> {
    if sorte != SorteDeGroupe::Administrateurs {
        return Ok(false);
    }
    let table = ecriture.open_table(domaines::DOMAINES)?;
    let lu = table.get(clef(rattache).as_slice())?;
    Ok(match lu {
        Some(brut) => Domaine::lire(brut.value())?.proprietaire == compte,
        None => false,
    })
}

// ── Appliquer ce que l'autre racine a écrit (§5.2) ──────────────────────────

/// `groupe` — insérer si absent, l'étiquette au plus récent. **Seulement un
/// groupe créé**, dans un domaine connu : les groupes déduits naissent avec
/// leur domaine ou leur compte, et un domaine effacé avec son compte ne
/// revient pas par ses groupes.
pub(crate) fn appliquer_groupe(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    enregistrement: &Groupe,
) -> Result<(), Faute> {
    if enregistrement.sorte != SorteDeGroupe::Domaine {
        return Ok(());
    }
    let domaine_connu = ecriture
        .open_table(domaines::DOMAINES)?
        .get(clef(enregistrement.rattache).as_slice())?
        .is_some();
    if !domaine_connu {
        return Ok(());
    }
    let recu = Groupe {
        provenance: Provenance::Ici,
        ..*enregistrement
    };
    if !inserer_groupe(ecriture, groupe, &recu)? {
        poser_l_etiquette(ecriture, groupe, recu.etiquette_estampille, recu.etiquette)?;
    }
    Ok(())
}

/// Pose cette étiquette si elle est plus récente que celle du groupe rangé.
/// Ignoré pour un groupe inconnu ou déduit.
fn poser_l_etiquette(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    estampille: Estampille,
    etiquette: NomRange,
) -> Result<(), Faute> {
    let avant = {
        let table = ecriture.open_table(GROUPES)?;
        let lu = table.get(clef(groupe).as_slice())?;
        match lu {
            Some(brut) => Groupe::lire(brut.value())?,
            None => return Ok(()),
        }
    };
    if avant.sorte != SorteDeGroupe::Domaine || avant.etiquette_estampille >= estampille {
        return Ok(());
    }
    ranger_groupe(
        ecriture,
        groupe,
        &Groupe {
            etiquette_estampille: estampille,
            etiquette,
            ..avant
        },
    )
}

/// `groupe-etiquette` — le plus récent.
pub(crate) fn appliquer_groupe_etiquette(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    etiquette: NomRange,
    estampille: Estampille,
) -> Result<(), Faute> {
    poser_l_etiquette(ecriture, groupe, estampille, etiquette)
}

/// `groupe-membre` — insérer l'ajout, sous l'estampille de l'opération ;
/// **refusé** pour un compte effacé, un groupe marqué, inconnu ou personnel.
/// Un retrait déjà rangé sous ce nom le garde retiré.
pub(crate) fn appliquer_groupe_membre(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    compte: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    if compte_efface_dans(ecriture, compte)? || peut_recevoir(ecriture, groupe)?.is_none() {
        return Ok(());
    }
    if adhesion_dans(ecriture, groupe, compte, estampille)?.is_none() {
        ranger_adhesion(
            ecriture,
            groupe,
            compte,
            estampille,
            &Adhesion {
                provenance: Provenance::Ici,
                retire: None,
            },
        )?;
    }
    Ok(())
}

/// `groupe-membre-retire` — **toujours**, l'ajout nommé et lui seul : la plus
/// petite estampille de retrait, ou une adhésion déjà retirée si l'ajout n'est
/// pas encore arrivé. Refusé pour un compte effacé, un groupe marqué, inconnu
/// ou personnel, et pour le propriétaire dans son groupe d'administrateurs.
pub(crate) fn appliquer_groupe_membre_retire(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    compte: Identifiant,
    ajout: Estampille,
    estampille: Estampille,
) -> Result<(), Faute> {
    if compte_efface_dans(ecriture, compte)? {
        return Ok(());
    }
    let Some(rangee) = peut_recevoir(ecriture, groupe)? else {
        return Ok(());
    };
    if proprietaire_d_office(ecriture, rangee, compte)? {
        return Ok(());
    }
    let retire = adhesion_dans(ecriture, groupe, compte, ajout)?
        .and_then(|avant| avant.retire)
        .map_or(estampille, |deja| deja.min(estampille));
    ranger_adhesion(
        ecriture,
        groupe,
        compte,
        ajout,
        &Adhesion {
            provenance: Provenance::Ici,
            retire: Some(retire),
        },
    )
}

/// `groupe-supprime` — **toujours** : la marque, la plus petite, et les
/// adhésions parties. Refusé pour un groupe déduit, qui ne part qu'avec son
/// domaine ou son compte. **Un groupe encore inconnu est marqué quand même** :
/// ce qui arrivera pour lui sera refusé.
pub(crate) fn appliquer_groupe_supprime(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    if groupe == groupe_des_administrateurs_des_racines() {
        return Ok(());
    }
    let sorte = {
        let table = ecriture.open_table(GROUPES)?;
        let lu = table.get(clef(groupe).as_slice())?;
        match lu {
            Some(brut) => Some(Groupe::lire(brut.value())?.sorte),
            None => None,
        }
    };
    if sorte.is_some_and(|sorte| sorte != SorteDeGroupe::Domaine) {
        return Ok(());
    }
    marquer(ecriture, groupe, estampille)
}

// ── L'effacement d'un compte ────────────────────────────────────────────────

/// Retire ce groupe entièrement : l'enregistrement, son index, sa marque, ses
/// adhésions, et les droits qu'il avait reçus — dont il rend le nombre.
fn effacer_le_groupe(
    ecriture: &WriteTransaction,
    groupe: Identifiant,
    rattache: Identifiant,
) -> Result<usize, Faute> {
    oublier_les_adhesions_du_groupe(ecriture, groupe)?;
    let droits_partis = droits::oublier_les_droits_du_groupe(ecriture, groupe)?;
    ecriture
        .open_table(GROUPES)?
        .remove(clef(groupe).as_slice())?;
    ecriture
        .open_table(GROUPES_PAR_RATTACHE)?
        .remove(paire(rattache, groupe).as_slice())?;
    ecriture
        .open_table(MARQUES_DE_GROUPES)?
        .remove(clef(groupe).as_slice())?;
    Ok(droits_partis)
}

/// Les groupes rangés sous ce rattaché.
fn groupes_rattaches(
    ecriture: &WriteTransaction,
    rattache: Identifiant,
) -> Result<Vec<Identifiant>, Faute> {
    let (debut, fin) = intervalle(rattache);
    let mut rendus = Vec::new();
    for entree in ecriture
        .open_table(GROUPES_PAR_RATTACHE)?
        .range(debut.as_slice()..fin.as_slice())?
    {
        let (_, groupe) = entree?;
        rendus.push(depuis_clef(groupe.value())?);
    }
    Ok(rendus)
}

/// Ce que l'effacement d'un compte fait des groupes (`docs/modele.md` §2.11,
/// §2.12) — **avant** que ses domaines partent, dont il lit la liste : les
/// groupes de ses domaines partent, avec leurs adhésions et leurs marques ;
/// son groupe personnel part ; **chacune de ses adhésions** part, retraits
/// compris. Ce qui arriverait ensuite pour lui est refusé, puisque le compte
/// est effacé ; pour ses domaines, puisqu'ils sont inconnus. Rend combien de
/// groupes sont partis, et combien de droits ils emportaient.
pub(crate) fn effacer_les_groupes(
    ecriture: &WriteTransaction,
    compte: Identifiant,
) -> Result<(usize, usize), Faute> {
    let mut partis = 0_usize;
    let mut droits_partis = 0_usize;
    let mut siens = Vec::new();
    {
        let index = ecriture.open_table(domaines::DOMAINES_PAR_COMPTE)?;
        let (debut, fin) = intervalle(compte);
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, domaine) = entree?;
            siens.push(depuis_clef(domaine.value())?);
        }
    }
    siens.push(compte);
    for rattache in siens {
        for groupe in groupes_rattaches(ecriture, rattache)? {
            droits_partis =
                droits_partis.saturating_add(effacer_le_groupe(ecriture, groupe, rattache)?);
            partis = partis.saturating_add(1);
        }
    }
    let (debut, fin) = intervalle(compte);
    let mut condamnees = Vec::new();
    for entree in ecriture
        .open_table(ADHESIONS_PAR_COMPTE)?
        .range(debut.as_slice()..fin.as_slice())?
    {
        let (clef_index, _) = entree?;
        condamnees.push(clef_index.value().to_vec());
    }
    let mut adhesions = ecriture.open_table(ADHESIONS)?;
    let mut index = ecriture.open_table(ADHESIONS_PAR_COMPTE)?;
    for clef_index in &condamnees {
        let (qui, groupe, ajout) = lire_clef_d_adhesion(clef_index)?;
        adhesions.remove(clef_d_adhesion(groupe, qui, ajout).as_slice())?;
        index.remove(clef_index.as_slice())?;
    }
    Ok((partis, droits_partis))
}

// ── L'instantané ────────────────────────────────────────────────────────────

/// Ce que les groupes ajoutent à un instantané — APRÈS les domaines, qu'un
/// groupe exige chez le lecteur : **chaque groupe créé** (les déduits ne
/// voyagent pas), **chaque marque**, puis **chaque ajout et son retrait**.
pub(crate) fn instantane_des_groupes(
    lecture: &redb::ReadTransaction,
    suite: &mut Suite,
) -> Result<(), Faute> {
    for entree in lecture.open_table(GROUPES)?.iter()? {
        let (clef_groupe, valeur) = entree?;
        let groupe = Groupe::lire(valeur.value())?;
        if groupe.sorte != SorteDeGroupe::Domaine || groupe.provenance != Provenance::Ici {
            continue;
        }
        suite.ajouter(
            groupe.estampille,
            &Operation::Groupe {
                groupe: depuis_clef(clef_groupe.value())?,
                enregistrement: groupe,
            },
        );
    }
    for entree in lecture.open_table(MARQUES_DE_GROUPES)?.iter()? {
        let (clef_groupe, valeur) = entree?;
        let marque = MarqueDeGroupe::lire(valeur.value())?;
        if marque.provenance != Provenance::Ici {
            continue;
        }
        suite.ajouter(
            marque.estampille,
            &Operation::GroupeSupprime {
                groupe: depuis_clef(clef_groupe.value())?,
            },
        );
    }
    for entree in lecture.open_table(ADHESIONS)?.iter()? {
        let (clef_adhesion, valeur) = entree?;
        let adhesion = Adhesion::lire(valeur.value())?;
        if adhesion.provenance != Provenance::Ici {
            continue;
        }
        let (groupe, compte, ajout) = lire_clef_d_adhesion(clef_adhesion.value())?;
        suite.ajouter(ajout, &Operation::GroupeMembre { groupe, compte });
        if let Some(retire) = adhesion.retire {
            suite.ajouter(
                retire,
                &Operation::GroupeMembreRetire {
                    groupe,
                    compte,
                    ajout,
                },
            );
        }
    }
    Ok(())
}

// ── Le ré-estampillage (`replication.md` §11.4) ─────────────────────────────

/// Passe sous `vers` ce que `de` a estampillé dans les tables des groupes, et
/// rend combien d'enregistrements ont bougé. **Les adhésions changent de
/// CLÉ** — l'estampille de l'ajout y est —, et leur index avec elles.
pub(crate) fn reestampiller(
    ecriture: &WriteTransaction,
    de: Identifiant,
    vers: Identifiant,
) -> Result<usize, Faute> {
    let sous = |estampille: Estampille| {
        if estampille.racine == de {
            Estampille {
                compteur: estampille.compteur,
                racine: vers,
            }
        } else {
            estampille
        }
    };
    let mut combien = 0_usize;

    let mut groupes = Vec::new();
    for entree in ecriture.open_table(GROUPES)?.iter()? {
        let (clef_groupe, valeur) = entree?;
        let avant = Groupe::lire(valeur.value())?;
        let apres = Groupe {
            estampille: sous(avant.estampille),
            etiquette_estampille: sous(avant.etiquette_estampille),
            ..avant
        };
        if apres != avant {
            groupes.push((depuis_clef(clef_groupe.value())?, apres));
        }
    }
    for (groupe, apres) in &groupes {
        ranger_groupe(ecriture, *groupe, apres)?;
    }
    combien = combien.saturating_add(groupes.len());

    let mut marques = Vec::new();
    for entree in ecriture.open_table(MARQUES_DE_GROUPES)?.iter()? {
        let (clef_groupe, valeur) = entree?;
        let avant = MarqueDeGroupe::lire(valeur.value())?;
        if sous(avant.estampille) != avant.estampille {
            marques.push((
                clef_groupe.value().to_vec(),
                MarqueDeGroupe {
                    estampille: sous(avant.estampille),
                    ..avant
                },
            ));
        }
    }
    {
        let mut table = ecriture.open_table(MARQUES_DE_GROUPES)?;
        for (clef_groupe, apres) in &marques {
            let mut octets = [0_u8; MARQUE_DE_GROUPE_OCTETS];
            apres.ecrire(&mut octets);
            table.insert(clef_groupe.as_slice(), &octets)?;
        }
    }
    combien = combien.saturating_add(marques.len());

    let mut adhesions = Vec::new();
    for entree in ecriture.open_table(ADHESIONS)?.iter()? {
        let (clef_adhesion, valeur) = entree?;
        let (groupe, compte, ajout) = lire_clef_d_adhesion(clef_adhesion.value())?;
        let avant = Adhesion::lire(valeur.value())?;
        let apres = Adhesion {
            retire: avant.retire.map(sous),
            ..avant
        };
        if sous(ajout) != ajout || apres != avant {
            adhesions.push((groupe, compte, ajout, apres));
        }
    }
    for (groupe, compte, ajout, apres) in &adhesions {
        ecriture
            .open_table(ADHESIONS)?
            .remove(clef_d_adhesion(*groupe, *compte, *ajout).as_slice())?;
        ecriture
            .open_table(ADHESIONS_PAR_COMPTE)?
            .remove(clef_d_adhesion_par_compte(*groupe, *compte, *ajout).as_slice())?;
        ranger_adhesion(ecriture, *groupe, *compte, sous(*ajout), apres)?;
    }
    Ok(combien.saturating_add(adhesions.len()))
}

/// Ce qui vient de cet annuaire, dans les tables des groupes (C17). **Rien
/// aujourd'hui**, pour la raison écrite sur celles des domaines ; la rupture
/// les regarde quand même.
pub(crate) fn oublier_ce_qui_vient_de(
    ecriture: &WriteTransaction,
    annuaire: Identifiant,
) -> Result<usize, Faute> {
    let mut groupes = Vec::new();
    for entree in ecriture.open_table(GROUPES)?.iter()? {
        let (clef_groupe, valeur) = entree?;
        let groupe = Groupe::lire(valeur.value())?;
        if groupe.provenance.vient_de(annuaire) {
            groupes.push((depuis_clef(clef_groupe.value())?, groupe.rattache));
        }
    }
    for (groupe, rattache) in &groupes {
        effacer_le_groupe(ecriture, *groupe, *rattache)?;
    }
    let mut marques = Vec::new();
    for entree in ecriture.open_table(MARQUES_DE_GROUPES)?.iter()? {
        let (clef_groupe, valeur) = entree?;
        if MarqueDeGroupe::lire(valeur.value())?
            .provenance
            .vient_de(annuaire)
        {
            marques.push(clef_groupe.value().to_vec());
        }
    }
    {
        let mut table = ecriture.open_table(MARQUES_DE_GROUPES)?;
        for clef_groupe in &marques {
            table.remove(clef_groupe.as_slice())?;
        }
    }
    let mut adhesions = Vec::new();
    for entree in ecriture.open_table(ADHESIONS)?.iter()? {
        let (clef_adhesion, valeur) = entree?;
        if Adhesion::lire(valeur.value())?
            .provenance
            .vient_de(annuaire)
        {
            adhesions.push(lire_clef_d_adhesion(clef_adhesion.value())?);
        }
    }
    for (groupe, compte, ajout) in &adhesions {
        ecriture
            .open_table(ADHESIONS)?
            .remove(clef_d_adhesion(*groupe, *compte, *ajout).as_slice())?;
        ecriture
            .open_table(ADHESIONS_PAR_COMPTE)?
            .remove(clef_d_adhesion_par_compte(*groupe, *compte, *ajout).as_slice())?;
    }
    Ok(groupes
        .len()
        .saturating_add(marques.len())
        .saturating_add(adhesions.len()))
}

// ── Les verbes de l'entrepôt ────────────────────────────────────────────────

/// Ce qu'une écriture locale sur un groupe a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcritureDeGroupe {
    /// Fait.
    Faite,
    /// Le groupe n'existe pas ou plus — ou le compte visé n'existe pas.
    Absent,
    /// Le compte est déjà membre.
    Deja,
    /// Ce groupe ne se modifie pas ainsi : un groupe déduit qu'on voudrait
    /// supprimer ou renommer, le propriétaire qu'on voudrait retirer de son
    /// groupe d'administrateurs — `409`.
    Protege,
    /// Ce groupe ne se modifie pas par ce verbe : un groupe personnel, ou celui
    /// des administrateurs des racines hors de la clé d'exploitant — `403`.
    Interdit,
}

impl Entrepot {
    /// Ce groupe, s'il est vivant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn groupe(&self, groupe: Identifiant) -> Result<Option<GroupeLu>, Faute> {
        let lecture = self.base.begin_read()?;
        vue!(lecture, vue);
        vue.lire(groupe)
    }

    /// Ce groupe et ses membres, s'il est vivant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn groupe_et_membres(
        &self,
        groupe: Identifiant,
    ) -> Result<Option<(GroupeLu, Vec<Identifiant>)>, Faute> {
        let lecture = self.base.begin_read()?;
        vue!(lecture, vue);
        match vue.lire(groupe)? {
            Some(lu) => {
                let membres = vue.membres(&lu)?;
                Ok(Some((lu, membres)))
            }
            None => Ok(None),
        }
    }

    /// Ce compte administre-t-il ce domaine ?
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn administre(&self, compte: Identifiant, domaine: Identifiant) -> Result<bool, Faute> {
        let par_le_groupe = {
            let lecture = self.base.begin_read()?;
            vue!(lecture, vue);
            vue.administre(compte, domaine)?
        };
        // **OU PAR UN DROIT `administrer` REÇU SUR LUI** (décision 40) — jamais
        // sur le domaine racine, qui ne s'administre que par son groupe.
        Ok(par_le_groupe
            || (domaine != domaine_racine()
                && self.domaine(domaine)?.is_some()
                && self
                    .droits_recus_sur(compte, domaine)?
                    .croise(asl_registre::Droits::ADMINISTRER)))
    }

    /// Les groupes VIVANTS dont ce compte est membre : son groupe personnel,
    /// ceux où un ajout le tient, les groupes d'administrateurs de ses
    /// domaines — dont il est membre d'office. **Sans rien lire des droits** :
    /// c'est d'ici que les droits partent, et ce qui en dépendrait tournerait
    /// en rond.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn groupes_dont_membre(&self, compte: Identifiant) -> Result<Vec<Identifiant>, Faute> {
        let siens: Vec<Identifiant> = self
            .domaines_de_compte(compte)?
            .into_iter()
            .map(|(domaine, _)| groupe_d_administrateurs(domaine))
            .collect();
        let lecture = self.base.begin_read()?;
        vue!(lecture, vue);
        let mut candidats = vec![groupe_personnel(compte)];
        candidats.extend(siens);
        {
            let index = lecture.open_table(ADHESIONS_PAR_COMPTE)?;
            let (debut, fin) = intervalle(compte);
            for entree in index.range(debut.as_slice()..fin.as_slice())? {
                let (_, groupe) = entree?;
                candidats.push(depuis_clef(groupe.value())?);
            }
        }
        candidats.sort_by_key(|groupe| clef(*groupe));
        candidats.dedup();
        let mut rendus = Vec::new();
        for groupe in candidats {
            if let Some(lu) = vue.lire(groupe)?
                && vue.membres(&lu)?.contains(&compte)
            {
                rendus.push(groupe);
            }
        }
        Ok(rendus)
    }

    /// Les administrateurs des racines, et le propriétaire du domaine racine
    /// — le premier nommé.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn administrateurs_des_racines(
        &self,
    ) -> Result<(Vec<Identifiant>, Option<Identifiant>), Faute> {
        let lecture = self.base.begin_read()?;
        vue!(lecture, vue);
        vue.administrateurs_des_racines()
    }

    /// Les groupes vivants de ce domaine, son groupe d'administrateurs
    /// compris, dans l'ordre de leurs identifiants.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn groupes_du_domaine(&self, domaine: Identifiant) -> Result<Vec<GroupeLu>, Faute> {
        let lecture = self.base.begin_read()?;
        vue!(lecture, vue);
        if domaine == domaine_racine() {
            return Ok(vue
                .lire(groupe_des_administrateurs_des_racines())?
                .into_iter()
                .collect());
        }
        let index = lecture.open_table(GROUPES_PAR_RATTACHE)?;
        let (debut, fin) = intervalle(domaine);
        let mut rendus = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, groupe) = entree?;
            if let Some(lu) = vue.lire(depuis_clef(groupe.value())?)? {
                rendus.push(lu);
            }
        }
        Ok(rendus)
    }

    /// Les domaines que ce compte administre sans les posséder : ceux où il
    /// est membre du groupe d'administrateurs. **Le domaine racine y figure**
    /// s'il est l'un des administrateurs des racines.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn domaines_administres(&self, compte: Identifiant) -> Result<Vec<Identifiant>, Faute> {
        let mut rendus = self.administres_par_le_groupe(compte)?;
        // **ET CEUX QU'UN DROIT `administrer` LUI DONNE** (décision 40).
        for (_, droit) in self.droits_recus(compte)? {
            if droit.retire.is_none()
                && droit.droits.croise(asl_registre::Droits::ADMINISTRER)
                && droit.element.genre() == asl_id::Genre::Domaine
                && self
                    .domaine(droit.element)?
                    .is_some_and(|rangee| rangee.proprietaire != compte)
            {
                rendus.push(droit.element);
            }
        }
        rendus.sort();
        rendus.dedup();
        Ok(rendus)
    }

    /// Les domaines que ce compte administre par leur groupe d'administrateurs
    /// sans les posséder, le domaine racine compris.
    fn administres_par_le_groupe(&self, compte: Identifiant) -> Result<Vec<Identifiant>, Faute> {
        let lecture = self.base.begin_read()?;
        vue!(lecture, vue);
        let index = lecture.open_table(ADHESIONS_PAR_COMPTE)?;
        let (debut, fin) = intervalle(compte);
        let mut candidats = Vec::new();
        for entree in index.range(debut.as_slice()..fin.as_slice())? {
            let (_, groupe) = entree?;
            candidats.push(depuis_clef(groupe.value())?);
        }
        candidats.sort();
        candidats.dedup();
        let mut rendus = Vec::new();
        for groupe in candidats {
            if let Some(lu) = vue.lire(groupe)?
                && lu.sorte == SorteDeGroupe::Administrateurs
                && let Some(domaine) = lu.domaine
                && vue.membres(&lu)?.contains(&compte)
                && vue
                    .domaine_vivant(domaine)?
                    .is_none_or(|rangee| rangee.proprietaire != compte)
            {
                rendus.push(domaine);
            }
        }
        rendus.sort();
        Ok(rendus)
    }

    /// Les groupes de ce compte : **ceux dont il est membre** — son groupe
    /// personnel, ceux où un ajout le tient, les groupes d'administrateurs de
    /// ses domaines —, **et ceux des domaines qu'il administre**, membre ou
    /// non. Chacun avec « membre ? ».
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn groupes_du_compte(&self, compte: Identifiant) -> Result<Vec<(GroupeLu, bool)>, Faute> {
        let mut domaines_vus: Vec<Identifiant> = self
            .domaines_de_compte(compte)?
            .into_iter()
            .map(|(domaine, _)| domaine)
            .collect();
        domaines_vus.extend(self.domaines_administres(compte)?);
        let lecture = self.base.begin_read()?;
        vue!(lecture, vue);
        let mut candidats = vec![groupe_personnel(compte)];
        {
            let index = lecture.open_table(ADHESIONS_PAR_COMPTE)?;
            let (debut, fin) = intervalle(compte);
            for entree in index.range(debut.as_slice()..fin.as_slice())? {
                let (_, groupe) = entree?;
                candidats.push(depuis_clef(groupe.value())?);
            }
        }
        {
            let index = lecture.open_table(GROUPES_PAR_RATTACHE)?;
            for domaine in &domaines_vus {
                if *domaine == domaine_racine() {
                    candidats.push(groupe_des_administrateurs_des_racines());
                    continue;
                }
                let (debut, fin) = intervalle(*domaine);
                for entree in index.range(debut.as_slice()..fin.as_slice())? {
                    let (_, groupe) = entree?;
                    candidats.push(depuis_clef(groupe.value())?);
                }
            }
        }
        candidats.sort();
        candidats.dedup();
        let mut rendus = Vec::new();
        for groupe in candidats {
            if let Some(lu) = vue.lire(groupe)? {
                let membre = vue.membres(&lu)?.contains(&compte);
                let visible = membre || lu.domaine.is_some_and(|d| domaines_vus.contains(&d));
                if visible {
                    rendus.push((lu, membre));
                }
            }
        }
        Ok(rendus)
    }

    /// Crée ce groupe dans ce domaine, avec cette étiquette. Rend `false` si
    /// le domaine n'est pas vivant — ou si c'est le domaine racine, qui n'a
    /// que son groupe d'administrateurs. **Les droits se jugent avant.**
    ///
    /// # Errors
    ///
    /// [`Faute::Existe`] si l'identifiant est déjà pris, [`Faute::Base`] ou
    /// [`Faute::Enregistrement`].
    pub fn creer_groupe(
        &self,
        groupe: Identifiant,
        domaine: Identifiant,
        etiquette: NomRange,
    ) -> Result<bool, Faute> {
        let ecriture = self.base.begin_write()?;
        if domaine == domaine_racine()
            || domaines::vivant_dans_l_ecriture(&ecriture, domaine)?.is_none()
        {
            return Ok(false);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        let enregistrement = Groupe {
            provenance: Provenance::Ici,
            estampille,
            sorte: SorteDeGroupe::Domaine,
            rattache: domaine,
            etiquette_estampille: estampille,
            etiquette,
        };
        if !inserer_groupe(&ecriture, groupe, &enregistrement)? {
            return Err(Faute::Existe);
        }
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::Groupe {
                groupe,
                enregistrement,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(true)
    }

    /// Change l'étiquette de ce groupe créé.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn etiqueter_groupe(
        &self,
        groupe: Identifiant,
        etiquette: NomRange,
    ) -> Result<EcritureDeGroupe, Faute> {
        let ecriture = self.base.begin_write()?;
        let lu = {
            vue!(ecriture, vue);
            vue.lire(groupe)?
        };
        let Some(lu) = lu else {
            return Ok(EcritureDeGroupe::Absent);
        };
        if lu.sorte != SorteDeGroupe::Domaine {
            return Ok(EcritureDeGroupe::Protege);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        poser_l_etiquette(&ecriture, groupe, estampille, etiquette)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::GroupeEtiquette { groupe, etiquette },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(EcritureDeGroupe::Faite)
    }

    /// Ajoute ce compte à ce groupe. **Jamais** à un groupe personnel, ni à
    /// celui des administrateurs des racines : celui-ci ne change que par
    /// [`Entrepot::nommer_administrateur_des_racines`].
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn ajouter_membre(
        &self,
        groupe: Identifiant,
        compte: Identifiant,
    ) -> Result<EcritureDeGroupe, Faute> {
        if groupe == groupe_des_administrateurs_des_racines() {
            return Ok(EcritureDeGroupe::Interdit);
        }
        self.ajouter(groupe, compte)
    }

    /// Nomme ce compte administrateur des racines — **sous la clé
    /// d'exploitant**, que l'étage 3 a vérifiée avant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn nommer_administrateur_des_racines(
        &self,
        compte: Identifiant,
    ) -> Result<EcritureDeGroupe, Faute> {
        self.ajouter(groupe_des_administrateurs_des_racines(), compte)
    }

    /// L'ajout, pour l'un ou l'autre chemin.
    fn ajouter(&self, groupe: Identifiant, compte: Identifiant) -> Result<EcritureDeGroupe, Faute> {
        let ecriture = self.base.begin_write()?;
        let juge = {
            vue!(ecriture, vue);
            match vue.lire(groupe)? {
                None => EcritureDeGroupe::Absent,
                Some(lu) if lu.sorte == SorteDeGroupe::Personnel => EcritureDeGroupe::Interdit,
                Some(_) if !vue.compte_vivant(compte)? => EcritureDeGroupe::Absent,
                Some(lu) if vue.membres(&lu)?.contains(&compte) => EcritureDeGroupe::Deja,
                Some(_) => EcritureDeGroupe::Faite,
            }
        };
        if juge != EcritureDeGroupe::Faite {
            return Ok(juge);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        ranger_adhesion(
            &ecriture,
            groupe,
            compte,
            estampille,
            &Adhesion {
                provenance: Provenance::Ici,
                retire: None,
            },
        )?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::GroupeMembre { groupe, compte },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(EcritureDeGroupe::Faite)
    }

    /// Retire ce compte de ce groupe : **chacun de ses ajouts encore vivants**,
    /// nommé par son estampille. Jamais le propriétaire de son groupe
    /// d'administrateurs ; jamais d'un groupe personnel, ni de celui des
    /// administrateurs des racines hors de la clé d'exploitant.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn retirer_membre(
        &self,
        groupe: Identifiant,
        compte: Identifiant,
    ) -> Result<EcritureDeGroupe, Faute> {
        if groupe == groupe_des_administrateurs_des_racines() {
            return Ok(EcritureDeGroupe::Interdit);
        }
        self.retirer(groupe, compte)
    }

    /// Retire ce compte des administrateurs des racines — **sous la clé
    /// d'exploitant**. Retirer est une révocation, et gagne toujours.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn retirer_administrateur_des_racines(
        &self,
        compte: Identifiant,
    ) -> Result<EcritureDeGroupe, Faute> {
        self.retirer(groupe_des_administrateurs_des_racines(), compte)
    }

    /// Le retrait, pour l'un ou l'autre chemin.
    fn retirer(&self, groupe: Identifiant, compte: Identifiant) -> Result<EcritureDeGroupe, Faute> {
        let ecriture = self.base.begin_write()?;
        let (juge, ajouts) = {
            vue!(ecriture, vue);
            match vue.lire(groupe)? {
                None => (EcritureDeGroupe::Absent, Vec::new()),
                Some(lu) if lu.sorte == SorteDeGroupe::Personnel => {
                    (EcritureDeGroupe::Interdit, Vec::new())
                }
                Some(lu) => {
                    let proprietaire = match lu.domaine {
                        Some(domaine) if lu.sorte == SorteDeGroupe::Administrateurs => vue
                            .domaine_vivant(domaine)?
                            .map(|rangee| rangee.proprietaire),
                        _ => None,
                    };
                    if proprietaire == Some(compte) {
                        (EcritureDeGroupe::Protege, Vec::new())
                    } else {
                        let ajouts: Vec<Estampille> = vue
                            .adhesions(groupe)?
                            .into_iter()
                            .filter(|(qui, _, adhesion)| {
                                *qui == compte && adhesion.retire.is_none()
                            })
                            .map(|(_, ajout, _)| ajout)
                            .collect();
                        if ajouts.is_empty() {
                            (EcritureDeGroupe::Absent, ajouts)
                        } else {
                            (EcritureDeGroupe::Faite, ajouts)
                        }
                    }
                }
            }
        };
        if juge != EcritureDeGroupe::Faite {
            return Ok(juge);
        }
        let mut journalisee = None;
        for ajout in ajouts {
            let estampille = estampiller(&ecriture, self.racine)?;
            ranger_adhesion(
                &ecriture,
                groupe,
                compte,
                ajout,
                &Adhesion {
                    provenance: Provenance::Ici,
                    retire: Some(estampille),
                },
            )?;
            journalisee = journaliser_l_operation(
                &ecriture,
                estampille,
                Provenance::Ici,
                &Operation::GroupeMembreRetire {
                    groupe,
                    compte,
                    ajout,
                },
            )?;
        }
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(EcritureDeGroupe::Faite)
    }

    /// Supprime ce groupe créé : sa marque, ses adhésions parties. Jamais un
    /// groupe déduit.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn supprimer_groupe(&self, groupe: Identifiant) -> Result<EcritureDeGroupe, Faute> {
        let ecriture = self.base.begin_write()?;
        let lu = {
            vue!(ecriture, vue);
            vue.lire(groupe)?
        };
        let Some(lu) = lu else {
            return Ok(EcritureDeGroupe::Absent);
        };
        if lu.sorte != SorteDeGroupe::Domaine {
            return Ok(EcritureDeGroupe::Protege);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        marquer(&ecriture, groupe, estampille)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::GroupeSupprime { groupe },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(EcritureDeGroupe::Faite)
    }
}
