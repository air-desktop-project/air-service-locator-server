//! L'inscription des annuaires locaux dans l'entrepôt (`docs/annuaires.md`
//! §2 ter, §4.1 ; `docs/replication.md` décisions 32, 48, 49) : six tables,
//! les écritures locales, les règles d'application, l'instantané, le
//! ré-estampillage.
//!
//! # RIEN NE S'ÉCRIT QUI SOIT UN ÉTAT
//!
//! L'état d'un membre — en attente, accepté, refusé, retiré — et l'hébergeur
//! effectif d'un domaine se LISENT, depuis des faits dont chacun a sa règle
//! (`asl_registre` module `inscription`). C'est la discipline des décisions
//! 42 et 43 : deux racines qui ont reçu les mêmes faits, dans n'importe quel
//! ordre, lisent la même chose, et aucune écriture ne vient « réparer ».
//!
//! # TOUT SE LIT EN ENTIER, ET C'EST UN CHOIX DE TAILLE
//!
//! Ces tables comptent un annuaire par maison qui en déploie un : des
//! dizaines, pas des millions. La lecture les charge toutes en mémoire
//! ([`Registre`]) et raisonne dessus sans index. Le jour où elles grossiront,
//! un index par propriétaire et par clé viendra — la logique, elle, ne
//! changera pas : elle est dans [`Registre`], pure.

use std::collections::BTreeMap;

use asl_id::Identifiant;
use asl_registre::{
    Adresse, Estampille, HEBERGEMENT_OCTETS, Hebergement, INSCRIPTION_OCTETS, Inscription,
    MARQUE_D_INSCRIPTION_OCTETS, MarqueDInscription, Operation, PRESENTATION_OCTETS, Presentation,
    Provenance,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::{
    COMPTES, Entrepot, Faute, Suite, clef, compte_efface_dans, depuis_clef, domaines, estampiller,
    journaliser_l_operation,
};
use asl_registre::Compte;

/// Les déclarations, par l'empreinte de leur code.
pub(crate) const INSCRIPTIONS: TableDefinition<'_, &[u8], &[u8; INSCRIPTION_OCTETS]> =
    TableDefinition::new("inscriptions");

/// Les présentations, par l'empreinte du code présenté.
pub(crate) const PRESENTATIONS: TableDefinition<'_, &[u8], &[u8; PRESENTATION_OCTETS]> =
    TableDefinition::new("presentations");

/// Les acceptations, par membre : la plus petite estampille.
pub(crate) const ACCEPTATIONS: TableDefinition<'_, &[u8], &[u8; MARQUE_D_INSCRIPTION_OCTETS]> =
    TableDefinition::new("inscriptions-acceptees");

/// Les refus, par membre : la plus petite estampille.
pub(crate) const REFUS: TableDefinition<'_, &[u8], &[u8; MARQUE_D_INSCRIPTION_OCTETS]> =
    TableDefinition::new("inscriptions-refusees");

/// Les retraits, par membre : la plus petite estampille.
pub(crate) const RETRAITS: TableDefinition<'_, &[u8], &[u8; MARQUE_D_INSCRIPTION_OCTETS]> =
    TableDefinition::new("inscriptions-retirees");

/// L'hébergement de chaque domaine qui en a eu un : le plus récent.
pub(crate) const HEBERGEMENTS: TableDefinition<'_, &[u8], &[u8; HEBERGEMENT_OCTETS]> =
    TableDefinition::new("hebergements");

/// L'état d'un membre d'annuaire local, tel qu'il se LIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtatDInscription {
    /// Présenté, pas encore tranché.
    EnAttente,
    /// Accepté par un administrateur des racines.
    Acceptee,
    /// Refusé — ou second membre écarté par un plus ancien.
    Refusee,
    /// Retiré, ou son titulaire l'est, ou son propriétaire est effacé.
    Retiree,
}

impl EtatDInscription {
    /// Le mot de la spec (`protocole.md` §2.2).
    #[must_use]
    pub const fn mot(self) -> &'static str {
        match self {
            Self::EnAttente => "en attente",
            Self::Acceptee => "acceptée",
            Self::Refusee => "refusée",
            Self::Retiree => "retirée",
        }
    }
}

/// Un membre d'annuaire local, lu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembreLu {
    /// Son `n-…`.
    pub membre: Identifiant,
    /// L'annuaire : le `n-…` de son titulaire — le sien, s'il l'est.
    pub annuaire: Identifiant,
    /// À qui l'annuaire appartient.
    pub proprietaire: Identifiant,
    /// L'adresse déclarée.
    pub adresse: Adresse,
    /// Sa clé d'identité.
    pub cle: [u8; 32],
    /// Son état.
    pub etat: EtatDInscription,
}

impl MembreLu {
    /// Est-il le titulaire de son annuaire ?
    #[must_use]
    pub fn titulaire(&self) -> bool {
        self.membre == self.annuaire
    }
}

/// Une déclaration dont le code n'a pas encore été présenté.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationAttendue {
    /// Rien pour un annuaire neuf ; le titulaire pour un second membre.
    pub annuaire: Option<Identifiant>,
    /// L'adresse déclarée.
    pub adresse: Adresse,
    /// Jusqu'à quand le code se présente, en millisecondes d'époque.
    pub expire_a: u64,
}

/// Ce que la présentation d'un code a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationDeCode {
    /// Rangée — ou déjà rangée pour cette même clé : le membre, lu.
    Faite(Box<MembreLu>),
    /// Aucun code ne porte cette empreinte.
    Inconnu,
    /// Le code a passé son heure.
    Expire,
    /// Une autre clé l'a déjà présenté, ou cette clé est déjà membre ailleurs.
    Deja,
}

/// Ce que la déclaration d'un annuaire ou d'un second membre a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationDAnnuaire {
    /// Rangée.
    Faite,
    /// Le compte n'est pas vivant, ou l'annuaire nommé n'est pas à lui, ou
    /// pas accepté.
    Inconnu,
    /// L'annuaire a déjà son second membre.
    Complet,
}

/// Ce qu'une décision a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionDInscription {
    /// Écrite.
    Faite,
    /// Aucun membre de ce `n-…`.
    Inconnu,
    /// Accepter un membre refusé ou retiré — `409`.
    Tranchee,
}

// ── Le registre en mémoire ──────────────────────────────────────────────────

/// Toutes les inscriptions, chargées d'une transaction — et la logique qui
/// les lit.
pub(crate) struct Registre {
    /// Les déclarations, par empreinte.
    declarations: BTreeMap<[u8; 32], Inscription>,
    /// Les présentations, par empreinte.
    presentations: BTreeMap<[u8; 32], Presentation>,
    /// Les acceptations, par membre.
    acceptations: BTreeMap<Identifiant, MarqueDInscription>,
    /// Les refus, par membre.
    refus: BTreeMap<Identifiant, MarqueDInscription>,
    /// Les retraits, par membre.
    retraits: BTreeMap<Identifiant, MarqueDInscription>,
    /// Les propriétaires effacés, parmi ceux des déclarations.
    effaces: Vec<Identifiant>,
}

/// Recopie une clé de trente-deux octets.
fn empreinte_de(octets: &[u8]) -> [u8; 32] {
    let mut empreinte = [0_u8; 32];
    for (place, octet) in empreinte.iter_mut().zip(octets) {
        *place = *octet;
    }
    empreinte
}

/// Charge une table de marques.
fn charger_les_marques<T>(table: &T) -> Result<BTreeMap<Identifiant, MarqueDInscription>, Faute>
where
    T: ReadableTable<&'static [u8], &'static [u8; MARQUE_D_INSCRIPTION_OCTETS]>,
{
    let mut marques = BTreeMap::new();
    for entree in table.iter()? {
        let (qui, valeur) = entree?;
        marques.insert(
            depuis_clef(qui.value())?,
            MarqueDInscription::lire(valeur.value())?,
        );
    }
    Ok(marques)
}

impl Registre {
    /// Charge le registre depuis ces tables ; `efface` dit si un compte l'est.
    fn charger<I, P, M>(
        inscriptions: &I,
        presentations: &P,
        acceptations: &M,
        refus: &M,
        retraits: &M,
        efface: impl Fn(Identifiant) -> Result<bool, Faute>,
    ) -> Result<Self, Faute>
    where
        I: ReadableTable<&'static [u8], &'static [u8; INSCRIPTION_OCTETS]>,
        P: ReadableTable<&'static [u8], &'static [u8; PRESENTATION_OCTETS]>,
        M: ReadableTable<&'static [u8], &'static [u8; MARQUE_D_INSCRIPTION_OCTETS]>,
    {
        let mut declarations = BTreeMap::new();
        let mut effaces = Vec::new();
        for entree in inscriptions.iter()? {
            let (empreinte, valeur) = entree?;
            let declaration = Inscription::lire(valeur.value())?;
            if !effaces.contains(&declaration.proprietaire) && efface(declaration.proprietaire)? {
                effaces.push(declaration.proprietaire);
            }
            declarations.insert(empreinte_de(empreinte.value()), declaration);
        }
        let mut lues = BTreeMap::new();
        for entree in presentations.iter()? {
            let (empreinte, valeur) = entree?;
            lues.insert(
                empreinte_de(empreinte.value()),
                Presentation::lire(valeur.value())?,
            );
        }
        Ok(Self {
            declarations,
            presentations: lues,
            acceptations: charger_les_marques(acceptations)?,
            refus: charger_les_marques(refus)?,
            retraits: charger_les_marques(retraits)?,
            effaces,
        })
    }

    /// La déclaration qui a fait de ce `n-…` un membre : parmi les codes que
    /// sa clé a présentés — et gagnés —, celui de la plus ancienne
    /// présentation.
    fn declaration_du_membre(&self, membre: Identifiant) -> Option<(&Inscription, &Presentation)> {
        self.presentations
            .iter()
            .filter(|(_, presentation)| presentation.membre == membre)
            .filter_map(|(empreinte, presentation)| {
                self.declarations
                    .get(empreinte)
                    .map(|declaration| (declaration, presentation))
            })
            .min_by_key(|(_, presentation)| presentation.estampille)
    }

    /// L'état d'un membre sans ce que son titulaire et son rival y ajoutent :
    /// ses propres marques, et son propriétaire.
    fn etat_propre(&self, membre: Identifiant, proprietaire: Identifiant) -> EtatDInscription {
        if self.retraits.contains_key(&membre) || self.effaces.contains(&proprietaire) {
            EtatDInscription::Retiree
        } else if self.refus.contains_key(&membre) {
            EtatDInscription::Refusee
        } else if self.acceptations.contains_key(&membre) {
            EtatDInscription::Acceptee
        } else {
            EtatDInscription::EnAttente
        }
    }

    /// Le second membre effectif de ce titulaire : parmi les seconds qu'aucune
    /// marque n'écarte, celui dont la déclaration est la plus ancienne.
    fn second_effectif(&self, titulaire: Identifiant) -> Option<Identifiant> {
        let mut candidats: Vec<(Estampille, Identifiant)> = Vec::new();
        for presentation in self.presentations.values() {
            if let Some((declaration, gagnante)) = self.declaration_du_membre(presentation.membre)
                && gagnante == presentation
                && declaration.annuaire == Some(titulaire)
                && matches!(
                    self.etat_propre(presentation.membre, declaration.proprietaire),
                    EtatDInscription::EnAttente | EtatDInscription::Acceptee
                )
            {
                candidats.push((declaration.estampille, presentation.membre));
            }
        }
        candidats.into_iter().min().map(|(_, membre)| membre)
    }

    /// Ce membre, lu — ou rien.
    pub(crate) fn membre(&self, membre: Identifiant) -> Option<MembreLu> {
        let (declaration, presentation) = self.declaration_du_membre(membre)?;
        let annuaire = declaration.annuaire.unwrap_or(membre);
        let mut etat = self.etat_propre(membre, declaration.proprietaire);
        if annuaire != membre && etat != EtatDInscription::Retiree {
            // **UN SECOND N'EXISTE QUE PAR SON TITULAIRE** : retiré avec lui
            // — même refusé : le retrait l'emporte sur tout —, et au plus un
            // — le plus ancien — par titulaire (décision 49).
            let titulaire_vivant =
                self.declaration_du_membre(annuaire)
                    .is_some_and(|(sienne, _)| {
                        sienne.annuaire.is_none()
                            && sienne.proprietaire == declaration.proprietaire
                            && self.etat_propre(annuaire, sienne.proprietaire)
                                != EtatDInscription::Retiree
                    });
            if !titulaire_vivant {
                etat = EtatDInscription::Retiree;
            } else if etat != EtatDInscription::Refusee
                && self.second_effectif(annuaire) != Some(membre)
            {
                etat = EtatDInscription::Refusee;
            }
        }
        Some(MembreLu {
            membre,
            annuaire,
            proprietaire: declaration.proprietaire,
            adresse: declaration.adresse,
            cle: presentation.cle,
            etat,
        })
    }

    /// Tous les membres, lus.
    fn membres(&self) -> Vec<MembreLu> {
        let mut vus: Vec<Identifiant> = self
            .presentations
            .values()
            .map(|presentation| presentation.membre)
            .collect();
        vus.sort();
        vus.dedup();
        vus.into_iter()
            .filter_map(|membre| self.membre(membre))
            .collect()
    }

    /// Cet annuaire est-il accepté ? Son titulaire l'est.
    pub(crate) fn accepte(&self, annuaire: Identifiant) -> Option<MembreLu> {
        self.membre(annuaire)
            .filter(|lu| lu.titulaire() && lu.etat == EtatDInscription::Acceptee)
    }
}

/// Charge le registre depuis cette transaction.
macro_rules! registre {
    ($transaction:expr, $efface:expr) => {
        Registre::charger(
            &$transaction.open_table(INSCRIPTIONS)?,
            &$transaction.open_table(PRESENTATIONS)?,
            &$transaction.open_table(ACCEPTATIONS)?,
            &$transaction.open_table(REFUS)?,
            &$transaction.open_table(RETRAITS)?,
            $efface,
        )
    };
}

/// Le registre, dans une transaction d'écriture.
fn registre_dans(ecriture: &WriteTransaction) -> Result<Registre, Faute> {
    registre!(ecriture, |qui| compte_efface_dans(ecriture, qui))
}

/// Pose une marque, si elle manque ou si celle-ci est plus petite.
fn marquer(
    ecriture: &WriteTransaction,
    table: TableDefinition<'_, &[u8], &[u8; MARQUE_D_INSCRIPTION_OCTETS]>,
    membre: Identifiant,
    marque: MarqueDInscription,
) -> Result<(), Faute> {
    let mut ouverte = ecriture.open_table(table)?;
    let avant = match ouverte.get(clef(membre).as_slice())? {
        Some(brut) => Some(MarqueDInscription::lire(brut.value())?),
        None => None,
    };
    if avant.is_some_and(|posee| posee.estampille <= marque.estampille) {
        return Ok(());
    }
    let mut octets = [0_u8; MARQUE_D_INSCRIPTION_OCTETS];
    marque.ecrire(&mut octets);
    ouverte.insert(clef(membre).as_slice(), &octets)?;
    Ok(())
}

/// L'hébergement rangé de ce domaine, s'il en a un.
fn hebergement_dans<T>(table: &T, domaine: Identifiant) -> Result<Option<Hebergement>, Faute>
where
    T: ReadableTable<&'static [u8], &'static [u8; HEBERGEMENT_OCTETS]>,
{
    Ok(match table.get(clef(domaine).as_slice())? {
        Some(brut) => Some(Hebergement::lire(brut.value())?),
        None => None,
    })
}

// ── L'application ───────────────────────────────────────────────────────────

/// `inscription` — insérer si absente.
pub(crate) fn appliquer_inscription(
    ecriture: &WriteTransaction,
    empreinte: &[u8; 32],
    enregistrement: &Inscription,
) -> Result<(), Faute> {
    let mut table = ecriture.open_table(INSCRIPTIONS)?;
    if table.get(empreinte.as_slice())?.is_some() {
        return Ok(());
    }
    let mut octets = [0_u8; INSCRIPTION_OCTETS];
    Inscription {
        provenance: Provenance::Ici,
        ..*enregistrement
    }
    .ecrire(&mut octets);
    table.insert(empreinte.as_slice(), &octets)?;
    Ok(())
}

/// `inscription-presentee` — la plus petite estampille.
pub(crate) fn appliquer_presentation(
    ecriture: &WriteTransaction,
    empreinte: &[u8; 32],
    enregistrement: &Presentation,
) -> Result<(), Faute> {
    let mut table = ecriture.open_table(PRESENTATIONS)?;
    let avant = match table.get(empreinte.as_slice())? {
        Some(brut) => Some(Presentation::lire(brut.value())?),
        None => None,
    };
    if avant.is_some_and(|posee| posee.estampille <= enregistrement.estampille) {
        return Ok(());
    }
    let mut octets = [0_u8; PRESENTATION_OCTETS];
    Presentation {
        provenance: Provenance::Ici,
        ..*enregistrement
    }
    .ecrire(&mut octets);
    table.insert(empreinte.as_slice(), &octets)?;
    Ok(())
}

/// `inscription-decision` — la plus petite estampille de sa sorte.
pub(crate) fn appliquer_decision(
    ecriture: &WriteTransaction,
    membre: Identifiant,
    accepte: bool,
    par: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    let table = if accepte { ACCEPTATIONS } else { REFUS };
    marquer(
        ecriture,
        table,
        membre,
        MarqueDInscription { estampille, par },
    )
}

/// `inscription-retiree` — toujours, la plus petite estampille.
pub(crate) fn appliquer_retrait(
    ecriture: &WriteTransaction,
    membre: Identifiant,
    par: Identifiant,
    estampille: Estampille,
) -> Result<(), Faute> {
    marquer(
        ecriture,
        RETRAITS,
        membre,
        MarqueDInscription { estampille, par },
    )
}

/// `domaine-hebergeur` — le plus récent.
pub(crate) fn appliquer_hebergement(
    ecriture: &WriteTransaction,
    domaine: Identifiant,
    enregistrement: &Hebergement,
) -> Result<(), Faute> {
    let mut table = ecriture.open_table(HEBERGEMENTS)?;
    if hebergement_dans(&table, domaine)?
        .is_some_and(|avant| avant.estampille >= enregistrement.estampille)
    {
        return Ok(());
    }
    let mut octets = [0_u8; HEBERGEMENT_OCTETS];
    Hebergement {
        provenance: Provenance::Ici,
        ..*enregistrement
    }
    .ecrire(&mut octets);
    table.insert(clef(domaine).as_slice(), &octets)?;
    Ok(())
}

// ── La rupture de confiance (C17) ───────────────────────────────────────────

/// Ce qui vient de cet annuaire, dans les tables des inscriptions. **Rien
/// aujourd'hui** : elles ne voyagent qu'entre racines, de provenance locale ;
/// la rupture les regarde quand même, comme celles des domaines.
pub(crate) fn oublier_ce_qui_vient_de(
    ecriture: &WriteTransaction,
    annuaire: Identifiant,
) -> Result<usize, Faute> {
    let mut condamnees = Vec::new();
    for entree in ecriture.open_table(INSCRIPTIONS)?.iter()? {
        let (empreinte, valeur) = entree?;
        if Inscription::lire(valeur.value())?
            .provenance
            .vient_de(annuaire)
        {
            condamnees.push(empreinte.value().to_vec());
        }
    }
    let mut table = ecriture.open_table(INSCRIPTIONS)?;
    for empreinte in &condamnees {
        table.remove(empreinte.as_slice())?;
    }
    let mut combien = condamnees.len();
    let mut condamnees = Vec::new();
    for entree in ecriture.open_table(PRESENTATIONS)?.iter()? {
        let (empreinte, valeur) = entree?;
        if Presentation::lire(valeur.value())?
            .provenance
            .vient_de(annuaire)
        {
            condamnees.push(empreinte.value().to_vec());
        }
    }
    let mut table = ecriture.open_table(PRESENTATIONS)?;
    for empreinte in &condamnees {
        table.remove(empreinte.as_slice())?;
    }
    combien = combien.saturating_add(condamnees.len());
    let mut condamnes = Vec::new();
    for entree in ecriture.open_table(HEBERGEMENTS)?.iter()? {
        let (domaine, valeur) = entree?;
        if Hebergement::lire(valeur.value())?
            .provenance
            .vient_de(annuaire)
        {
            condamnes.push(domaine.value().to_vec());
        }
    }
    let mut table = ecriture.open_table(HEBERGEMENTS)?;
    for domaine in &condamnes {
        table.remove(domaine.as_slice())?;
    }
    Ok(combien.saturating_add(condamnes.len()))
}

// ── L'instantané ────────────────────────────────────────────────────────────

/// Ce que les inscriptions ajoutent à un instantané : chaque fait, sous son
/// estampille.
pub(crate) fn instantane_des_inscriptions(
    lecture: &redb::ReadTransaction,
    suite: &mut Suite,
) -> Result<(), Faute> {
    for entree in lecture.open_table(INSCRIPTIONS)?.iter()? {
        let (empreinte, valeur) = entree?;
        let declaration = Inscription::lire(valeur.value())?;
        suite.ajouter(
            declaration.estampille,
            &Operation::Inscription {
                empreinte: empreinte_de(empreinte.value()),
                enregistrement: declaration,
            },
        );
    }
    for entree in lecture.open_table(PRESENTATIONS)?.iter()? {
        let (empreinte, valeur) = entree?;
        let presentation = Presentation::lire(valeur.value())?;
        suite.ajouter(
            presentation.estampille,
            &Operation::InscriptionPresentee {
                empreinte: empreinte_de(empreinte.value()),
                enregistrement: presentation,
            },
        );
    }
    for (table, accepte) in [(ACCEPTATIONS, true), (REFUS, false)] {
        for (membre, marque) in charger_les_marques(&lecture.open_table(table)?)? {
            suite.ajouter(
                marque.estampille,
                &Operation::InscriptionDecision {
                    membre,
                    accepte,
                    par: marque.par,
                },
            );
        }
    }
    for (membre, marque) in charger_les_marques(&lecture.open_table(RETRAITS)?)? {
        suite.ajouter(
            marque.estampille,
            &Operation::InscriptionRetiree {
                membre,
                par: marque.par,
            },
        );
    }
    for entree in lecture.open_table(HEBERGEMENTS)?.iter()? {
        let (domaine, valeur) = entree?;
        let hebergement = Hebergement::lire(valeur.value())?;
        suite.ajouter(
            hebergement.estampille,
            &Operation::DomaineHebergeur {
                domaine: depuis_clef(domaine.value())?,
                enregistrement: hebergement,
            },
        );
    }
    Ok(())
}

// ── Les verbes de l'entrepôt ────────────────────────────────────────────────

impl Entrepot {
    /// Déclare un annuaire local neuf (`annuaire: None`) ou le second membre
    /// de celui-ci, pour ce compte, et range le code sous son empreinte.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn declarer_annuaire(
        &self,
        proprietaire: Identifiant,
        annuaire: Option<Identifiant>,
        adresse: Adresse,
        empreinte: [u8; 32],
        expire_a: u64,
    ) -> Result<DeclarationDAnnuaire, Faute> {
        let ecriture = self.base.begin_write()?;
        if crate::compte_dans(&ecriture, proprietaire)?.is_none_or(|compte| compte.est_efface()) {
            return Ok(DeclarationDAnnuaire::Inconnu);
        }
        if let Some(titulaire) = annuaire {
            let registre = registre_dans(&ecriture)?;
            let Some(lu) = registre.accepte(titulaire) else {
                return Ok(DeclarationDAnnuaire::Inconnu);
            };
            if lu.proprietaire != proprietaire {
                return Ok(DeclarationDAnnuaire::Inconnu);
            }
            if registre.second_effectif(titulaire).is_some() {
                return Ok(DeclarationDAnnuaire::Complet);
            }
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        let declaration = Inscription {
            provenance: Provenance::Ici,
            estampille,
            proprietaire,
            annuaire,
            expire_a,
            adresse,
        };
        appliquer_inscription(&ecriture, &empreinte, &declaration)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::Inscription {
                empreinte,
                enregistrement: declaration,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(DeclarationDAnnuaire::Faite)
    }

    /// Un annuaire présente ce code avec cette clé, dont `membre` est le
    /// `n-…`. **Présenter deux fois le même code avec la même clé rend l'état,
    /// sans rien écrire** — c'est ainsi qu'un annuaire relit le sien.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn presenter_un_code(
        &self,
        empreinte: [u8; 32],
        membre: Identifiant,
        cle: [u8; 32],
        maintenant_ms: u64,
    ) -> Result<PresentationDeCode, Faute> {
        let ecriture = self.base.begin_write()?;
        let registre = registre_dans(&ecriture)?;
        let Some(declaration) = registre.declarations.get(&empreinte).copied() else {
            return Ok(PresentationDeCode::Inconnu);
        };
        if let Some(posee) = registre.presentations.get(&empreinte) {
            return Ok(if posee.membre == membre {
                registre
                    .membre(membre)
                    .map_or(PresentationDeCode::Deja, |lu| {
                        PresentationDeCode::Faite(Box::new(lu))
                    })
            } else {
                PresentationDeCode::Deja
            });
        }
        if declaration.expire_a < maintenant_ms {
            return Ok(PresentationDeCode::Expire);
        }
        // **UNE CLÉ, UN MEMBRE** : une clé déjà membre d'un annuaire — qui ne
        // s'en est pas retirée — ne devient pas le membre d'un autre.
        if registre
            .membre(membre)
            .is_some_and(|lu| lu.etat != EtatDInscription::Retiree)
        {
            return Ok(PresentationDeCode::Deja);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        let presentation = Presentation {
            provenance: Provenance::Ici,
            estampille,
            membre,
            cle,
        };
        appliquer_presentation(&ecriture, &empreinte, &presentation)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::InscriptionPresentee {
                empreinte,
                enregistrement: presentation,
            },
        )?;
        let lu = registre_dans(&ecriture)?.membre(membre);
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(lu.map_or(PresentationDeCode::Deja, |lu| {
            PresentationDeCode::Faite(Box::new(lu))
        }))
    }

    /// Accepte ou refuse ce membre. **Les droits se jugent avant** : l'entrepôt
    /// ne sait pas qui administre les racines.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn decider_d_une_inscription(
        &self,
        membre: Identifiant,
        accepte: bool,
        par: Identifiant,
    ) -> Result<DecisionDInscription, Faute> {
        let ecriture = self.base.begin_write()?;
        let Some(lu) = registre_dans(&ecriture)?.membre(membre) else {
            return Ok(DecisionDInscription::Inconnu);
        };
        if accepte
            && matches!(
                lu.etat,
                EtatDInscription::Refusee | EtatDInscription::Retiree
            )
        {
            return Ok(DecisionDInscription::Tranchee);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        appliquer_decision(&ecriture, membre, accepte, par, estampille)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::InscriptionDecision {
                membre,
                accepte,
                par,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(DecisionDInscription::Faite)
    }

    /// Retire ce membre — le titulaire retire l'annuaire entier. Rend `false`
    /// s'il est inconnu. **Les droits se jugent avant.**
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn retirer_un_membre(&self, membre: Identifiant, par: Identifiant) -> Result<bool, Faute> {
        let ecriture = self.base.begin_write()?;
        if registre_dans(&ecriture)?.membre(membre).is_none() {
            return Ok(false);
        }
        let estampille = estampiller(&ecriture, self.racine)?;
        appliquer_retrait(&ecriture, membre, par, estampille)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::InscriptionRetiree { membre, par },
        )?;
        self.commettre_une_operation(ecriture, journalisee)?;
        Ok(true)
    }

    /// Confie ce domaine à cet annuaire, ou le rend aux racines avec `None`.
    /// **Les droits se jugent avant** — le propriétaire, un annuaire accepté
    /// à lui : voir [`Entrepot::hebergeur_de_domaine`].
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn confier_domaine(
        &self,
        domaine: Identifiant,
        annuaire: Option<Identifiant>,
    ) -> Result<(), Faute> {
        let ecriture = self.base.begin_write()?;
        let estampille = estampiller(&ecriture, self.racine)?;
        let hebergement = Hebergement {
            provenance: Provenance::Ici,
            estampille,
            annuaire,
        };
        appliquer_hebergement(&ecriture, domaine, &hebergement)?;
        let journalisee = journaliser_l_operation(
            &ecriture,
            estampille,
            Provenance::Ici,
            &Operation::DomaineHebergeur {
                domaine,
                enregistrement: hebergement,
            },
        )?;
        self.commettre_une_operation(ecriture, journalisee)
    }

    /// L'annuaire qui héberge EFFECTIVEMENT ce domaine — ou rien : les
    /// racines. **Il ne vaut que si l'annuaire nommé est accepté et appartient
    /// au propriétaire du domaine vivant** (décision 48) : sinon, le domaine se
    /// lit aux racines, sans que rien ne se réécrive.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn hebergeur_de_domaine(&self, domaine: Identifiant) -> Result<Option<Identifiant>, Faute> {
        let lecture = self.base.begin_read()?;
        let Some(rangee) = ({
            let index = lecture.open_table(domaines::DOMAINES_PAR_COMPTE)?;
            let tables = lecture.open_table(domaines::DOMAINES)?;
            domaines::vivant_dans(&index, &tables, domaine)?
        }) else {
            return Ok(None);
        };
        let Some(voulu) = hebergement_dans(&lecture.open_table(HEBERGEMENTS)?, domaine)?
            .and_then(|hebergement| hebergement.annuaire)
        else {
            return Ok(None);
        };
        let registre = self.registre_lu(&lecture)?;
        Ok(registre
            .accepte(voulu)
            .filter(|lu| lu.proprietaire == rangee.proprietaire)
            .map(|lu| lu.annuaire))
    }

    /// Le registre, dans une transaction de lecture.
    fn registre_lu(&self, lecture: &redb::ReadTransaction) -> Result<Registre, Faute> {
        let comptes = lecture.open_table(COMPTES)?;
        registre!(lecture, |qui: Identifiant| {
            Ok(match comptes.get(clef(qui).as_slice())? {
                Some(brut) => Compte::lire(brut.value())?.est_efface(),
                None => false,
            })
        })
    }

    /// Ce membre, lu — ou rien.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn membre_d_annuaire(&self, membre: Identifiant) -> Result<Option<MembreLu>, Faute> {
        let lecture = self.base.begin_read()?;
        Ok(self.registre_lu(&lecture)?.membre(membre))
    }

    /// Les annuaires de ce compte — chaque membre lu — et ses déclarations
    /// dont le code attend encore, non expirées.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn annuaires_du_compte(
        &self,
        proprietaire: Identifiant,
        maintenant_ms: u64,
    ) -> Result<(Vec<MembreLu>, Vec<DeclarationAttendue>), Faute> {
        let lecture = self.base.begin_read()?;
        let registre = self.registre_lu(&lecture)?;
        let membres = registre
            .membres()
            .into_iter()
            .filter(|lu| lu.proprietaire == proprietaire)
            .collect();
        let attendues = registre
            .declarations
            .iter()
            .filter(|(empreinte, declaration)| {
                declaration.proprietaire == proprietaire
                    && declaration.expire_a >= maintenant_ms
                    && !registre.presentations.contains_key(*empreinte)
            })
            .map(|(_, declaration)| DeclarationAttendue {
                annuaire: declaration.annuaire,
                adresse: declaration.adresse,
                expire_a: declaration.expire_a,
            })
            .collect();
        Ok((membres, attendues))
    }

    /// Les membres en attente d'une décision, pour les administrateurs des
    /// racines.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn inscriptions_en_attente(&self) -> Result<Vec<MembreLu>, Faute> {
        let lecture = self.base.begin_read()?;
        Ok(self
            .registre_lu(&lecture)?
            .membres()
            .into_iter()
            .filter(|lu| lu.etat == EtatDInscription::EnAttente)
            .collect())
    }
}
