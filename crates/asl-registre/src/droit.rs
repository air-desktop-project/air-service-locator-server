//! Les droits (`docs/modele.md` §2.13, `docs/replication.md` décisions 40 et
//! 41) : ce qu'un GROUPE reçoit sur un élément — un domaine, une machine, un
//! service, ou, pour les seules autorisations converties, un compte.
//!
//! # CE QUI REMPLACE L'AUTORISATION, ET CE QUI EN RESTE
//!
//! L'autorisation d'hier était une arête d'un compte vers un compte
//! ([`crate::Autorisation`]). **Elle devient un droit `voir` + `localiser`
//! accordé au groupe personnel du bénéficiaire, sous le même `g-…`** — c'est
//! [`Droit::depuis_autorisation`], une fonction des seuls octets de
//! l'autorisation, que les deux racines calculent chacune de son côté et au
//! même résultat. L'inverse, [`Droit::en_autorisation`], dit un droit dans la
//! forme d'hier quand il s'y laisse dire : c'est ce que les verbes de
//! compatibilité rendent aux applications déployées.
//!
//! # LE RETRAIT PORTE SON ESTAMPILLE, À CÔTÉ DE L'OCTROI
//!
//! Comme l'adhésion (`groupe.rs`) : **deux retraits du même droit gardent la
//! plus petite estampille**, et l'octroi garde la sienne. Réécrire l'estampille
//! de l'octroi au retrait — ce que faisait l'autorisation — rendrait le retrait
//! plus récent que lui-même selon l'ordre d'arrivée.

use asl_id::{Genre, Identifiant};

use crate::{
    Autorisation, ESTAMPILLE_OCTETS, Estampille, Faute, IDENTIFIANT_OCTETS, NOM_OCTETS_MAX,
    NomRange, PROVENANCE_OCTETS, Portee, Provenance, bourrage_nul, ecrire_identifiant,
    groupe_personnel, lire_identifiant, poser_un,
};

// ── Les quatre droits ───────────────────────────────────────────────────────

/// Un ensemble de droits, parmi `administrer`, `rattacher`, `voir`,
/// `localiser` (`docs/modele.md` §2.13).
///
/// **Un ensemble, et non une énumération** : un droit accordé en porte un ou
/// plusieurs, et ce qu'un compte peut sur un élément est la RÉUNION de tout ce
/// que ses groupes ont reçu (décision 40) — une réunion d'ensembles de bits,
/// qui ne dépend d'aucun ordre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Droits(u8);

/// Les noms, dans l'ordre où le fil les écrit — celui de la spec.
const NOMS: [&str; 4] = ["administrer", "rattacher", "voir", "localiser"];

/// Chaque sous-ensemble, nommé dans cet ordre. Seize entrées, une par valeur
/// de quatre bits : un tableau lu par son index ne peut pas mal ordonner.
const LISTES: [&[&str]; 16] = [
    &[],
    &["administrer"],
    &["rattacher"],
    &["administrer", "rattacher"],
    &["voir"],
    &["administrer", "voir"],
    &["rattacher", "voir"],
    &["administrer", "rattacher", "voir"],
    &["localiser"],
    &["administrer", "localiser"],
    &["rattacher", "localiser"],
    &["administrer", "rattacher", "localiser"],
    &["voir", "localiser"],
    &["administrer", "voir", "localiser"],
    &["rattacher", "voir", "localiser"],
    &["administrer", "rattacher", "voir", "localiser"],
];

impl Droits {
    /// Aucun droit.
    pub const AUCUN: Self = Self(0);
    /// Gérer le domaine : son alias, ses groupes, les droits accordés sur lui.
    /// **Emporte `voir`.**
    pub const ADMINISTRER: Self = Self(0b0001);
    /// Ranger SES PROPRES machines dans le domaine.
    pub const RATTACHER: Self = Self(0b0010);
    /// Lister machines et services — pas leurs adresses.
    pub const VOIR: Self = Self(0b0100);
    /// Obtenir l'adresse et le port d'un service. **Emporte `voir`.**
    pub const LOCALISER: Self = Self(0b1000);
    /// Les quatre.
    pub const TOUS: Self = Self(0b1111);
    /// Ce qu'une autorisation d'hier donnait, et ce que sa conversion garde.
    pub const D_UNE_AUTORISATION: Self = Self(0b1100);

    /// L'octet rangé.
    #[must_use]
    pub const fn octet(self) -> u8 {
        self.0
    }

    /// Relit un octet rangé.
    ///
    /// # Errors
    ///
    /// [`Faute::Etiquette`] si un bit ne désigne aucun droit.
    pub const fn depuis(octet: u8) -> Result<Self, Faute> {
        if octet & !Self::TOUS.0 != 0 {
            return Err(Faute::Etiquette { lue: octet });
        }
        Ok(Self(octet))
    }

    /// La réunion des deux.
    #[must_use]
    pub const fn union(self, autre: Self) -> Self {
        Self(self.0 | autre.0)
    }

    /// Porte-t-il tous ceux-là ?
    #[must_use]
    pub const fn contient(self, autre: Self) -> bool {
        self.0 & autre.0 == autre.0
    }

    /// Porte-t-il au moins un de ceux-là ?
    #[must_use]
    pub const fn croise(self, autre: Self) -> bool {
        self.0 & autre.0 != 0
    }

    /// Aucun ?
    #[must_use]
    pub const fn est_vide(self) -> bool {
        self.0 == 0
    }

    /// Ces droits permettent-ils de VOIR ? `voir`, et ce qui l'emporte :
    /// `localiser` et `administrer`.
    #[must_use]
    pub const fn permettent_de_voir(self) -> bool {
        self.croise(Self(Self::VOIR.0 | Self::LOCALISER.0 | Self::ADMINISTRER.0))
    }

    /// Ces droits permettent-ils de LOCALISER ?
    #[must_use]
    pub const fn permettent_de_localiser(self) -> bool {
        self.croise(Self::LOCALISER)
    }

    /// Le droit qui porte ce nom — un seul, et exact.
    #[must_use]
    pub fn depuis_nom(nom: &str) -> Option<Self> {
        let rang = NOMS.iter().position(|connu| *connu == nom)?;
        Some(Self(1_u8 << rang))
    }

    /// Leurs noms, dans l'ordre du fil.
    #[must_use]
    pub fn noms(self) -> &'static [&'static str] {
        LISTES
            .get(usize::from(self.0 & Self::TOUS.0))
            .copied()
            .unwrap_or_default()
    }

    /// Ont-ils un sens sur un élément de ce genre ?
    ///
    /// **`administrer` et `rattacher` ne se posent que sur un domaine** — on
    /// ne range pas une machine dans une machine. `voir` et `localiser` se
    /// posent sur un domaine, une machine, un service, et sur un compte pour
    /// les seules autorisations converties. Aucun genre d'autre élément.
    #[must_use]
    pub const fn ont_un_sens_sur(self, genre: Genre) -> bool {
        if self.est_vide() {
            return false;
        }
        match genre {
            Genre::Domaine => true,
            Genre::Machine | Genre::Service | Genre::Utilisateur => {
                !self.croise(Self(Self::ADMINISTRER.0 | Self::RATTACHER.0))
            }
            _ => false,
        }
    }
}

// ── L'élément ───────────────────────────────────────────────────────────────

/// Relit un élément : **un compte, un domaine, une machine ou un service**, et
/// rien d'autre. Le genre est lu, pas deviné — l'octet exact de son préfixe,
/// pour la raison écrite sur `lire_identifiant`.
fn lire_element(octets: &[u8]) -> Result<Identifiant, Faute> {
    let genre = match octets.first().copied().unwrap_or(0) {
        b'u' => Genre::Utilisateur,
        b'd' => Genre::Domaine,
        b'm' => Genre::Machine,
        b's' => Genre::Service,
        lue => return Err(Faute::Etiquette { lue }),
    };
    lire_identifiant(octets, genre)
}

// ── Le droit ────────────────────────────────────────────────────────────────

/// Ce qu'un droit occupe : la provenance, l'octroi, celui qui accorde, le
/// groupe, l'élément, l'ensemble des droits, le retrait (un drapeau et son
/// estampille), l'étiquette.
pub const DROIT_OCTETS: usize = PROVENANCE_OCTETS
    + ESTAMPILLE_OCTETS
    + IDENTIFIANT_OCTETS
    + IDENTIFIANT_OCTETS
    + IDENTIFIANT_OCTETS
    + 1
    + 1
    + ESTAMPILLE_OCTETS
    + 1
    + NOM_OCTETS_MAX;

/// Un droit accordé à un groupe sur un élément (`docs/modele.md` §2.13).
///
/// # RETIRÉ, JAMAIS EFFACÉ
///
/// Pour la raison de l'autorisation : **l'utilisateur doit voir ce qu'il a
/// retiré**. Un droit retiré reste, marqué, et n'ouvre plus rien.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Droit {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// L'octroi.
    pub estampille: Estampille,
    /// Le compte qui l'a accordé.
    pub par: Identifiant,
    /// Le groupe qui le reçoit — jamais un compte seul.
    pub groupe: Identifiant,
    /// Ce sur quoi il porte : `u-…`, `d-…`, `m-…` ou `s-…`.
    pub element: Identifiant,
    /// Ce qu'il permet — non vide, et sensé sur l'élément.
    pub droits: Droits,
    /// Son retrait, ou rien : il vaut.
    pub retire: Option<Estampille>,
    /// Le libellé que son auteur lui a donné — pour l'humain, comme celui de
    /// l'autorisation.
    pub etiquette: NomRange,
}

impl Droit {
    /// Écrit ce droit.
    pub fn ecrire(&self, sortie: &mut [u8; DROIT_OCTETS]) {
        sortie.fill(0);
        let mut curseur = 0_usize;
        let mut tranche = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        self.provenance.ecrire(
            sortie
                .get_mut(tranche(PROVENANCE_OCTETS))
                .unwrap_or_default(),
        );
        self.estampille.ecrire(
            sortie
                .get_mut(tranche(ESTAMPILLE_OCTETS))
                .unwrap_or_default(),
        );
        ecrire_identifiant(
            self.par,
            sortie
                .get_mut(tranche(IDENTIFIANT_OCTETS))
                .unwrap_or_default(),
        );
        ecrire_identifiant(
            self.groupe,
            sortie
                .get_mut(tranche(IDENTIFIANT_OCTETS))
                .unwrap_or_default(),
        );
        ecrire_identifiant(
            self.element,
            sortie
                .get_mut(tranche(IDENTIFIANT_OCTETS))
                .unwrap_or_default(),
        );
        poser_un(
            sortie.get_mut(tranche(1)).unwrap_or_default(),
            self.droits.octet(),
        );
        let retrait = tranche(1 + ESTAMPILLE_OCTETS);
        if let Some(quand) = self.retire {
            let place = sortie.get_mut(retrait).unwrap_or_default();
            poser_un(place, 1);
            quand.ecrire(place.get_mut(1..).unwrap_or_default());
        }
        self.etiquette.ecrire(
            sortie
                .get_mut(tranche(1 + NOM_OCTETS_MAX))
                .unwrap_or_default(),
        );
    }

    /// Relit un droit.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un droit — un ensemble vide, ou
    /// sans sens sur son élément, compris.
    pub fn lire(octets: &[u8; DROIT_OCTETS]) -> Result<Self, Faute> {
        let mut curseur = 0_usize;
        let mut prendre = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            octets.get(debut..curseur).unwrap_or_default()
        };
        let provenance = Provenance::lire(prendre(PROVENANCE_OCTETS))?;
        let estampille = Estampille::lire(prendre(ESTAMPILLE_OCTETS))?;
        let par = lire_identifiant(prendre(IDENTIFIANT_OCTETS), Genre::Utilisateur)?;
        let groupe = lire_identifiant(prendre(IDENTIFIANT_OCTETS), Genre::Ensemble)?;
        let element = lire_element(prendre(IDENTIFIANT_OCTETS))?;
        let octet = prendre(1).first().copied().unwrap_or(0);
        let droits = Droits::depuis(octet)?;
        if !droits.ont_un_sens_sur(element.genre()) {
            return Err(Faute::Etiquette { lue: octet });
        }
        let retrait = prendre(1 + ESTAMPILLE_OCTETS);
        let retire = match retrait.first().copied().unwrap_or(0) {
            0 => {
                if !bourrage_nul(retrait.get(1..).unwrap_or_default()) {
                    return Err(Faute::Bourrage);
                }
                None
            }
            1 => Some(Estampille::lire(retrait.get(1..).unwrap_or_default())?),
            lue => return Err(Faute::Etiquette { lue }),
        };
        let etiquette = NomRange::lire(prendre(1 + NOM_OCTETS_MAX))?;
        Ok(Self {
            provenance,
            estampille,
            par,
            groupe,
            element,
            droits,
            retire,
            etiquette,
        })
    }

    /// **L'autorisation d'hier, convertie** (`docs/modele.md` §2.13) : le même
    /// donneur, le groupe personnel du bénéficiaire, l'élément que nommait la
    /// portée — le compte du donneur pour « tout mon compte » —, `voir` et
    /// `localiser`, l'étiquette, et le retrait si elle était révoquée.
    ///
    /// **Une fonction des seuls octets de l'autorisation** : les deux racines
    /// la calculent chacune de son côté, sans rien échanger, et arrivent au
    /// même droit. Une autorisation révoquée portait l'estampille de sa
    /// révocation, la plus récente écriture qu'elle ait connue : c'est elle
    /// qui date l'octroi et le retrait, faute de mieux — elles ne se
    /// distinguaient plus.
    #[must_use]
    pub fn depuis_autorisation(autorisation: &Autorisation) -> Self {
        Self {
            provenance: autorisation.provenance,
            estampille: autorisation.estampille,
            par: autorisation.par,
            groupe: groupe_personnel(autorisation.a),
            element: match autorisation.portee {
                Portee::ToutLeCompte => autorisation.par,
                Portee::UneMachine(quoi) | Portee::UnService(quoi) => quoi,
            },
            droits: Droits::D_UNE_AUTORISATION,
            retire: autorisation.revoquee.then_some(autorisation.estampille),
            etiquette: autorisation.etiquette,
        }
    }

    /// **Ce droit dit dans la forme d'hier**, avec ce compte pour
    /// bénéficiaire — ou rien, s'il ne s'y laisse pas dire.
    ///
    /// Il s'y laisse dire s'il permet de LOCALISER (sans quoi ce n'était pas
    /// une autorisation) et s'il porte sur ce qu'une portée savait nommer : un
    /// compte (« tout »), une machine, un service. Un droit sur un domaine n'a
    /// pas de forme d'hier.
    #[must_use]
    pub fn en_autorisation(&self, a: Identifiant) -> Option<Autorisation> {
        if !self.droits.permettent_de_localiser() {
            return None;
        }
        let portee = match self.element.genre() {
            Genre::Utilisateur => Portee::ToutLeCompte,
            Genre::Machine => Portee::UneMachine(self.element),
            Genre::Service => Portee::UnService(self.element),
            _ => return None,
        };
        Some(Autorisation {
            provenance: self.provenance,
            estampille: self
                .retire
                .map_or(self.estampille, |quand| quand.max(self.estampille)),
            par: self.par,
            a,
            portee,
            revoquee: self.retire.is_some(),
            etiquette: self.etiquette,
        })
    }
}

#[cfg(test)]
mod tests {
    use asl_id::{Genre, Identifiant};

    use super::{DROIT_OCTETS, Droit, Droits, IDENTIFIANT_OCTETS, NOMS, PROVENANCE_OCTETS};
    use crate::{
        Autorisation, ESTAMPILLE_OCTETS, Estampille, Faute, NomRange, Portee, Provenance,
        groupe_personnel,
    };

    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    fn e(compteur: u64) -> Estampille {
        Estampille {
            compteur,
            racine: un(Genre::Annuaire, 0xEE),
        }
    }

    fn un_droit(element: Identifiant, droits: Droits, retire: Option<Estampille>) -> Droit {
        Droit {
            provenance: Provenance::Ici,
            estampille: e(4),
            par: un(Genre::Utilisateur, 1),
            groupe: un(Genre::Ensemble, 2),
            element,
            droits,
            retire,
            etiquette: NomRange::nouveau("accès NAS").unwrap(),
        }
    }

    fn aller_retour(droit: &Droit) -> Droit {
        let mut octets = [0_u8; DROIT_OCTETS];
        droit.ecrire(&mut octets);
        Droit::lire(&octets).unwrap()
    }

    #[test]
    fn les_droits_se_nomment_se_reunissent_et_se_relisent() {
        for (rang, nom) in NOMS.iter().enumerate() {
            let seul = Droits::depuis_nom(nom).unwrap();
            assert_eq!(seul.octet(), 1 << rang);
            assert_eq!(seul.noms(), &[*nom]);
        }
        assert_eq!(Droits::depuis_nom("lire"), None);
        assert_eq!(Droits::depuis_nom("Voir"), None);
        assert_eq!(Droits::TOUS.noms(), &NOMS);
        assert!(Droits::AUCUN.noms().is_empty());
        assert!(Droits::AUCUN.est_vide());
        let deux = Droits::VOIR.union(Droits::LOCALISER);
        assert_eq!(deux, Droits::D_UNE_AUTORISATION);
        assert_eq!(deux.noms(), &["voir", "localiser"]);
        assert!(deux.contient(Droits::VOIR));
        assert!(!deux.contient(Droits::ADMINISTRER));
        assert!(deux.croise(Droits::LOCALISER));
        assert!(!deux.croise(Droits::RATTACHER));
        // Chaque valeur de quatre bits se nomme, et se relit par ses noms.
        for octet in 0_u8..16 {
            let droits = Droits::depuis(octet).unwrap();
            let refaits = droits.noms().iter().fold(Droits::AUCUN, |tous, nom| {
                tous.union(Droits::depuis_nom(nom).unwrap())
            });
            assert_eq!(refaits, droits);
        }
        assert_eq!(Droits::depuis(0x10), Err(Faute::Etiquette { lue: 0x10 }));
    }

    #[test]
    fn voir_et_localiser_se_deduisent_de_ce_qui_les_emporte() {
        assert!(Droits::VOIR.permettent_de_voir());
        assert!(Droits::LOCALISER.permettent_de_voir());
        assert!(Droits::ADMINISTRER.permettent_de_voir());
        assert!(!Droits::RATTACHER.permettent_de_voir());
        assert!(!Droits::AUCUN.permettent_de_voir());
        assert!(Droits::LOCALISER.permettent_de_localiser());
        assert!(!Droits::VOIR.permettent_de_localiser());
        assert!(!Droits::ADMINISTRER.permettent_de_localiser());
    }

    #[test]
    fn administrer_et_rattacher_ne_se_posent_que_sur_un_domaine() {
        for genre in [Genre::Machine, Genre::Service, Genre::Utilisateur] {
            assert!(Droits::VOIR.ont_un_sens_sur(genre));
            assert!(Droits::D_UNE_AUTORISATION.ont_un_sens_sur(genre));
            assert!(!Droits::ADMINISTRER.ont_un_sens_sur(genre));
            assert!(!Droits::RATTACHER.union(Droits::VOIR).ont_un_sens_sur(genre));
        }
        assert!(Droits::TOUS.ont_un_sens_sur(Genre::Domaine));
        assert!(!Droits::AUCUN.ont_un_sens_sur(Genre::Domaine));
        for genre in [
            Genre::Appareil,
            Genre::Autorisation,
            Genre::Annuaire,
            Genre::Ensemble,
        ] {
            assert!(!Droits::VOIR.ont_un_sens_sur(genre));
        }
    }

    #[test]
    fn un_droit_fait_l_aller_retour_sur_chaque_element() {
        for (element, droits) in [
            (un(Genre::Domaine, 5), Droits::TOUS),
            (un(Genre::Machine, 5), Droits::LOCALISER),
            (un(Genre::Service, 5), Droits::VOIR),
            (un(Genre::Utilisateur, 5), Droits::D_UNE_AUTORISATION),
        ] {
            for retire in [None, Some(e(9))] {
                let droit = un_droit(element, droits, retire);
                assert_eq!(aller_retour(&droit), droit);
            }
        }
    }

    /// Le décalage de l'octet des droits, puis celui du retrait.
    const DROITS_EN: usize = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS + 3 * IDENTIFIANT_OCTETS;

    #[test]
    fn un_droit_corrompu_se_denonce() {
        let droit = un_droit(un(Genre::Machine, 5), Droits::VOIR, Some(e(9)));
        let mut octets = [0_u8; DROIT_OCTETS];
        droit.ecrire(&mut octets);

        // Une provenance, une estampille, un donneur qui n'en sont pas.
        let mut autre = octets;
        autre[0] = 9;
        assert_eq!(Droit::lire(&autre), Err(Faute::Etiquette { lue: 9 }));
        let mut autre = octets;
        autre[PROVENANCE_OCTETS + 8] = b'u';
        assert_eq!(
            Droit::lire(&autre),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
        let mut autre = octets;
        autre[PROVENANCE_OCTETS + ESTAMPILLE_OCTETS] = b'e';
        assert_eq!(
            Droit::lire(&autre),
            Err(Faute::Genre {
                attendu: Genre::Utilisateur
            })
        );
        // Une estampille de retrait qui n'en est pas une, une étiquette trop
        // longue pour sa place.
        let mut autre = octets;
        autre[DROITS_EN + 2 + 8] = b'u';
        assert_eq!(
            Droit::lire(&autre),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
        let mut autre = octets;
        autre[DROITS_EN + 2 + ESTAMPILLE_OCTETS] = 0xFF;
        assert!(Droit::lire(&autre).is_err());
        // Un élément d'un genre qui n'en est pas un.
        let mut autre = octets;
        autre[DROITS_EN - IDENTIFIANT_OCTETS] = b'a';
        assert_eq!(Droit::lire(&autre), Err(Faute::Etiquette { lue: b'a' }));
        // Un groupe qui n'est pas un groupe.
        let mut autre = octets;
        autre[DROITS_EN - 2 * IDENTIFIANT_OCTETS] = b'u';
        assert_eq!(
            Droit::lire(&autre),
            Err(Faute::Genre {
                attendu: Genre::Ensemble
            })
        );
        // Un bit qui ne désigne aucun droit, un ensemble vide, un droit sans
        // sens sur son élément.
        for lue in [0x20, 0, Droits::ADMINISTRER.octet()] {
            let mut autre = octets;
            autre[DROITS_EN] = lue;
            assert_eq!(Droit::lire(&autre), Err(Faute::Etiquette { lue }));
        }
        // Une étiquette de retrait qui n'en est pas une.
        let mut autre = octets;
        autre[DROITS_EN + 1] = 7;
        assert_eq!(Droit::lire(&autre), Err(Faute::Etiquette { lue: 7 }));
        // Du bourrage sous un retrait absent.
        let vivant = un_droit(un(Genre::Machine, 5), Droits::VOIR, None);
        let mut octets = [0_u8; DROIT_OCTETS];
        vivant.ecrire(&mut octets);
        octets[DROITS_EN + 2] = 1;
        assert_eq!(Droit::lire(&octets), Err(Faute::Bourrage));
    }

    fn une_autorisation(portee: Portee, revoquee: bool) -> Autorisation {
        Autorisation {
            provenance: Provenance::Ici,
            estampille: e(12),
            par: un(Genre::Utilisateur, 1),
            a: un(Genre::Utilisateur, 3),
            portee,
            revoquee,
            etiquette: NomRange::nouveau("accès NAS").unwrap(),
        }
    }

    #[test]
    fn une_autorisation_se_convertit_et_se_redit_a_l_identique() {
        let machine = un(Genre::Machine, 7);
        let service = un(Genre::Service, 7);
        for (portee, element) in [
            (Portee::ToutLeCompte, un(Genre::Utilisateur, 1)),
            (Portee::UneMachine(machine), machine),
            (Portee::UnService(service), service),
        ] {
            for revoquee in [false, true] {
                let autorisation = une_autorisation(portee, revoquee);
                let droit = Droit::depuis_autorisation(&autorisation);
                assert_eq!(droit.groupe, groupe_personnel(autorisation.a));
                assert_eq!(droit.element, element);
                assert_eq!(droit.droits, Droits::D_UNE_AUTORISATION);
                assert_eq!(droit.retire.is_some(), revoquee);
                assert_eq!(aller_retour(&droit), droit);
                assert_eq!(droit.en_autorisation(autorisation.a), Some(autorisation));
            }
        }
    }

    #[test]
    fn ce_qui_n_a_pas_de_forme_d_hier_ne_s_y_dit_pas() {
        let a = un(Genre::Utilisateur, 3);
        // Sans `localiser`, ce n'était pas une autorisation.
        assert_eq!(
            un_droit(un(Genre::Machine, 5), Droits::VOIR, None).en_autorisation(a),
            None
        );
        // Sur un domaine, aucune portée ne savait le nommer.
        assert_eq!(
            un_droit(un(Genre::Domaine, 5), Droits::LOCALISER, None).en_autorisation(a),
            None
        );
        // Retiré après l'octroi : la forme d'hier datait de la révocation.
        let retire = un_droit(un(Genre::Service, 5), Droits::LOCALISER, Some(e(9)))
            .en_autorisation(a)
            .unwrap();
        assert!(retire.revoquee);
        assert_eq!(retire.estampille, e(9));
        assert_eq!(retire.portee, Portee::UnService(un(Genre::Service, 5)));
    }
}
