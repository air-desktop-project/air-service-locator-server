//! Les groupes (`docs/modele.md` §2.12, 2026-09-26) : les trois identifiants
//! qui se DÉDUISENT — le domaine racine, le groupe d'administrateurs d'un
//! domaine, le groupe personnel d'un compte —, et les trois enregistrements
//! que l'entrepôt range : le groupe, la marque de sa suppression, l'adhésion
//! d'un compte.
//!
//! # POURQUOI L'ADHÉSION PORTE L'ESTAMPILLE DE SON AJOUT
//!
//! `docs/replication.md` §5.2 : `groupe-membre-retire` retire **l'ajout
//! nommé, et lui seul**. Un compte retiré d'un côté pendant qu'on le rajoute
//! de l'autre reste donc membre par le second ajout, dans tous les ordres
//! d'arrivée : c'est un ensemble où chaque ajout a son nom, et où un retrait
//! ne vise que ce qu'il a vu. Le nom d'un ajout est son estampille — et c'est
//! dans la CLÉ que l'entrepôt la range, pas ici.

use asl_id::{Genre, Identifiant};

use crate::{
    ESTAMPILLE_OCTETS, Estampille, Faute, IDENTIFIANT_OCTETS, NOM_OCTETS_MAX, NomRange,
    PROVENANCE_OCTETS, Provenance, bourrage_nul, ecrire_identifiant, lire_identifiant, poser,
    poser_un,
};

// ── Les identifiants déduits ────────────────────────────────────────────────

/// Le séparateur du groupe d'administrateurs d'un domaine.
pub const SEPARATEUR_GROUPE_D_ADMINISTRATEURS: &[u8] =
    b"air-service-locator/v1/groupe-d-administrateurs\x00";

/// Le séparateur du groupe personnel d'un compte.
pub const SEPARATEUR_GROUPE_PERSONNEL: &[u8] = b"air-service-locator/v1/groupe-personnel\x00";

/// Le séparateur du domaine racine. **L'étiquette fixe est `asl domaine
/// racine`** (`docs/modele.md` §2.11) : elle est tout le message, derrière le
/// séparateur.
pub const SEPARATEUR_DOMAINE_RACINE: &[u8] = b"air-service-locator/v1/domaine-racine\x00";

/// L'étiquette fixe dont le domaine racine se déduit.
pub const ETIQUETTE_DOMAINE_RACINE: &[u8] = b"asl domaine racine";

/// Seize octets d'un SHA-256 à séparateur.
fn seize(separateur: &[u8], message: &[u8]) -> [u8; 16] {
    use sha2::Digest as _;
    let mut condensat = sha2::Sha256::new();
    condensat.update(separateur);
    condensat.update(message);
    let entier = condensat.finalize();
    let mut rendus = [0_u8; 16];
    poser(&mut rendus, &entier);
    rendus
}

/// Le domaine racine — le seul au niveau 0 (`docs/modele.md` §2.11).
///
/// # DÉDUIT D'UNE ÉTIQUETTE, ET CALCULÉ PARTOUT
///
/// Les deux racines et tout annuaire local le calculent pareil, sans rien
/// échanger ni rien amorcer : il n'y a pas de fenêtre où l'une le connaîtrait
/// et l'autre non.
#[must_use]
pub fn domaine_racine() -> Identifiant {
    Identifiant::depuis_entropie(
        Genre::Domaine,
        seize(SEPARATEUR_DOMAINE_RACINE, ETIQUETTE_DOMAINE_RACINE),
    )
}

/// Le groupe d'administrateurs de ce domaine.
///
/// **Déduit, et non tiré**, pour la raison de [`crate::premier_domaine`] :
/// chaque racine le fait naître avec le domaine, de son côté, et les deux
/// arrivent au même identifiant sans qu'une opération voyage. Celui du
/// domaine racine est le groupe des administrateurs des racines.
#[must_use]
pub fn groupe_d_administrateurs(domaine: Identifiant) -> Identifiant {
    Identifiant::depuis_entropie(
        Genre::Ensemble,
        seize(SEPARATEUR_GROUPE_D_ADMINISTRATEURS, domaine.octets()),
    )
}

/// Le groupe personnel de ce compte — celui qu'on nomme pour partager avec
/// une personne, et qui ne contient qu'elle.
#[must_use]
pub fn groupe_personnel(compte: Identifiant) -> Identifiant {
    Identifiant::depuis_entropie(
        Genre::Ensemble,
        seize(SEPARATEUR_GROUPE_PERSONNEL, compte.octets()),
    )
}

// ── La sorte d'un groupe ────────────────────────────────────────────────────

/// Les trois sortes de groupes (`docs/modele.md` §2.12) — une seule mécanique.
///
/// **Aucune ne vaut zéro**, pour la raison écrite sur [`crate::Attestation`] :
/// un tampon réemployé vaut zéro, et ne doit désigner aucune sorte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SorteDeGroupe {
    /// Le groupe d'administrateurs d'un domaine : né avec lui, identifiant
    /// déduit, le propriétaire membre d'office et non retirable.
    Administrateurs,
    /// Un groupe qu'un administrateur a créé dans le domaine.
    Domaine,
    /// Le groupe personnel d'un compte : né avec lui, identifiant déduit, sans
    /// domaine, et qui ne contient que lui.
    Personnel,
}

impl SorteDeGroupe {
    /// Son étiquette rangée.
    #[must_use]
    pub const fn etiquette(self) -> u8 {
        match self {
            Self::Administrateurs => 1,
            Self::Domaine => 2,
            Self::Personnel => 3,
        }
    }

    /// Relit une étiquette.
    ///
    /// # Errors
    ///
    /// [`Faute::Etiquette`] si l'octet ne désigne aucune sorte.
    pub const fn depuis(octet: u8) -> Result<Self, Faute> {
        Ok(match octet {
            1 => Self::Administrateurs,
            2 => Self::Domaine,
            3 => Self::Personnel,
            lue => return Err(Faute::Etiquette { lue }),
        })
    }

    /// Ce qu'elle s'appelle sur le fil (`protocole.md` §2.2).
    #[must_use]
    pub const fn nom(self) -> &'static str {
        match self {
            Self::Administrateurs => "administrateurs",
            Self::Domaine => "domaine",
            Self::Personnel => "personnel",
        }
    }

    /// Le genre de ce à quoi un groupe de cette sorte est rattaché : son
    /// domaine, ou le compte dont il est le groupe personnel.
    #[must_use]
    pub const fn genre_du_rattache(self) -> Genre {
        match self {
            Self::Administrateurs | Self::Domaine => Genre::Domaine,
            Self::Personnel => Genre::Utilisateur,
        }
    }
}

// ── Le groupe ───────────────────────────────────────────────────────────────

/// Ce qu'un groupe occupe.
pub const GROUPE_OCTETS: usize = PROVENANCE_OCTETS
    + ESTAMPILLE_OCTETS
    + 1
    + IDENTIFIANT_OCTETS
    + ESTAMPILLE_OCTETS
    + 1
    + NOM_OCTETS_MAX;

/// Un groupe (`docs/modele.md` §2.12).
///
/// # L'ÉTIQUETTE ET SON ESTAMPILLE SONT DANS L'ENREGISTREMENT
///
/// Elle change — `PATCH /v1/groupes/{e}` —, et le plus récent gagne : elle
/// porte donc sa propre estampille, à côté de la naissance, comme le nom d'une
/// machine. Un instantané rend le groupe avec son étiquette courante, et le
/// lecteur la garde si elle est plus récente que la sienne.
///
/// # LA SUPPRESSION N'EST PAS ICI
///
/// Elle vit à part ([`MarqueDeGroupe`]), pour que la marque puisse arriver
/// AVANT le groupe qu'elle vise et le condamner quand même : une marque ne
/// s'efface jamais, et un groupe marqué n'existe pas pour qui le demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Groupe {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Sa naissance.
    pub estampille: Estampille,
    /// Sa sorte.
    pub sorte: SorteDeGroupe,
    /// Son domaine — ou, pour un groupe personnel, le compte dont il est le
    /// groupe. Le genre suit la sorte.
    pub rattache: Identifiant,
    /// La dernière pose de l'étiquette.
    pub etiquette_estampille: Estampille,
    /// L'étiquette : libre, pour l'humain. **Vide pour un groupe déduit**,
    /// qui n'en a jamais reçu.
    pub etiquette: NomRange,
}

impl Groupe {
    /// Écrit ce groupe.
    pub fn ecrire(&self, sortie: &mut [u8; GROUPE_OCTETS]) {
        sortie.fill(0);
        let mut place = 0_usize;
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        place = place.saturating_add(PROVENANCE_OCTETS);
        self.estampille
            .ecrire(sortie.get_mut(place..).unwrap_or_default());
        place = place.saturating_add(ESTAMPILLE_OCTETS);
        poser_un(
            sortie.get_mut(place..).unwrap_or_default(),
            self.sorte.etiquette(),
        );
        place = place.saturating_add(1);
        ecrire_identifiant(self.rattache, sortie.get_mut(place..).unwrap_or_default());
        place = place.saturating_add(IDENTIFIANT_OCTETS);
        self.etiquette_estampille
            .ecrire(sortie.get_mut(place..).unwrap_or_default());
        place = place.saturating_add(ESTAMPILLE_OCTETS);
        self.etiquette
            .ecrire(sortie.get_mut(place..).unwrap_or_default());
    }

    /// Relit un groupe.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas un groupe — un rattaché d'un
    /// autre genre que celui que sa sorte exige compris.
    pub fn lire(octets: &[u8; GROUPE_OCTETS]) -> Result<Self, Faute> {
        let mut place = 0_usize;
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        place = place.saturating_add(PROVENANCE_OCTETS);
        let estampille = Estampille::lire(octets.get(place..).unwrap_or_default())?;
        place = place.saturating_add(ESTAMPILLE_OCTETS);
        let sorte = SorteDeGroupe::depuis(octets.get(place).copied().unwrap_or(0))?;
        place = place.saturating_add(1);
        let rattache = lire_identifiant(
            octets.get(place..).unwrap_or_default(),
            sorte.genre_du_rattache(),
        )?;
        place = place.saturating_add(IDENTIFIANT_OCTETS);
        let etiquette_estampille = Estampille::lire(octets.get(place..).unwrap_or_default())?;
        place = place.saturating_add(ESTAMPILLE_OCTETS);
        let etiquette = NomRange::lire(octets.get(place..).unwrap_or_default())?;
        Ok(Self {
            provenance,
            estampille,
            sorte,
            rattache,
            etiquette_estampille,
            etiquette,
        })
    }
}

// ── La marque d'un groupe supprimé ──────────────────────────────────────────

/// Ce qu'une marque occupe.
pub const MARQUE_DE_GROUPE_OCTETS: usize = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;

/// La suppression d'un groupe, sous son estampille (`docs/replication.md`
/// §5.2) : **toujours**, la plus petite si deux racines l'ont voulue, et
/// jamais effacée — ce qui arrive ensuite pour ce groupe est refusé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarqueDeGroupe {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// La suppression.
    pub estampille: Estampille,
}

impl MarqueDeGroupe {
    /// Écrit cette marque.
    pub fn ecrire(&self, sortie: &mut [u8; MARQUE_DE_GROUPE_OCTETS]) {
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        self.estampille
            .ecrire(sortie.get_mut(PROVENANCE_OCTETS..).unwrap_or_default());
    }

    /// Relit une marque.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une marque.
    pub fn lire(octets: &[u8; MARQUE_DE_GROUPE_OCTETS]) -> Result<Self, Faute> {
        Ok(Self {
            provenance: Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?,
            estampille: Estampille::lire(octets.get(PROVENANCE_OCTETS..).unwrap_or_default())?,
        })
    }
}

// ── L'adhésion ──────────────────────────────────────────────────────────────

/// Ce qu'une adhésion occupe.
pub const ADHESION_OCTETS: usize = PROVENANCE_OCTETS + 1 + ESTAMPILLE_OCTETS;

/// Un ajout d'un compte à un groupe — **le groupe, le compte et l'estampille
/// de l'ajout sont dans la clé** —, et son retrait s'il a eu lieu.
///
/// Un retrait arrivé AVANT l'ajout qu'il nomme se range quand même, sous la
/// forme d'une adhésion déjà retirée : l'ajout, quand il arrive, trouve la
/// place prise et ne ressuscite rien. Deux retraits du même ajout gardent la
/// plus petite estampille.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adhesion {
    /// D'où vient cet enregistrement.
    pub provenance: Provenance,
    /// Le retrait de cet ajout, ou rien : le compte est membre par lui.
    pub retire: Option<Estampille>,
}

impl Adhesion {
    /// Écrit cette adhésion.
    pub fn ecrire(&self, sortie: &mut [u8; ADHESION_OCTETS]) {
        sortie.fill(0);
        self.provenance
            .ecrire(sortie.get_mut(..PROVENANCE_OCTETS).unwrap_or_default());
        if let Some(quand) = self.retire {
            let reste = sortie.get_mut(PROVENANCE_OCTETS..).unwrap_or_default();
            poser_un(reste, 1);
            quand.ecrire(reste.get_mut(1..).unwrap_or_default());
        }
    }

    /// Relit une adhésion.
    ///
    /// # Errors
    ///
    /// [`Faute`] si les octets ne forment pas une adhésion.
    pub fn lire(octets: &[u8; ADHESION_OCTETS]) -> Result<Self, Faute> {
        let provenance = Provenance::lire(octets.get(..PROVENANCE_OCTETS).unwrap_or_default())?;
        let reste = octets.get(PROVENANCE_OCTETS..).unwrap_or_default();
        let retire = match reste.first().copied().unwrap_or(0) {
            0 => {
                if !bourrage_nul(reste.get(1..).unwrap_or_default()) {
                    return Err(Faute::Bourrage);
                }
                None
            }
            1 => Some(Estampille::lire(reste.get(1..).unwrap_or_default())?),
            lue => return Err(Faute::Etiquette { lue }),
        };
        Ok(Self { provenance, retire })
    }
}

#[cfg(test)]
mod tests {
    use asl_id::{Genre, Identifiant};

    use super::{
        ADHESION_OCTETS, Adhesion, GROUPE_OCTETS, Groupe, MARQUE_DE_GROUPE_OCTETS, MarqueDeGroupe,
        SorteDeGroupe, domaine_racine, groupe_d_administrateurs, groupe_personnel,
    };
    use crate::{ESTAMPILLE_OCTETS, Estampille, Faute, NomRange, PROVENANCE_OCTETS, Provenance};

    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    fn e(compteur: u64) -> Estampille {
        Estampille {
            compteur,
            racine: un(Genre::Annuaire, 0xEE),
        }
    }

    #[test]
    fn les_trois_identifiants_se_deduisent_et_ne_se_confondent_pas() {
        let racine = domaine_racine();
        assert_eq!(racine.genre(), Genre::Domaine);
        assert_eq!(domaine_racine(), racine);
        let d = un(Genre::Domaine, 1);
        let u = un(Genre::Utilisateur, 1);
        let admins = groupe_d_administrateurs(d);
        let personnel = groupe_personnel(u);
        assert_eq!(admins.genre(), Genre::Ensemble);
        assert_eq!(personnel.genre(), Genre::Ensemble);
        assert_eq!(groupe_d_administrateurs(d), admins);
        assert_eq!(groupe_personnel(u), personnel);
        // Les mêmes seize octets de départ, deux séparateurs, deux groupes.
        assert_ne!(admins, personnel);
        assert_ne!(groupe_d_administrateurs(un(Genre::Domaine, 2)), admins);
        assert_ne!(groupe_personnel(un(Genre::Utilisateur, 2)), personnel);
        assert_ne!(groupe_d_administrateurs(racine), admins);
    }

    #[test]
    fn la_sorte_fait_l_aller_retour_et_zero_n_en_est_pas_une() {
        for sorte in [
            SorteDeGroupe::Administrateurs,
            SorteDeGroupe::Domaine,
            SorteDeGroupe::Personnel,
        ] {
            assert_eq!(SorteDeGroupe::depuis(sorte.etiquette()), Ok(sorte));
            assert!(!sorte.nom().is_empty());
        }
        assert_eq!(SorteDeGroupe::depuis(0), Err(Faute::Etiquette { lue: 0 }));
        assert_eq!(
            SorteDeGroupe::Personnel.genre_du_rattache(),
            Genre::Utilisateur
        );
        assert_eq!(SorteDeGroupe::Domaine.genre_du_rattache(), Genre::Domaine);
    }

    fn un_groupe(sorte: SorteDeGroupe) -> Groupe {
        let rattache = match sorte {
            SorteDeGroupe::Personnel => un(Genre::Utilisateur, 3),
            _ => un(Genre::Domaine, 3),
        };
        Groupe {
            provenance: Provenance::Ici,
            estampille: e(4),
            sorte,
            rattache,
            etiquette_estampille: e(6),
            etiquette: NomRange::nouveau("Famille").unwrap(),
        }
    }

    #[test]
    fn un_groupe_fait_l_aller_retour() {
        for sorte in [
            SorteDeGroupe::Administrateurs,
            SorteDeGroupe::Domaine,
            SorteDeGroupe::Personnel,
        ] {
            let groupe = un_groupe(sorte);
            let mut octets = [0xFF_u8; GROUPE_OCTETS];
            groupe.ecrire(&mut octets);
            assert_eq!(Groupe::lire(&octets), Ok(groupe));
        }
    }

    #[test]
    fn un_groupe_corrompu_est_refuse() {
        let mut octets = [0_u8; GROUPE_OCTETS];
        un_groupe(SorteDeGroupe::Domaine).ecrire(&mut octets);
        let sorte = PROVENANCE_OCTETS + ESTAMPILLE_OCTETS;
        // Une sorte inconnue.
        let mut corrompu = octets;
        corrompu[sorte] = 9;
        assert_eq!(Groupe::lire(&corrompu), Err(Faute::Etiquette { lue: 9 }));
        // Une sorte personnelle sur un domaine : le rattaché n'est pas du genre
        // que la sorte exige.
        let mut corrompu = octets;
        corrompu[sorte] = SorteDeGroupe::Personnel.etiquette();
        assert_eq!(
            Groupe::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Utilisateur
            })
        );
        // Une étiquette plus longue que sa place.
        let mut corrompu = octets;
        corrompu[GROUPE_OCTETS - 1 - crate::NOM_OCTETS_MAX] = 200;
        assert!(Groupe::lire(&corrompu).is_err());
        // L'estampille de l'étiquette dont la racine n'est pas un annuaire.
        let mut corrompu = octets;
        corrompu[sorte + 1 + crate::IDENTIFIANT_OCTETS + 8] = b'u';
        assert_eq!(
            Groupe::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
        // La naissance, de même.
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS + 8] = b'u';
        assert_eq!(
            Groupe::lire(&corrompu),
            Err(Faute::Genre {
                attendu: Genre::Annuaire
            })
        );
        // Une provenance inconnue.
        let mut corrompu = octets;
        corrompu[0] = 7;
        assert_eq!(Groupe::lire(&corrompu), Err(Faute::Etiquette { lue: 7 }));
    }

    #[test]
    fn une_marque_fait_l_aller_retour_et_se_refuse_corrompue() {
        let marque = MarqueDeGroupe {
            provenance: Provenance::Annuaire(un(Genre::Annuaire, 5)),
            estampille: e(9),
        };
        let mut octets = [0_u8; MARQUE_DE_GROUPE_OCTETS];
        marque.ecrire(&mut octets);
        assert_eq!(MarqueDeGroupe::lire(&octets), Ok(marque));
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS + 8] = b'u';
        assert!(MarqueDeGroupe::lire(&corrompu).is_err());
        let mut corrompu = octets;
        corrompu[0] = 7;
        assert_eq!(
            MarqueDeGroupe::lire(&corrompu),
            Err(Faute::Etiquette { lue: 7 })
        );
    }

    #[test]
    fn une_adhesion_fait_l_aller_retour() {
        for retire in [None, Some(e(12))] {
            let adhesion = Adhesion {
                provenance: Provenance::Ici,
                retire,
            };
            let mut octets = [0xFF_u8; ADHESION_OCTETS];
            adhesion.ecrire(&mut octets);
            assert_eq!(Adhesion::lire(&octets), Ok(adhesion));
        }
    }

    #[test]
    fn une_adhesion_corrompue_est_refusee() {
        let mut octets = [0_u8; ADHESION_OCTETS];
        Adhesion {
            provenance: Provenance::Ici,
            retire: Some(e(12)),
        }
        .ecrire(&mut octets);
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS] = 2;
        assert_eq!(Adhesion::lire(&corrompu), Err(Faute::Etiquette { lue: 2 }));
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS] = 0;
        assert_eq!(Adhesion::lire(&corrompu), Err(Faute::Bourrage));
        let mut corrompu = octets;
        corrompu[PROVENANCE_OCTETS + 1 + 8] = b'u';
        assert!(Adhesion::lire(&corrompu).is_err());
        let mut corrompu = octets;
        corrompu[0] = 7;
        assert_eq!(Adhesion::lire(&corrompu), Err(Faute::Etiquette { lue: 7 }));
        assert_eq!(ADHESION_OCTETS, PROVENANCE_OCTETS + 1 + ESTAMPILLE_OCTETS);
    }
}
