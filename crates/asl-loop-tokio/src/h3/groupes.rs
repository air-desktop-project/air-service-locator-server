//! Les groupes, à l'étage 3 (`protocole.md` §2.2, `docs/modele.md` §2.12,
//! 2026-09-27) : lire l'entrepôt, juger, écrire.
//!
//! # QUI PEUT QUOI SUR UN GROUPE
//!
//! **Les administrateurs de son domaine** le créent, l'étiquettent, le
//! suppriment, et en changent les membres — y compris ceux du groupe
//! d'administrateurs lui-même. **Un membre** voit le groupe et peut s'en aller.
//! **Un groupe personnel** ne se voit que de son titulaire, et ne se modifie
//! pas. **Le groupe des administrateurs des racines** ne change que sous la clé
//! d'exploitant (`POST`/`DELETE /v1/administrateurs`) : ici, `403`.
//!
//! Partout ailleurs, **absent et interdit se confondent** (C10) : un groupe
//! qu'on ne peut pas voir n'existe pas pour qui le demande.

use asl_cle::{Defi, Signature};
use asl_id::{Genre, Identifiant};
use asl_registre::{NomRange, SorteDeGroupe};
use asl_session::Trouvaille;
use asl_store::{EcritureDeGroupe, GroupeLu};

use super::{Service, alloc_reponse};

/// Ce qu'une écriture de l'entrepôt devient sur le fil.
const fn trouvaille_de(ecrit: EcritureDeGroupe) -> Trouvaille {
    match ecrit {
        EcritureDeGroupe::Faite => Trouvaille::Fait,
        EcritureDeGroupe::Deja | EcritureDeGroupe::Protege => Trouvaille::Conflit,
        EcritureDeGroupe::Interdit => Trouvaille::Refus,
        EcritureDeGroupe::Absent => Trouvaille::Rien,
    }
}

/// Le groupe tel que le fil le rend.
fn rendu(lu: &GroupeLu) -> asl_api::groupe::GroupeRendu<'_> {
    asl_api::groupe::GroupeRendu {
        groupe: lu.groupe,
        domaine: lu.domaine,
        etiquette: lu
            .etiquette
            .as_ref()
            .and_then(|texte| core::str::from_utf8(texte.octets()).ok()),
        sorte: lu.sorte.nom(),
    }
}

impl Service<'_> {
    /// Ce compte administre-t-il le domaine de ce groupe ?
    fn administre_le_domaine_de(&self, compte: Identifiant, lu: &GroupeLu) -> bool {
        lu.domaine
            .is_some_and(|domaine| self.entrepot.administre(compte, domaine).unwrap_or(false))
    }

    /// `GET /v1/groupes` — les miens.
    pub(super) fn rassembler_mes_groupes(&self) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(groupes) = self.entrepot.groupes_du_compte(compte) else {
            return Trouvaille::Rien;
        };
        let elements = groupes
            .iter()
            .filter_map(|(lu, membre)| {
                let mut sortie = alloc_reponse();
                let combien = rendu(lu).encoder_dans_la_liste(*membre, &mut sortie).ok()?;
                sortie.truncate(combien);
                Some(sortie)
            })
            .collect();
        Trouvaille::Groupes(elements)
    }

    /// `POST /v1/domaines/{d}/groupes` — un groupe de plus dans un domaine que
    /// j'administre. Jamais dans le domaine racine, qui n'a que son groupe
    /// d'administrateurs.
    pub(super) fn creer_un_groupe(&self, domaine: Identifiant, etiquette: NomRange) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        if self.domaine_gere(compte, domaine).is_none() {
            return Trouvaille::Rien;
        }
        let Some(groupe) = self.un_identifiant(Genre::Ensemble) else {
            return Trouvaille::Rien;
        };
        match self.entrepot.creer_groupe(groupe, domaine, etiquette) {
            Ok(true) => Trouvaille::GroupeCree(groupe),
            Ok(false) | Err(_) => Trouvaille::Rien,
        }
    }

    /// `GET /v1/groupes/{e}` — le groupe et ses membres, pour ses membres et
    /// les administrateurs de son domaine.
    pub(super) fn lire_un_groupe(&self, groupe: Identifiant) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(Some((lu, membres))) = self.entrepot.groupe_et_membres(groupe) else {
            return Trouvaille::Rien;
        };
        if !membres.contains(&compte) && !self.administre_le_domaine_de(compte, &lu) {
            return Trouvaille::Rien;
        }
        let mut sortie = alloc_reponse();
        match rendu(&lu).encoder_avec_ses_membres(&membres, &mut sortie) {
            Ok(combien) => {
                sortie.truncate(combien);
                Trouvaille::GroupeLu(sortie)
            }
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Le groupe vivant que ce compte administre — par son domaine —, ou rien.
    fn groupe_administre(&self, compte: Identifiant, groupe: Identifiant) -> Option<GroupeLu> {
        let lu = self.entrepot.groupe(groupe).ok().flatten()?;
        self.administre_le_domaine_de(compte, &lu).then_some(lu)
    }

    /// `PATCH /v1/groupes/{e}` — son étiquette.
    pub(super) fn etiqueter_un_groupe(
        &self,
        groupe: Identifiant,
        etiquette: NomRange,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        if self.groupe_administre(compte, groupe).is_none() {
            return Trouvaille::Rien;
        }
        match self.entrepot.etiqueter_groupe(groupe, etiquette) {
            Ok(ecrit) => trouvaille_de(ecrit),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// `DELETE /v1/groupes/{e}` — jamais un groupe déduit (`409`).
    pub(super) fn supprimer_un_groupe(&self, groupe: Identifiant) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        if self.groupe_administre(compte, groupe).is_none() {
            return Trouvaille::Rien;
        }
        match self.entrepot.supprimer_groupe(groupe) {
            Ok(ecrit) => trouvaille_de(ecrit),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// `POST /v1/groupes/{e}/membres` — un compte de plus. `403` sur un groupe
    /// personnel et sur celui des administrateurs des racines ; `404` si le
    /// compte n'existe pas ; `409` s'il est déjà membre.
    ///
    /// **Réveille le compte ajouté si le groupe porte des droits**
    /// (`docs/modele.md` §2.13) : il vient d'en recevoir.
    pub(super) fn ajouter_un_membre(
        &mut self,
        groupe: Identifiant,
        membre: Identifiant,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Some(lu) = self.entrepot.groupe(groupe).ok().flatten() else {
            return Trouvaille::Rien;
        };
        if lu.sorte == SorteDeGroupe::Personnel
            || lu.domaine == Some(asl_registre::domaine_racine())
        {
            return Trouvaille::Refus;
        }
        if !self.administre_le_domaine_de(compte, &lu) {
            return Trouvaille::Rien;
        }
        match self.entrepot.ajouter_membre(groupe, membre) {
            Ok(EcritureDeGroupe::Faite) => {
                if self
                    .entrepot
                    .groupe_porte_des_droits(groupe)
                    .unwrap_or(false)
                {
                    self.a_reveiller.push(membre);
                }
                Trouvaille::Fait
            }
            Ok(ecrit) => trouvaille_de(ecrit),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// `DELETE /v1/groupes/{e}/membres/{u}` — par un administrateur du
    /// domaine, **ou par le membre lui-même qui s'en va**. `409` pour le
    /// propriétaire dans son groupe d'administrateurs.
    pub(super) fn retirer_un_membre(&self, groupe: Identifiant, membre: Identifiant) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Some(lu) = self.entrepot.groupe(groupe).ok().flatten() else {
            return Trouvaille::Rien;
        };
        if lu.sorte == SorteDeGroupe::Personnel
            || lu.domaine == Some(asl_registre::domaine_racine())
        {
            return Trouvaille::Refus;
        }
        if compte != membre && !self.administre_le_domaine_de(compte, &lu) {
            return Trouvaille::Rien;
        }
        match self.entrepot.retirer_membre(groupe, membre) {
            Ok(ecrit) => trouvaille_de(ecrit),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// `POST /v1/administrateurs` et `DELETE /v1/administrateurs/{u}` — **sous
    /// la clé d'exploitant**, et sous elle seule (`docs/modele.md` §2.12).
    ///
    /// Sans `--operator-key`, la ressource n'existe pas : `Rien`, `404`. Une
    /// signature qui ne tient pas : `Refus`, `401` — la ressource existe.
    pub(super) fn changer_les_administrateurs(
        &self,
        defi: &Defi,
        signature: &Signature,
        compte: Identifiant,
        nomme: bool,
    ) -> Trouvaille {
        let Some(cle) = self.voie.exploitant else {
            return Trouvaille::Rien;
        };
        if !cle.prouve_l_exploitant(defi, self.session.liaison(), signature) {
            (self.voie.journal)(
                "administrateurs des racines : la signature de l'exploitant ne tient pas",
            );
            return Trouvaille::Refus;
        }
        let ecrit = if nomme {
            self.entrepot.nommer_administrateur_des_racines(compte)
        } else {
            self.entrepot.retirer_administrateur_des_racines(compte)
        };
        match ecrit {
            Ok(EcritureDeGroupe::Faite) => {
                (self.voie.journal)(&format!(
                    "administrateurs des racines : {} {}, sous la clé d'exploitant",
                    compte.texte().as_str(),
                    if nomme { "nommé" } else { "retiré" }
                ));
                Trouvaille::Fait
            }
            Ok(ecrit) => trouvaille_de(ecrit),
            Err(_) => Trouvaille::Rien,
        }
    }
}
