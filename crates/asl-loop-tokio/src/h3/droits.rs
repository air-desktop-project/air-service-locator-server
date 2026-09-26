//! Les droits, à l'étage 3 (`protocole.md` §2.2, `docs/modele.md` §2.13,
//! 2026-09-27) : lire l'entrepôt, juger qui peut accorder et retirer, écrire,
//! et réveiller ceux qui reçoivent.
//!
//! # QUI ACCORDE, QUI RETIRE
//!
//! **Sur un domaine** : qui l'administre — son groupe d'administrateurs, ou un
//! groupe qui a reçu `administrer` sur lui. **Sur une machine ou un de ses
//! services** : son propriétaire, toujours, et qui administre le domaine où
//! elle est rangée (décision 40). **Aucun droit ne se crée pour soi par un
//! autre chemin** : on n'accorde que sur ce qu'on possède ou qu'on administre.
//! Retirer : celui qui a accordé, ou qui a aujourd'hui le pouvoir d'accorder
//! sur l'élément.
//!
//! Partout, **absent et interdit se confondent pour qui ne voit rien** (C10) :
//! `404`. Qui voit l'élément sans pouvoir y accorder reçoit `403`.

use asl_id::{Genre, Identifiant};
use asl_registre::{Droit, Droits, NomRange};
use asl_session::Trouvaille;
use asl_store::EcritureDeDroit;

use super::{Service, alloc_reponse};

impl Service<'_> {
    /// Ce compte a-t-il aujourd'hui le pouvoir d'accorder sur cet élément ?
    fn peut_accorder_sur(&self, compte: Identifiant, element: Identifiant) -> bool {
        match element.genre() {
            Genre::Domaine => {
                element != asl_registre::domaine_racine()
                    && self.entrepot.administre(compte, element).unwrap_or(false)
            }
            Genre::Machine | Genre::Service => self
                .entrepot
                .machine_de_l_element(element)
                .ok()
                .flatten()
                .is_some_and(|machine| {
                    self.entrepot
                        .peut_accorder_sur_la_machine(compte, machine)
                        .unwrap_or(false)
                }),
            // L'élément « compte » n'est accordé que par son titulaire, et par
            // le verbe de compatibilité.
            Genre::Utilisateur => element == compte,
            _ => false,
        }
    }

    /// Ce compte VOIT-il cet élément, sans forcément pouvoir y accorder ? Un
    /// domaine où il tient un droit, une machine qu'il voit.
    fn voit(&self, compte: Identifiant, element: Identifiant) -> bool {
        match element.genre() {
            Genre::Domaine => !self
                .entrepot
                .droits_sur_domaine(compte, element)
                .unwrap_or_default()
                .est_vide(),
            Genre::Machine | Genre::Service => {
                let Some(machine) = self.entrepot.machine_de_l_element(element).ok().flatten()
                else {
                    return false;
                };
                self.entrepot
                    .acces(compte, asl_store::Voulu::Voir)
                    .unwrap_or_default()
                    .iter()
                    .any(|acces| match acces.portee {
                        asl_registre::Portee::UneMachine(vue) => vue == machine,
                        asl_registre::Portee::UnService(vu) => vu == element,
                        asl_registre::Portee::ToutLeCompte => self
                            .entrepot
                            .machine(machine)
                            .ok()
                            .flatten()
                            .is_some_and(|rangee| rangee.proprietaire == acces.proprietaire),
                    })
            }
            _ => false,
        }
    }

    /// `GET /v1/droits` — **ceux que j'ai accordés, ceux que mes groupes ont
    /// reçus, et ceux qui visent ce que je possède ou que j'administre** —
    /// pour qu'on puisse voir, et retirer, ce qu'un administrateur a partagé
    /// de sa machine. Retirés compris, une fois chacun.
    pub(super) fn rassembler_mes_droits(&self) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let mut tous: Vec<(Identifiant, Droit)> = Vec::new();
        tous.extend(self.entrepot.droits_accordes(compte).unwrap_or_default());
        tous.extend(self.entrepot.droits_recus(compte).unwrap_or_default());
        let mut vises: Vec<Identifiant> = self
            .entrepot
            .domaines_de_compte(compte)
            .unwrap_or_default()
            .into_iter()
            .map(|(domaine, _)| domaine)
            .collect();
        vises.extend(
            self.entrepot
                .domaines_administres(compte)
                .unwrap_or_default(),
        );
        for (machine, _) in self.entrepot.machines_de_compte(compte).unwrap_or_default() {
            vises.push(machine);
            vises.extend(
                self.entrepot
                    .services_de_machine(machine)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(service, _)| service),
            );
        }
        for element in vises {
            tous.extend(self.entrepot.droits_sur(element).unwrap_or_default());
        }
        tous.sort_by_key(|(droit, _)| (droit.genre().prefixe(), *droit.octets()));
        tous.dedup_by_key(|(droit, _)| *droit);
        let elements = tous
            .iter()
            .filter_map(|(quel, droit)| {
                let etiquette = core::str::from_utf8(droit.etiquette.octets()).ok()?;
                let rendu = asl_api::droit::DroitRendu {
                    droit: *quel,
                    groupe: droit.groupe,
                    element: droit.element,
                    droits: droit.droits.octet(),
                    etiquette,
                    par: droit.par,
                    retire: droit.retire.is_some(),
                };
                let mut sortie = alloc_reponse();
                let combien = rendu.encoder(&mut sortie).ok()?;
                sortie.truncate(combien);
                Some(sortie)
            })
            .collect();
        Trouvaille::Droits(elements)
    }

    /// `POST /v1/droits` — accorder, puis **réveiller les membres du groupe**
    /// (`docs/modele.md` §2.13), d'ici et d'ici seulement (décision 9), dans
    /// le même tour que la réponse (décision 29).
    pub(super) fn accorder_un_droit(
        &mut self,
        groupe: Identifiant,
        element: Identifiant,
        droits: Droits,
        etiquette: NomRange,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(Some((_, membres))) = self.entrepot.groupe_et_membres(groupe) else {
            return Trouvaille::Rien;
        };
        if !self.peut_accorder_sur(compte, element) {
            return if self.voit(compte, element) {
                Trouvaille::Refus
            } else {
                Trouvaille::Rien
            };
        }
        let Some(droit) = self.un_identifiant(Genre::Autorisation) else {
            return Trouvaille::Rien;
        };
        match self
            .entrepot
            .accorder_droit(droit, compte, groupe, element, droits, etiquette)
        {
            Ok(EcritureDeDroit::Faite) => {
                self.a_reveiller
                    .extend(membres.into_iter().filter(|membre| *membre != compte));
                Trouvaille::DroitCree(droit)
            }
            Ok(EcritureDeDroit::Absent) | Err(_) => Trouvaille::Rien,
        }
    }

    /// `DELETE /v1/droits/{g}` — par celui qui l'a accordé, ou par qui a
    /// aujourd'hui le pouvoir d'accorder sur l'élément. Un membre du groupe
    /// qui l'a reçu le voit, et reçoit `403` ; les autres ne le voient pas.
    pub(super) fn retirer_un_droit(&self, droit: Identifiant) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(rangee)) = self.entrepot.droit(droit) else {
            return Trouvaille::Rien;
        };
        if rangee.par != compte && !self.peut_accorder_sur(compte, rangee.element) {
            let recu = self
                .entrepot
                .droits_recus(compte)
                .unwrap_or_default()
                .iter()
                .any(|(quel, _)| *quel == droit);
            return if recu {
                Trouvaille::Refus
            } else {
                Trouvaille::Rien
            };
        }
        match self.entrepot.retirer_droit(droit) {
            Ok(Some(_)) => Trouvaille::Fait,
            Ok(None) | Err(_) => Trouvaille::Rien,
        }
    }
}
