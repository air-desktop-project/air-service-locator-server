//! L'inscription des annuaires locaux, à l'étage 3 (`protocole.md` §2.2 ;
//! `docs/annuaires.md` §2 ter, §4.1 ; 0.27.0) : lire l'entrepôt, juger,
//! écrire.
//!
//! # QUI PEUT QUOI
//!
//! **Le propriétaire** déclare son annuaire et son second membre, les retire,
//! et confie ses domaines — à un annuaire accepté qui est le sien, et à nul
//! autre (décision 48). **Un administrateur des racines** voit ce qui attend,
//! accepte ou refuse, et peut retirer. **L'annuaire lui-même** présente son
//! code et relit son état, sa clé prouvée sur la connexion.
//!
//! Partout ailleurs, **absent et interdit se confondent** (C10) : `404`.

use asl_cle::ClePublique;
use asl_id::Identifiant;
use asl_registre::Adresse;
use asl_session::Trouvaille;
use asl_store::{
    DecisionDInscription, DeclarationAttendue, DeclarationDAnnuaire, EtatDInscription, MembreLu,
    PresentationDeCode,
};

use super::{Service, alloc_reponse, maintenant};

/// Un membre, encodé — `proprietaire` pour les administrateurs, et les
/// locateurs qu'il a publiés (décision 57).
fn encoder_un_membre(lu: &MembreLu, avec_proprietaire: bool) -> Option<Vec<u8>> {
    let locateurs: Vec<&str> = lu
        .locateurs
        .iter()
        .flat_map(asl_registre::Locateurs::adresses)
        .map(Adresse::texte)
        .collect();
    let rendu = asl_api::annuaire::InscriptionRendue {
        membre: Some(lu.membre),
        annuaire: Some(lu.annuaire),
        proprietaire: avec_proprietaire.then_some(lu.proprietaire),
        etat: lu.etat.mot(),
        adresse: lu.adresse.texte(),
        locateurs: &locateurs,
        expire_a: None,
    };
    let mut sortie = alloc_reponse();
    let combien = rendu.encoder(&mut sortie).ok()?;
    sortie.truncate(combien);
    Some(sortie)
}

/// Une déclaration qui attend, encodée.
fn encoder_une_attente(attendue: &DeclarationAttendue) -> Option<Vec<u8>> {
    let rendu = asl_api::annuaire::InscriptionRendue {
        membre: None,
        annuaire: attendue.annuaire,
        proprietaire: None,
        etat: "attendue",
        adresse: attendue.adresse.texte(),
        locateurs: &[],
        expire_a: Some(attendue.expire_a),
    };
    let mut sortie = alloc_reponse();
    let combien = rendu.encoder(&mut sortie).ok()?;
    sortie.truncate(combien);
    Some(sortie)
}

impl Service<'_> {
    /// Ce compte administre-t-il les racines ?
    fn administre_les_racines(&self, compte: Identifiant) -> bool {
        self.entrepot
            .administrateurs_des_racines()
            .is_ok_and(|(membres, _)| membres.contains(&compte))
    }

    /// `GET /v1/annuaires` — mes annuaires, membre par membre, et mes
    /// déclarations qui attendent.
    pub(super) fn rassembler_mes_annuaires(&self) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let maintenant_ms = maintenant().saturating_div(1_000);
        let Ok((membres, attendues)) = self.entrepot.annuaires_du_compte(compte, maintenant_ms)
        else {
            return Trouvaille::Rien;
        };
        let mut elements: Vec<Vec<u8>> = membres
            .iter()
            .filter_map(|lu| encoder_un_membre(lu, false))
            .collect();
        elements.extend(attendues.iter().filter_map(encoder_une_attente));
        Trouvaille::Inscriptions(elements)
    }

    /// `POST /v1/annuaires` et `POST /v1/annuaires/{n}/membres` — un code
    /// d'inscription, rendu une fois ; l'entrepôt n'en garde que l'empreinte.
    pub(super) fn declarer_un_annuaire(
        &self,
        annuaire: Option<Identifiant>,
        adresse: Adresse,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Some(graine) = (self.tirer_un_identifiant)() else {
            return Trouvaille::Rien;
        };
        let mut huit = [0_u8; 8];
        for (place, octet) in huit.iter_mut().zip(graine.iter()) {
            *place = *octet;
        }
        let code = asl_cle::CodeInscription::depuis_entropie(huit);
        let expire_a = maintenant()
            .saturating_div(1_000)
            .saturating_add(asl_cle::VALIDITE_INSCRIPTION_SECONDES.saturating_mul(1_000));
        match self
            .entrepot
            .declarer_annuaire(compte, annuaire, adresse, code.empreinte(), expire_a)
        {
            Ok(DeclarationDAnnuaire::Faite) => {
                (self.voie.journal)(&format!(
                    "annuaire local déclaré par {} ({}), en attente de sa clé",
                    compte.texte().as_str(),
                    annuaire.map_or("annuaire neuf", |_| "second membre")
                ));
                Trouvaille::CodeEmis {
                    code: code.texte_groupe(),
                    expire_a,
                }
            }
            Ok(DeclarationDAnnuaire::Complet) => Trouvaille::Conflit,
            Ok(DeclarationDAnnuaire::Inconnu) | Err(_) => Trouvaille::Rien,
        }
    }

    /// `DELETE /v1/annuaires/{n}` et `…/membres/{n2}` — par le propriétaire,
    /// ou par un administrateur des racines.
    pub(super) fn retirer_un_annuaire(
        &self,
        annuaire: Identifiant,
        membre: Identifiant,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(lu)) = self.entrepot.membre_d_annuaire(membre) else {
            return Trouvaille::Rien;
        };
        if lu.annuaire != annuaire
            || (lu.proprietaire != compte && !self.administre_les_racines(compte))
        {
            return Trouvaille::Rien;
        }
        match self.entrepot.retirer_un_membre(membre, compte) {
            Ok(true) => {
                (self.voie.journal)(&format!(
                    "annuaire local : membre {} retiré par {}",
                    membre.texte().as_str(),
                    compte.texte().as_str()
                ));
                Trouvaille::Fait
            }
            _ => Trouvaille::Rien,
        }
    }

    /// `POST /v1/annuaires/inscription` — un annuaire présente son code avec
    /// sa clé. **La limite de débit garde la porte**, avant tout regard sur
    /// le code : un code de cinquante bits ne se tient que si l'on ne peut pas
    /// en essayer mille.
    pub(super) fn presenter_une_inscription(
        &mut self,
        empreinte: [u8; asl_cle::EMPREINTE_OCTETS],
        cle: &ClePublique,
    ) -> Trouvaille {
        let adresse = self.vu_depuis.adresse;
        let maintenant_ms = maintenant().saturating_div(1_000);
        if self.echecs_d_invitation.trop(adresse, maintenant_ms) {
            (self.voie.journal)(&format!(
                "inscription refusée : trop d'essais depuis {adresse}"
            ));
            return Trouvaille::TropDEssais;
        }
        let membre = asl_cle::identifiant_de_racine(cle);
        match self
            .entrepot
            .presenter_un_code(empreinte, membre, cle.octets(), maintenant_ms)
        {
            Ok(PresentationDeCode::Faite(lu)) => {
                (self.voie.journal)(&format!(
                    "annuaire local {} présenté pour {} : {}",
                    membre.texte().as_str(),
                    lu.proprietaire.texte().as_str(),
                    lu.etat.mot()
                ));
                encoder_un_membre(&lu, false).map_or(Trouvaille::Rien, Trouvaille::InscriptionLue)
            }
            Ok(PresentationDeCode::Inconnu) => {
                self.echecs_d_invitation.echec(adresse, maintenant_ms);
                Trouvaille::Rien
            }
            Ok(PresentationDeCode::Expire) => {
                self.echecs_d_invitation.echec(adresse, maintenant_ms);
                Trouvaille::Refus
            }
            Ok(PresentationDeCode::Deja) => Trouvaille::Conflit,
            Err(_) => Trouvaille::Rien,
        }
    }

    /// `POST /v1/annuaires/etat` — un annuaire relit son inscription.
    pub(super) fn lire_l_etat_d_une_inscription(&self, cle: &ClePublique) -> Trouvaille {
        let membre = asl_cle::identifiant_de_racine(cle);
        match self.entrepot.membre_d_annuaire(membre) {
            Ok(Some(lu)) if lu.cle == cle.octets() => {
                encoder_un_membre(&lu, false).map_or(Trouvaille::Rien, Trouvaille::InscriptionLue)
            }
            _ => Trouvaille::Rien,
        }
    }

    /// `GET /v1/inscriptions` — ce qui attend, pour un administrateur des
    /// racines ; `404` pour les autres.
    pub(super) fn rassembler_les_inscriptions_en_attente(&self) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        if !self.administre_les_racines(compte) {
            return Trouvaille::Rien;
        }
        let Ok(membres) = self.entrepot.inscriptions_en_attente() else {
            return Trouvaille::Rien;
        };
        Trouvaille::Inscriptions(
            membres
                .iter()
                .filter_map(|lu| encoder_un_membre(lu, true))
                .collect(),
        )
    }

    /// `POST /v1/inscriptions/{n}/decision` — un administrateur tranche.
    pub(super) fn decider_d_une_inscription(
        &self,
        membre: Identifiant,
        accepte: bool,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        if !self.administre_les_racines(compte) {
            return Trouvaille::Rien;
        }
        match self
            .entrepot
            .decider_d_une_inscription(membre, accepte, compte)
        {
            Ok(DecisionDInscription::Faite) => {
                (self.voie.journal)(&format!(
                    "inscription de {} {} par {}",
                    membre.texte().as_str(),
                    if accepte { "acceptée" } else { "refusée" },
                    compte.texte().as_str()
                ));
                Trouvaille::Fait
            }
            Ok(DecisionDInscription::Tranchee) => Trouvaille::Conflit,
            Ok(DecisionDInscription::Inconnu) | Err(_) => Trouvaille::Rien,
        }
    }

    /// `PUT` / `DELETE /v1/domaines/{d}/hebergeur` — le propriétaire confie
    /// son domaine à SON annuaire accepté, ou le rend aux racines.
    pub(super) fn confier_un_domaine(
        &self,
        domaine: Identifiant,
        annuaire: Option<Identifiant>,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        if !self
            .entrepot
            .domaine(domaine)
            .ok()
            .flatten()
            .is_some_and(|rangee| rangee.proprietaire == compte)
        {
            return Trouvaille::Rien;
        }
        if let Some(voulu) = annuaire {
            let accepte = self
                .entrepot
                .membre_d_annuaire(voulu)
                .ok()
                .flatten()
                .is_some_and(|lu| {
                    lu.titulaire()
                        && lu.etat == EtatDInscription::Acceptee
                        && lu.proprietaire == compte
                });
            if !accepte {
                return Trouvaille::Rien;
            }
        }
        match self.entrepot.confier_domaine(domaine, annuaire) {
            Ok(()) => Trouvaille::Fait,
            Err(_) => Trouvaille::Rien,
        }
    }
}
