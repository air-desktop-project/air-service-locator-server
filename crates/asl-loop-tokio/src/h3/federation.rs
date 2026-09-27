//! La voie de l'annuaire local, côté racine (`protocole.md` §3 ter ;
//! `docs/annuaires.md` §2 bis, §5.4 ; 0.28.0) : qui l'ouvre, ce qu'on lui
//! rend, ce qu'on range de lui, et la machine qu'on renvoie chez lui.
//!
//! # CE QU'UN ANNUAIRE LOCAL PEUT, ET RIEN DE PLUS (C11)
//!
//! Il est cru sur **les services des machines rattachées aux domaines qu'il
//! héberge**, et sur rien d'autre. Chaque rapport est vérifié entrée par
//! entrée contre cet ensemble, recalculé à la requête : une machine détachée,
//! un domaine rendu aux racines, une inscription retirée entre deux rapports,
//! et ce qu'il en dit n'est plus rangé. Une entrée hors de son périmètre
//! refuse le rapport ENTIER, et se journalise : c'est un défaut ou une
//! attaque, et les deux méritent d'être vus.

use asl_id::Identifiant;
use asl_registre::{Adresse, EntreeDEtat, MACHINE_FEDEREE_OCTETS, MachineFederee};
use asl_session::Trouvaille;
use asl_store::{EtatDInscription, MembreLu};

use super::{Service, maintenant};
use crate::federation::MACHINES_PAR_PART;

impl Service<'_> {
    /// Le membre accepté que cette connexion représente, lu MAINTENANT.
    ///
    /// **Relu à chaque requête** : une inscription retirée ou refusée entre la
    /// preuve et la demande ne sert plus rien — `404`.
    fn membre_accepte(&self) -> Option<MembreLu> {
        let membre = self.session.annuaire_local()?;
        self.entrepot
            .membre_d_annuaire(membre)
            .ok()
            .flatten()
            .filter(|lu| lu.etat == EtatDInscription::Acceptee)
    }

    /// Les machines rattachées aux domaines que cet annuaire héberge, rangées
    /// par identifiant, sans doublon.
    fn machines_hebergees(&self, lu: &MembreLu) -> Option<Vec<Identifiant>> {
        let mut machines = Vec::new();
        for (domaine, _) in self.entrepot.domaines_de_compte(lu.proprietaire).ok()? {
            if self.entrepot.hebergeur_de_domaine(domaine).ok()? != Some(lu.annuaire) {
                continue;
            }
            for machine in self.entrepot.machines_du_domaine(domaine).ok()? {
                if !machines.contains(&machine) {
                    machines.push(machine);
                }
            }
        }
        machines.sort_by_key(|machine| *machine.octets());
        Some(machines)
    }

    /// `GET /v1/federation/machines?apres=<rang>` — une part des machines de
    /// nos domaines, à partir de ce rang.
    pub(super) fn rassembler_les_machines_federees(&self, apres: u64) -> Trouvaille {
        let Some(lu) = self.membre_accepte() else {
            return Trouvaille::Rien;
        };
        let Some(machines) = self.machines_hebergees(&lu) else {
            return Trouvaille::Rien;
        };
        let debut = usize::try_from(apres).unwrap_or(usize::MAX);
        let mut corps = Vec::new();
        for machine in machines.into_iter().skip(debut).take(MACHINES_PAR_PART) {
            let Ok(Some(enregistrement)) = self.entrepot.machine(machine) else {
                continue;
            };
            let mut octets = [0_u8; MACHINE_FEDEREE_OCTETS];
            MachineFederee {
                machine,
                enregistrement,
            }
            .ecrire(&mut octets);
            corps.extend_from_slice(&octets);
        }
        Trouvaille::MachinesFederees(corps)
    }

    /// `POST /v1/federation/etat` — ce que cet annuaire dit de ses services.
    pub(super) fn ranger_un_etat_federe(&mut self, entrees: &[u8]) -> Trouvaille {
        let Some(lu) = self.membre_accepte() else {
            return Trouvaille::Rien;
        };
        let Some(machines) = self.machines_hebergees(&lu) else {
            return Trouvaille::Rien;
        };
        // **TOUT OU RIEN** : on lit d'abord le rapport entier, et une entrée
        // hors du périmètre le refuse avant qu'on ait rangé quoi que ce soit.
        let mut lues = Vec::new();
        let mut reste = entrees;
        while !reste.is_empty() {
            let Ok((entree, occupe)) = EntreeDEtat::lire(reste) else {
                return Trouvaille::Rien;
            };
            if !machines.contains(&entree.machine) {
                (self.voie.journal)(&format!(
                    "fédération : {} rapporte un service de {}, qui n'est dans aucun domaine \
                     qu'il héberge — rapport refusé (C11)",
                    lu.membre, entree.machine
                ));
                return Trouvaille::Refus;
            }
            lues.push(entree);
            reste = reste.get(occupe..).unwrap_or_default();
        }
        let maintenant = maintenant();
        for entree in &lues {
            self.etat_federe.ranger(lu.membre, entree, maintenant);
        }
        Trouvaille::Fait
    }

    /// `PUT /v1/federation/locateurs` — où joindre cet annuaire, dit par lui
    /// (décision 57). Le corps a été lu une fois par `asl-session` ; il se
    /// relit ici.
    pub(super) fn publier_mes_locateurs(&self, corps: &[u8]) -> Trouvaille {
        let Some(lu) = self.membre_accepte() else {
            return Trouvaille::Rien;
        };
        let Ok(publication) = asl_api::annuaire::PublicationDeLocateurs::decoder(corps) else {
            return Trouvaille::Rien;
        };
        let mut adresses = Vec::new();
        for locateur in publication.locateurs() {
            let Ok(adresse) = Adresse::nouvelle(locateur) else {
                return Trouvaille::Rien;
            };
            adresses.push(adresse);
        }
        match self.entrepot.publier_locateurs(lu.membre, &adresses) {
            Ok(true) => Trouvaille::Fait,
            Ok(false) | Err(_) => Trouvaille::Rien,
        }
    }

    /// Cette machine appartient-elle à un domaine confié à un annuaire local ?
    /// Si oui, le corps du `421` : l'annuaire, et où joindre ses membres
    /// acceptés — les locateurs que chacun a publiés, ou son adresse
    /// déclarée (décision 57).
    pub(super) fn annonce_mal_adressee(&self, machine: Identifiant) -> Option<Vec<u8>> {
        let domaine = self.entrepot.domaine_de_machine(machine).ok()??;
        let annuaire = self.entrepot.hebergeur_de_domaine(domaine).ok()??;
        let proprietaire = self
            .entrepot
            .membre_d_annuaire(annuaire)
            .ok()??
            .proprietaire;
        let (membres, _) = self
            .entrepot
            .annuaires_du_compte(proprietaire, maintenant().saturating_div(1_000))
            .ok()?;
        // **CHAQUE ADRESSE AVEC L'IDENTITÉ DE SON MEMBRE** (décision 59) : le
        // second d'une paire a sa clé, et c'est elle qu'un client doit trouver
        // au bout. Les adresses sont de l'ASCII sans guillemet ni barre — la
        // règle d'`asl_registre::Adresse` à la déclaration —, elles se posent
        // telles quelles dans le JSON.
        let adresses: Vec<(Adresse, Identifiant)> = membres
            .iter()
            .filter(|lu| lu.annuaire == annuaire && lu.etat == EtatDInscription::Acceptee)
            .flat_map(|lu| {
                lu.ou_joindre()
                    .into_iter()
                    .map(move |adresse| (adresse, lu.membre))
            })
            .collect();
        let textes: Vec<(&str, Identifiant)> = adresses
            .iter()
            .map(|(adresse, membre)| (adresse.texte(), *membre))
            .collect();
        let mut corps = vec![0_u8; 256_usize.saturating_add(textes.len().saturating_mul(300))];
        let combien = asl_api::annuaire::RenvoiRendu {
            annuaire,
            adresses: &textes,
        }
        .encoder(&mut corps)
        .ok()?;
        corps.truncate(combien);
        Some(corps)
    }
}
