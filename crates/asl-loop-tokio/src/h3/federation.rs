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

    /// [`Self::membre_accepte`], **et la voie de ce membre notée ouverte**
    /// (0.38.0, décision 86) : chacun des quatre verbes de sa voie est une
    /// parole — le fédérateur en dit au moins deux par tour, toutes les dix
    /// secondes. C'est ce qui fait vivre l'`asl-directory` et que
    /// `GET /v1/annuaires` dit par `voie`.
    fn membre_qui_parle(&mut self) -> Option<MembreLu> {
        let lu = self.membre_accepte()?;
        self.etat_federe
            .noter_une_parole(lu.membre, &self.connexion, maintenant());
        Some(lu)
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
    pub(super) fn rassembler_les_machines_federees(&mut self, apres: u64) -> Trouvaille {
        let Some(lu) = self.membre_qui_parle() else {
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
        let Some(lu) = self.membre_qui_parle() else {
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
        // **LE NOM SE RANGE, JAMAIS L'ADRESSE** (0.40.0, décision 100) : au
        // premier rapport d'un service, les racines en déclarent la ligne —
        // machine, nom, `s-…` dérivé —, comme pour un service qu'on leur
        // annonce, et elle se réplique comme toute opération `service`. C'est
        // ce qui fait marcher un droit « Un service » sur lui. **Elle se garde
        // pour toujours** (décision 102), avec ses droits ; l'état vivant et
        // les adresses restent en mémoire (C13), et c'est le rapport qui les
        // donne (décision 99).
        let nommees = lues
            .iter()
            .filter_map(|entree| Some((entree, core::str::from_utf8(entree.nom.octets()).ok()?)));
        for (entree, nom) in nommees {
            if matches!(self.entrepot.service_par_nom(entree.machine, nom), Ok(None))
                && let Ok(service) = self.entrepot.declarer_service(
                    asl_registre::Provenance::Ici,
                    entree.machine,
                    entree.nom,
                )
            {
                (self.voie.journal)(&format!(
                    "fédération : {} rapporte « {nom} » de {} — nom rangé sous {service} \
                     (décision 100)",
                    lu.membre, entree.machine
                ));
            }
        }
        let vivantes = lues
            .iter()
            .filter(|entree| entree.reponse.is_some())
            .count();
        // **UN MEMBRE D'AVANT LA 0.37.0 SE VOIT ICI** (décision 72) : ses
        // `s-…` ne sont pas les dérivés. La racine rend ce qu'il dit — c'est
        // lui qui tient le daemon —, et le journal dit l'écart.
        let non_derives = lues
            .iter()
            .filter(|entree| {
                entree.service != asl_registre::service_derive(entree.machine, entree.nom.octets())
            })
            .count();
        if self
            .etat_federe
            .noter_un_rapport(lu.membre, lues.len(), vivantes, non_derives)
        {
            (self.voie.journal)(&format!(
                "fédération : {} rapporte {} service(s), dont {vivantes} vivant(s) — accepté{}",
                lu.membre,
                lues.len(),
                if non_derives == 0 {
                    String::new()
                } else {
                    format!(
                        " ; {non_derives} sous un identifiant qui n'est pas le dérivé : ce \
                         membre n'est pas encore en 0.37.0 (décision 72)"
                    )
                }
            ));
        }
        Trouvaille::Fait
    }

    /// `PUT /v1/federation/locateurs` — où joindre cet annuaire, dit par lui
    /// (décision 57). Le corps a été lu une fois par `asl-session` ; il se
    /// relit ici.
    pub(super) fn publier_mes_locateurs(&mut self, corps: &[u8]) -> Trouvaille {
        let Some(lu) = self.membre_qui_parle() else {
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

    /// `PUT /v1/federation/paire` — ce membre dit son `--peer` ; on lui rend
    /// son annuaire et ses membres acceptés (0.36.0, décision 70).
    ///
    /// **C'est lui qui juge**, de ce qu'on lui rend ; on juge ici de la même
    /// façon ([`asl_api::annuaire::EtatDePaire::juger`], les mêmes données),
    /// pour que `GET /v1/annuaires` le montre à l'écran de l'annuaire, et
    /// que le journal de la racine le dise quand cela change.
    pub(super) fn declarer_ma_paire(&mut self, pair: Option<Identifiant>) -> Trouvaille {
        let Some(lu) = self.membre_qui_parle() else {
            return Trouvaille::Rien;
        };
        let Ok((membres, _)) = self
            .entrepot
            .annuaires_du_compte(lu.proprietaire, maintenant().saturating_div(1_000))
        else {
            return Trouvaille::Rien;
        };
        let acceptes: Vec<Identifiant> = membres
            .iter()
            .filter(|autre| {
                autre.annuaire == lu.annuaire && autre.etat == EtatDInscription::Acceptee
            })
            .map(|autre| autre.membre)
            .collect();
        let etat = asl_api::annuaire::EtatDePaire::juger(lu.membre, pair, &acceptes);
        if self.etat_federe.noter_une_paire(lu.membre, etat) {
            (self.voie.journal)(&format!(
                "fédération : {} dit sa paire — {}{}",
                lu.membre,
                etat.mot(),
                if etat.alerte() {
                    " : paire MAL RÉGLÉE (décision 70)"
                } else {
                    ""
                }
            ));
        }
        Trouvaille::Paire(asl_api::annuaire::PaireRendue::nouvelle(
            lu.annuaire,
            &acceptes,
        ))
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

    /// `GET /v1/ou/{n-…}/asl-directory` — ce qu'il faut pour décider
    /// (0.38.0 ; décisions 73 à 87).
    ///
    /// **Synthétisé, rien n'est écrit** : l'annuaire logique est l'inscription
    /// acceptée de son titulaire ; ses membres vivants sont ceux dont la voie
    /// vers CETTE racine est ouverte ([`crate::federation::EtatFedere::voie_de`]),
    /// chacun sous ses locateurs publiés ou, à défaut, son adresse déclarée
    /// — la source du `421`, filtrée aux vivants (décisions 74, 75, 81).
    ///
    /// **Le cercle se lit depuis le DEMANDEUR** (C10) : son compte est-il
    /// administrateur des racines, et que peut-il sur les domaines que cet
    /// annuaire héberge ? `asl-auth` décide ; l'étage 2 rend.
    ///
    /// **Le même travail, que le demandeur soit dans le cercle ou non** (C9) :
    /// le cercle et les vivants sont lus avant toute décision. Seul un
    /// annuaire qui n'existe pas s'arrête plus tôt, comme une résolution de
    /// machine dont la machine n'existe pas (`rassembler`).
    pub(super) fn rassembler_un_annuaire(&self, annuaire: Identifiant) -> Trouvaille {
        let Some(qui) = self.session.machine() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(rangee)) = self.entrepot.machine(qui) else {
            return Trouvaille::Rien;
        };
        let Ok(demandeur) = asl_auth::Machine::nouvelle(
            qui,
            rangee.proprietaire,
            asl_auth::Capacites {
                annonce: rangee.annonce,
                lecture: rangee.lecture,
            },
        ) else {
            return Trouvaille::Rien;
        };
        let administrateur_des_racines = self.administre_les_racines(rangee.proprietaire);

        // **L'ANNUAIRE LOGIQUE, SOUS SON TITULAIRE** : le `n-…` du second
        // membre ne nomme pas l'annuaire, et rend ce que rend l'inexistant.
        let Some(titulaire) = self
            .entrepot
            .membre_d_annuaire(annuaire)
            .ok()
            .flatten()
            .filter(MembreLu::titulaire)
        else {
            return Trouvaille::Rien;
        };
        let proprietaire = titulaire.proprietaire;
        let Ok((membres, _)) = self
            .entrepot
            .annuaires_du_compte(proprietaire, maintenant().saturating_div(1_000))
        else {
            return Trouvaille::Rien;
        };
        let acceptes: Vec<&MembreLu> = membres
            .iter()
            .filter(|lu| lu.annuaire == annuaire && lu.etat == EtatDInscription::Acceptee)
            .collect();
        // **IL EXISTE DÈS QUE L'INSCRIPTION EST ACCEPTÉE**, et disparaît avec
        // elle (décision 74).
        if acceptes.is_empty() {
            return Trouvaille::Rien;
        }

        // **LES DROITS SUR LES DOMAINES HÉBERGÉS, ET SUR EUX SEULS**
        // (décision 79) : `droits_sur_domaine` réunit les droits reçus et
        // l'administration ; un droit sur une machine ou un service n'y entre
        // pas.
        let mut droits = asl_registre::Droits::AUCUN;
        for (domaine, _) in self
            .entrepot
            .domaines_de_compte(proprietaire)
            .unwrap_or_default()
        {
            if self.entrepot.hebergeur_de_domaine(domaine).ok().flatten() == Some(annuaire) {
                droits = droits.union(
                    self.entrepot
                        .droits_sur_domaine(rangee.proprietaire, domaine)
                        .unwrap_or(asl_registre::Droits::AUCUN),
                );
            }
        }

        let maintenant = maintenant();
        let vivants = acceptes
            .iter()
            .filter(|lu| {
                self.etat_federe
                    .voie_de(lu.membre, maintenant, self.expiration_federee_us)
                    == Some(asl_api::annuaire::EtatDeVoie::Ouverte)
            })
            .flat_map(|lu| {
                lu.ou_joindre()
                    .into_iter()
                    .map(move |adresse| (adresse.texte().to_owned(), lu.membre))
            })
            .collect();

        Trouvaille::ResolutionDAnnuaire(asl_session::ResolutionDAnnuaire {
            demandeur,
            cercle: asl_auth::CercleDAnnuaire {
                proprietaire,
                administrateur_des_racines,
                voir: droits.permettent_de_voir(),
                localiser: droits.permettent_de_localiser(),
            },
            annuaire,
            vivants,
        })
    }

    /// Cette annonce porte-t-elle le nom réservé (décision 73) ? Rend la
    /// machine qui l'a tentée — le journal la nomme.
    ///
    /// **Avant tout le reste** : une machine d'un domaine confié reçoit ce
    /// `403` plutôt que le `421`, puisque l'annuaire local la refuserait de
    /// même. Un corps illisible ne dit rien ici, et suit son chemin d'hier.
    pub(super) fn annonce_reservee(&self) -> Option<Identifiant> {
        let qui = self.session.machine()?;
        let mut tampons = asl_proto::cadrage::Tampons::nouveaux();
        let annonce = asl_proto::Annonce::decoder(&self.corps, &mut tampons).ok()?;
        annonce.service.reserve().then_some(qui)
    }
}
