//! Les domaines, à l'étage 3 (`protocole.md` §2.2, `docs/modele.md` §2.11,
//! 2026-09-26) : lire l'entrepôt, demander à `asl-auth`, écrire.
//!
//! # QUI GÈRE UN DOMAINE — SES ADMINISTRATEURS, DEPUIS LES GROUPES
//!
//! Depuis la 0.24.0 (`docs/modele.md` §2.12), **un domaine se gère par les
//! membres de son groupe d'administrateurs** — le propriétaire en est d'office
//! et ne s'en retire pas —, et depuis la 0.25.0 par ceux d'un groupe qui a
//! reçu `administrer` sur lui (`docs/modele.md` §2.13). Eux posent l'alias,
//! créent les groupes, en changent les membres, accordent des droits sur lui.
//! **Le propriétaire seul le supprime.** Ranger SA machine demande
//! `rattacher`, qu'`administrer` emporte ; le voir demande `voir`, que
//! `localiser` et `administrer` emportent.
//!
//! Le **domaine racine** n'a pas d'enregistrement : il se déduit, et son
//! propriétaire est le premier administrateur des racines nommé. Il n'a ni
//! alias, ni machine, et ne se supprime pas.

use asl_id::{Genre, Identifiant};
use asl_registre::{AliasDeDomaine, AliasDeMachine};
use asl_session::Trouvaille;
use asl_store::SuppressionDeDomaine;

use super::{Service, alloc_reponse};

impl Service<'_> {
    /// Le compte au nom duquel cette connexion agit, sur l'une OU l'autre voie :
    /// l'appareil vivant qui a prouvé sa clé, ou la machine qui a prouvé la
    /// sienne — celle-ci pour son propriétaire.
    fn compte_de_l_une_ou_l_autre_voie(&self) -> Option<Identifiant> {
        if let Some(compte) = self.compte_de_la_connexion() {
            return Some(compte);
        }
        let machine = self.session.machine()?;
        self.entrepot
            .machine(machine)
            .ok()
            .flatten()
            .map(|rangee| rangee.proprietaire)
    }

    /// `GET /v1/domaines` — les domaines vivants que je possède, **puis ceux
    /// où l'un de mes groupes tient un droit** sans les posséder — administrés
    /// compris —, le domaine racine compris si je suis l'un des
    /// administrateurs des racines.
    pub(super) fn rassembler_mes_domaines(&self) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(domaines) = self.entrepot.domaines_de_compte(compte) else {
            return Trouvaille::Rien;
        };
        let Ok(administres) = self.entrepot.domaines_ou_j_ai_un_droit(compte) else {
            return Trouvaille::Rien;
        };
        let mut elements: Vec<Vec<u8>> = domaines
            .into_iter()
            .filter_map(|(domaine, _)| self.rendre_un_domaine(compte, domaine))
            .collect();
        elements.extend(
            administres
                .into_iter()
                .filter_map(|domaine| self.rendre_un_domaine(compte, domaine)),
        );
        Trouvaille::Domaines(elements)
    }

    /// Ce qu'on rend d'un domaine où l'on tient un droit : son propriétaire, son
    /// alias, ce qu'on peut sur lui — **la réunion** que l'entrepôt calcule.
    /// Rien si l'on n'y peut rien.
    fn rendu_d_un_domaine(
        &self,
        compte: Identifiant,
        domaine: Identifiant,
    ) -> Option<(Identifiant, Option<AliasDeDomaine>, &'static [&'static str])> {
        if domaine == asl_registre::domaine_racine() {
            let (membres, premier) = self.entrepot.administrateurs_des_racines().ok()?;
            if !membres.contains(&compte) {
                return None;
            }
            return Some((
                premier?,
                None,
                &asl_api::domaine::DROITS_SUR_LE_DOMAINE_RACINE,
            ));
        }
        let rangee = self.entrepot.domaine(domaine).ok().flatten()?;
        let droits = self.entrepot.droits_sur_domaine(compte, domaine).ok()?;
        if droits.est_vide() {
            return None;
        }
        let alias = self.entrepot.alias_de_domaine(domaine).ok().flatten();
        Some((rangee.proprietaire, alias, droits.noms()))
    }

    /// Un domaine de la liste, encodé.
    fn rendre_un_domaine(&self, compte: Identifiant, domaine: Identifiant) -> Option<Vec<u8>> {
        let (proprietaire, alias, droits) = self.rendu_d_un_domaine(compte, domaine)?;
        let rendu = asl_api::domaine::DomaineRendu {
            domaine,
            proprietaire,
            heberge_par: self.entrepot.hebergeur_de_domaine(domaine).ok().flatten(),
            alias: alias.as_ref().map(AliasDeDomaine::texte),
            droits,
        };
        let mut sortie = alloc_reponse();
        let combien = rendu.encoder(&mut sortie).ok()?;
        sortie.truncate(combien);
        Some(sortie)
    }

    /// `POST /v1/domaines` — un domaine de plus à mon compte.
    pub(super) fn creer_un_domaine(&self, alias: Option<AliasDeDomaine>) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Some(domaine) = self.un_identifiant(Genre::Domaine) else {
            return Trouvaille::Rien;
        };
        match self.entrepot.creer_domaine(domaine, compte, alias) {
            Ok(true) => Trouvaille::DomaineCree(domaine),
            Ok(false) | Err(_) => Trouvaille::Rien,
        }
    }

    /// `GET /v1/domaines?alias=…` — tous les domaines vivants qui portent cet
    /// alias. **Une liste, toujours**, et rien d'autre que l'identifiant et
    /// l'annuaire qui fait autorité : ni propriétaire, ni machine.
    pub(super) fn chercher_des_domaines(&self, alias: &AliasDeDomaine) -> Trouvaille {
        // **TOUT COMPTE AUTHENTIFIÉ** : une connexion qui a prouvé une clé
        // révoquée depuis ne cherche plus rien.
        if self.compte_de_l_une_ou_l_autre_voie().is_none() {
            return Trouvaille::Rien;
        }
        let Ok(trouves) = self.entrepot.domaines_par_alias(alias) else {
            return Trouvaille::Rien;
        };
        let elements = trouves
            .into_iter()
            .filter_map(|domaine| {
                let mut sortie = alloc_reponse();
                // **L'AUTORITÉ SE LIT COMME `heberge_par`** : par le même
                // chemin, pour que la recherche et `GET /v1/domaines` ne se
                // contredisent jamais sur un même domaine.
                let autorite = self.entrepot.hebergeur_de_domaine(domaine).ok()?;
                let combien = asl_api::domaine::DomaineTrouve { domaine, autorite }
                    .encoder(&mut sortie)
                    .ok()?;
                sortie.truncate(combien);
                Some(sortie)
            })
            .collect();
        Trouvaille::Domaines(elements)
    }

    /// Le domaine vivant que ce compte gère — il en est le propriétaire, ou
    /// membre de son groupe d'administrateurs —, ou rien. **Absent et
    /// interdit se confondent** (C10). Jamais le domaine racine, qui n'a pas
    /// d'enregistrement.
    pub(super) fn domaine_gere(
        &self,
        compte: Identifiant,
        domaine: Identifiant,
    ) -> Option<asl_registre::Domaine> {
        let rangee = self.entrepot.domaine(domaine).ok().flatten()?;
        self.entrepot
            .administre(compte, domaine)
            .ok()?
            .then_some(rangee)
    }

    /// `GET /v1/domaines/{d}` — le domaine, ce qui y est rangé pour qui a
    /// `voir`, et ses groupes pour qui l'administre.
    pub(super) fn lire_un_domaine(&self, domaine: Identifiant) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Some((proprietaire, alias, droits)) = self.rendu_d_un_domaine(compte, domaine) else {
            return Trouvaille::Rien;
        };
        let administre = droits.contains(&"administrer");
        let voit = administre || droits.contains(&"voir");
        let groupes = if administre {
            self.entrepot
                .groupes_du_domaine(domaine)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let groupes_rendus: Vec<asl_api::groupe::GroupeRendu<'_>> = groupes
            .iter()
            .map(|lu| asl_api::groupe::GroupeRendu {
                groupe: lu.groupe,
                domaine: lu.domaine,
                etiquette: lu
                    .etiquette
                    .as_ref()
                    .and_then(|texte| core::str::from_utf8(texte.octets()).ok()),
                sorte: lu.sorte.nom(),
            })
            .collect();
        let machines: Vec<(
            Identifiant,
            asl_registre::Machine,
            Option<asl_registre::AliasDeMachine>,
        )> = if voit {
            self.entrepot
                .machines_du_domaine(domaine)
                .unwrap_or_default()
        } else {
            Vec::new()
        }
        .into_iter()
        .filter_map(|machine| {
            let rangee = self.entrepot.machine(machine).ok().flatten()?;
            let alias = self.entrepot.alias_de_machine(machine).ok().flatten();
            Some((machine, rangee, alias))
        })
        .collect();
        // **LE NOM, POUR QUI A `voir` SUR LE DOMAINE** — ses administrateurs,
        // et ceux qui ont reçu `voir` ou `localiser` : ils voient le nom de
        // tout ce qui y est rangé, y compris ce qu'un autre y a rattaché
        // (`protocole.md` §2.2).
        let vues: Vec<asl_api::domaine::MachineDeDomaine<'_>> = machines
            .iter()
            .map(
                |(machine, rangee, alias)| asl_api::domaine::MachineDeDomaine {
                    machine: *machine,
                    proprietaire: rangee.proprietaire,
                    nom: core::str::from_utf8(rangee.nom.octets()).ok(),
                    alias: alias.as_ref().map(asl_registre::AliasDeMachine::texte),
                },
            )
            .collect();
        let detaille = asl_api::domaine::DomaineDetaille {
            domaine: asl_api::domaine::DomaineRendu {
                domaine,
                proprietaire,
                heberge_par: self.entrepot.hebergeur_de_domaine(domaine).ok().flatten(),
                alias: alias.as_ref().map(AliasDeDomaine::texte),
                droits,
            },
            groupes: &groupes_rendus,
            machines: &vues,
        };
        let mut sortie = alloc_reponse();
        match detaille.encoder(&mut sortie) {
            Ok(combien) => {
                sortie.truncate(combien);
                Trouvaille::DomaineLu(sortie)
            }
            Err(_) => Trouvaille::Rien,
        }
    }

    /// `DELETE /v1/domaines/{d}` — jamais le dernier, et **par son
    /// propriétaire seul** (`docs/modele.md` §2.11) : un administrateur qui
    /// ne le possède pas le voit, et le trouve absent pour ce verbe.
    pub(super) fn supprimer_un_domaine(&self, domaine: Identifiant) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        if self
            .domaine_gere(compte, domaine)
            .is_none_or(|rangee| rangee.proprietaire != compte)
        {
            return Trouvaille::Rien;
        }
        match self.entrepot.supprimer_domaine(domaine) {
            Ok(SuppressionDeDomaine::Faite) => Trouvaille::Fait,
            Ok(SuppressionDeDomaine::Derniere) => Trouvaille::Conflit,
            Ok(SuppressionDeDomaine::Absent) | Err(_) => Trouvaille::Rien,
        }
    }

    /// `PUT` / `DELETE /v1/domaines/{d}/alias`.
    pub(super) fn poser_l_alias_de_domaine(
        &self,
        domaine: Identifiant,
        alias: Option<AliasDeDomaine>,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        // **LE DOMAINE RACINE N'A PAS DE RANGÉE** (décision 43) : `domaine_gere`
        // ne le trouve pas. Ses administrateurs — le groupe des
        // administrateurs des racines — y posent un alias comme ailleurs.
        let gere = if domaine == asl_registre::domaine_racine() {
            self.entrepot.administre(compte, domaine).unwrap_or(false)
        } else {
            self.domaine_gere(compte, domaine).is_some()
        };
        if !gere {
            return Trouvaille::Rien;
        }
        match self.entrepot.poser_alias_de_domaine(domaine, alias) {
            Ok(true) => Trouvaille::Fait,
            Ok(false) | Err(_) => Trouvaille::Rien,
        }
    }

    /// `PUT` / `DELETE /v1/machines/{m}/domaine`.
    ///
    /// # DEUX PROPRIÉTÉS, ET CHACUNE A SON REFUS
    ///
    /// **La machine doit être à moi** — sinon `404`, comme tout verbe sur une
    /// machine qu'on ne possède pas : dire « elle n'est pas à vous »
    /// confirmerait qu'elle existe. **Le domaine doit être un de ceux où je
    /// peux ranger** — sinon `403` s'il existe (`protocole.md` §2.2 : « `403`
    /// sans le droit »), et `404` s'il n'existe pas ou plus. On ne range que
    /// ce qu'on possède, quel que soit le droit qu'on tient
    /// (`docs/modele.md` §2.11).
    pub(super) fn rattacher_une_machine(
        &self,
        machine: Identifiant,
        domaine: Option<Identifiant>,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(rangee)) = self.entrepot.machine(machine) else {
            return Trouvaille::Rien;
        };
        if asl_auth::decider_gestion(compte, rangee.proprietaire) == asl_auth::Decision::Refuser {
            return Trouvaille::Rien;
        }
        if let Some(quel) = domaine {
            if self.entrepot.domaine(quel).ok().flatten().is_none() {
                return Trouvaille::Rien;
            }
            // **RANGER DEMANDE `rattacher`** — qu'`administrer` emporte : le
            // propriétaire, un membre de son groupe d'administrateurs, ou un
            // groupe qui a reçu l'un ou l'autre (`docs/modele.md` §2.13).
            if !self.entrepot.peut_ranger(compte, quel).unwrap_or(false) {
                return Trouvaille::Refus;
            }
        }
        match self.entrepot.rattacher_machine(machine, domaine) {
            Ok(true) => Trouvaille::Fait,
            Ok(false) | Err(_) => Trouvaille::Rien,
        }
    }

    /// `PUT` / `DELETE /v1/machines/{m}/alias` (0.26.0).
    ///
    /// **Le propriétaire de la machine, et lui seul** : l'alias dit comment
    /// on la nomme, pas où elle est rangée, et ranger une machine dans un
    /// domaine confie à ses administrateurs le droit de la PARTAGER
    /// (décision 40), pas de la renommer. Pour tout autre compte, `404` —
    /// dire « elle n'est pas à vous » confirmerait qu'elle existe.
    pub(super) fn poser_l_alias_de_machine(
        &self,
        machine: Identifiant,
        alias: Option<AliasDeMachine>,
    ) -> Trouvaille {
        let Some(compte) = self.compte_de_la_connexion() else {
            return Trouvaille::Rien;
        };
        let Ok(Some(rangee)) = self.entrepot.machine(machine) else {
            return Trouvaille::Rien;
        };
        if asl_auth::decider_gestion(compte, rangee.proprietaire) == asl_auth::Decision::Refuser {
            return Trouvaille::Rien;
        }
        match self.entrepot.poser_alias_de_machine(machine, alias) {
            Ok(true) => Trouvaille::Fait,
            Ok(false) | Err(_) => Trouvaille::Rien,
        }
    }
}
