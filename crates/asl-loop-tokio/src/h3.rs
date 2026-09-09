//! L'application HTTP/3 : elle relie la boucle QUIC à ce qui décide.
//!
//! # ELLE NE DÉCIDE RIEN, ET C'EST LA TROISIÈME FOIS QU'ON LE DIT
//!
//! `asl-session` décide de la réponse — statut, corps, champs — et le fait
//! **sans entrée-sortie**, sous le régime de couverture. `ams-h3` sait quel flux
//! ouvrir et dans quel ordre. Ce module ne fait que les présenter l'un à
//! l'autre, connexion par connexion.
//!
//! # C'EST ICI QUE LE BESOIN EST SATISFAIT, ET NULLE PART AILLEURS
//!
//! `asl-session` ne lit pas l'entrepôt : elle dit ce qu'il lui faut
//! (`besoin`), et répond quand on le lui apporte (`repondre`). **L'entre-deux
//! est ici**, parce que c'est le seul étage qui a le droit d'attendre.
//!
//! Ce n'est pas un détour : `ams_h3::Service::serve` doit rendre une réponse
//! SYNCHRONE, donc quelqu'un doit tenir les deux bouts. Que ce soit l'étage 3
//! est ce qui garde à l'étage 2 sa propriété — **il ne peut pas attendre, parce
//! qu'il n'a personne à appeler.**
//!
//! # UNE SESSION PAR CONNEXION, ET C'EST LE BAIL QUI L'EXIGE
//!
//! `asl_session::Session` portera la machine authentifiée : la connexion QUIC
//! **est** le bail, et ce qu'une requête a le droit de faire dépend de qui a
//! signé le défi au début de CETTE connexion-là. Une session partagée entre
//! connexions ferait hériter une requête des droits d'une autre — c'est la
//! faille qu'on ne peut pas se permettre.
//!
//! Elle est donc rangée avec le conducteur, sous l'identifiant local de la
//! connexion, et les deux disparaissent ensemble.

use std::collections::HashMap;
use std::net::SocketAddr;

use ams_h3::{Http3, Reponse};
use ams_proto_http::RequestHead;
use ams_proto_quic::StreamId;
use ams_quic_tls::Connection;
use asl_cle::{ClePublique, Defi, LiaisonDeCanal};
use asl_id::Identifiant;
use asl_session::{Besoin, Resolution, Session, Trouvaille};
use asl_store::Entrepot;

use crate::sonde::{self, Verdict};
use crate::vivier::Vivier;

use crate::pont::Pont;
use crate::quic::{Application, maintenant};

/// Ce qu'on tient pour une connexion vivante.
struct ParConnexion {
    /// Le conducteur HTTP/3 : flux de contrôle, QPACK, cadrage.
    conducteur: Http3,
    /// Ce qui décide des réponses de CETTE connexion.
    session: Session,
}

/// Ce qui sert une requête : la session décide, l'entrepôt fournit.
///
/// # POURQUOI CE TYPE EXISTE
///
/// `ams_h3::Service` veut un seul objet ; le travail en demande deux. Celui-ci
/// les tient le temps d'une requête, et **c'est lui qui fait le voyage à
/// l'entrepôt** — entre `besoin` et `repondre`, là où l'étage 2 ne peut pas
/// aller.
struct Service<'a> {
    /// Ce qui décide.
    session: &'a mut Session,
    /// Ce que l'annuaire exige d'un appareil qui s'enrôle.
    politique: asl_auth::Politique,
    /// Ce qui se souvient.
    entrepot: &'a Entrepot,
    /// Ce qui vit.
    vivier: &'a mut Vivier,
    /// L'identifiant local de la connexion, pour attribuer les annonces.
    connexion: Vec<u8>,
    /// De quoi tirer un identifiant de service, si l'annonce en crée un.
    tirer_un_identifiant: &'a (dyn Fn() -> Option<[u8; 16]> + Send + Sync),
    /// Le corps de la requête, pour l'annonce qui doit le décoder.
    corps: Vec<u8>,
    /// Par où les sondes rapportent.
    rapports: tokio::sync::mpsc::UnboundedSender<Verdict>,
    /// Combien de sondes sont en vol, pour ne pas en lancer sans fin.
    en_vol: &'a mut usize,
    /// D'où l'on VOIT ce pair.
    ///
    /// **C'est le seul fait qu'on ait constaté plutôt qu'entendu**, et c'est ce
    /// qui permet le verdict de NAT : `asl-annuaire` compare cette adresse à
    /// celles que le daemon annonce.
    vu_depuis: asl_proto::VuDepuis,
    /// De quoi tirer un défi, si le noyau en a donné.
    ///
    /// **L'ENTROPIE EST UNE ENTRÉE-SORTIE**, donc elle est ici et pas à
    /// l'étage 2. Le défi est tiré à chaque requête, qu'il serve ou non : le
    /// tirer paresseusement demanderait de savoir d'avance si la session en
    /// aura besoin, ce qui est précisément ce qu'elle seule sait.
    ///
    /// **`None` QUAND LE NOYAU A REFUSÉ**, et surtout pas un défi de repli : un
    /// défi prévisible ne défie personne, et se replier en silence serait pire
    /// que de rendre l'erreur. `asl-session` répond alors `500`.
    defi: Option<Defi>,
}

impl ams_h3::Service for Service<'_> {
    fn serve<'o>(
        &mut self,
        tete: &RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Reponse<'o> {
        let besoin = asl_session::besoin(self.session, tete, corps);
        self.corps = corps.to_vec();
        let trouvaille = self.chercher(&besoin);
        asl_session::repondre(self.session, &besoin, &trouvaille, self.defi, sortie)
    }
}

impl Service<'_> {
    /// Va chercher ce que la session a demandé.
    ///
    /// # UNE FAUTE DE L'ENTREPÔT REND `Rien`, ET IL FAUT LE DIRE
    ///
    /// Une base qui refuse et un compte qui n'existe pas donnent la même
    /// réponse : `404`. **Ce n'est pas satisfaisant**, et c'est délibéré tant
    /// qu'il n'y a pas de journal d'exploitation : distinguer les deux dans la
    /// RÉPONSE dirait à un inconnu que notre base a un problème, et c'est
    /// précisément ce qu'on ne veut pas lui apprendre. La distinction ira au
    /// journal, quand il existera.
    fn chercher(&mut self, besoin: &Besoin<'_>) -> Trouvaille {
        match besoin {
            Besoin::Deja(_) | Besoin::DefiATirer => Trouvaille::Rien,

            // **C'EST ICI QUE L'ANNONCE VIT.** Voir `annoncer`.
            Besoin::Annoncer => self
                .annoncer()
                .map_or(Trouvaille::Rien, Trouvaille::Annoncee),

            // **LA CLÉ VIENT DE L'ENREGISTREMENT DE LA MACHINE**, et rien
            // d'autre : une machine inconnue, une clé illisible et une
            // signature fausse donnent le même refus, et c'est `asl-session`
            // qui le compose.
            // **DEUX GENRES PROUVENT UNE CLÉ ICI** : une machine, ou un
            // appareil. Le genre de l'identifiant dit dans quelle table
            // chercher, et il vient de la SIGNATURE — `asl-session` l'a lu du
            // corps, mais c'est le message signé qui le rend contraignant.
            Besoin::ClePourPreuve { machine: qui, .. } => {
                let rangee = match qui.genre() {
                    asl_id::Genre::Appareil => self
                        .entrepot
                        .appareil(*qui)
                        .ok()
                        .flatten()
                        .map(|appareil| appareil.cle),
                    // **UNE MACHINE SANS CLÉ NE PROUVE RIEN.** Elle est
                    // déclarée et pas encore enrôlée ; c'est `None`, et non
                    // trente-deux zéros dont n'importe qui forgerait la
                    // signature.
                    _ => self
                        .entrepot
                        .machine(*qui)
                        .ok()
                        .flatten()
                        .and_then(|m| m.cle),
                };
                match rangee.map(ClePublique::depuis_octets) {
                    Some(Ok(cle)) => Trouvaille::Cle(cle),
                    Some(Err(_)) | None => Trouvaille::Rien,
                }
            }
            Besoin::Compte(qui) => match self.entrepot.compte(*qui) {
                Ok(Some(compte)) => Trouvaille::Compte {
                    qui: *qui,
                    alias: compte.alias,
                },
                Ok(None) | Err(_) => Trouvaille::Rien,
            },
            // ── LA RÉSOLUTION : QUATRE LECTURES, ET TOUTES OU AUCUNE ──────
            //
            // Décider avec trois sur quatre n'aurait pas de sens : si l'une
            // manque, on rend `Rien`, et `asl-session` répond `404` — le même
            // `404` qu'un refus, pour que rien ne dise à qui essaie ce qui
            // existe.
            Besoin::Ou { machine, service } => self
                .rassembler(*machine, service)
                .map_or(Trouvaille::Rien, Trouvaille::Resolution),

            // ── CE QUI CRÉE ─────────────────────────────────────────────
            //
            // **TOUT SE PASSE ICI**, et rien à l'étage 2 : créer, c'est écrire,
            // et tirer un identifiant, c'est lire l'entropie du noyau. Ce que
            // `asl-session` a fait avant, elle, est ce qu'elle seule pouvait
            // faire : vérifier une preuve contre le défi de cette connexion.
            Besoin::PreuveRefusee => Trouvaille::Rien,
            Besoin::CreerCompte { cle } => self.creer_un_compte(cle),
            Besoin::CreerAppareil { cle } => self.creer_un_appareil(cle),
            Besoin::CreerMachine { nom, capacites } => self.creer_une_machine(nom, *capacites),
            Besoin::NouveauCode { machine } => self.emettre_un_code(*machine),
            Besoin::Enroler { empreinte, cle } => self.enroler(empreinte, cle),
            Besoin::Autoriser { a, portee } => self.autoriser(*a, *portee),

            Besoin::CompteParAlias(alias) => match self.entrepot.compte_par_alias(alias) {
                Ok(Some(qui)) => match self.entrepot.compte(qui) {
                    Ok(Some(compte)) => Trouvaille::Compte {
                        qui,
                        alias: compte.alias,
                    },
                    // **L'INDEX DÉSIGNE UN COMPTE QUI N'EXISTE PAS.** C'est une
                    // incohérence de la base, pas une requête fautive ; on rend
                    // `404` plutôt que d'inventer un compte vide.
                    Ok(None) | Err(_) => Trouvaille::Rien,
                },
                Ok(None) | Err(_) => Trouvaille::Rien,
            },
        }
    }
}

impl Service<'_> {
    /// Le compte au nom duquel cette connexion agit.
    ///
    /// **C'est l'APPAREIL qui a prouvé sa clé qui le désigne**, jamais ce
    /// qu'une requête a nommé. C10 tient par là : aucun verbe d'administration
    /// ne prend un compte en paramètre.
    fn compte_de_la_connexion(&self) -> Option<Identifiant> {
        let appareil = self.session.appareil()?;
        self.entrepot
            .appareil(appareil)
            .ok()
            .flatten()
            .map(|rangee| rangee.proprietaire)
    }

    /// Tire un identifiant de ce genre.
    fn un_identifiant(&self, genre: asl_id::Genre) -> Option<Identifiant> {
        Some(Identifiant::depuis_entropie(
            genre,
            (self.tirer_un_identifiant)()?,
        ))
    }

    /// Crée un compte et enrôle l'appareil qui vient de prouver sa clé.
    fn creer_un_compte(&self, cle: &ClePublique) -> Trouvaille {
        // **L'ATTESTATION EST LA SEULE CHOSE QUI GARDE CE CHEMIN.** Il n'exige
        // aucune signature de compte, pour la raison la plus simple : il n'y a
        // pas encore de compte.
        if asl_auth::decider_attestation(false, self.politique) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        let (Some(compte), Some(appareil)) = (
            self.un_identifiant(asl_id::Genre::Utilisateur),
            self.un_identifiant(asl_id::Genre::Appareil),
        ) else {
            return Trouvaille::Rien;
        };

        if self
            .entrepot
            .poser_compte(
                compte,
                &asl_registre::Compte {
                    provenance: asl_registre::Provenance::Ici,
                    alias: None,
                },
            )
            .is_err()
        {
            return Trouvaille::Rien;
        }
        if self
            .entrepot
            .poser_appareil(
                appareil,
                &asl_registre::Appareil {
                    provenance: asl_registre::Provenance::Ici,
                    proprietaire: compte,
                    cle: cle.octets(),
                },
            )
            .is_err()
        {
            return Trouvaille::Rien;
        }
        Trouvaille::CompteCree { compte, appareil }
    }

    /// Enrôle un appareil de plus sur le compte de cette connexion.
    fn creer_un_appareil(&self, cle: &ClePublique) -> Trouvaille {
        if asl_auth::decider_attestation(false, self.politique) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        let (Some(compte), Some(appareil)) = (
            self.compte_de_la_connexion(),
            self.un_identifiant(asl_id::Genre::Appareil),
        ) else {
            return Trouvaille::Rien;
        };
        match self.entrepot.poser_appareil(
            appareil,
            &asl_registre::Appareil {
                provenance: asl_registre::Provenance::Ici,
                proprietaire: compte,
                cle: cle.octets(),
            },
        ) {
            Ok(()) => Trouvaille::AppareilCree(appareil),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Déclare une machine, et émet son premier code d'enrôlement.
    fn creer_une_machine(&self, nom: &str, capacites: asl_api::corps::Capacites) -> Trouvaille {
        let (Some(compte), Some(machine)) = (
            self.compte_de_la_connexion(),
            self.un_identifiant(asl_id::Genre::Machine),
        ) else {
            return Trouvaille::Rien;
        };
        let Ok(nom) = asl_registre::NomRange::nouveau(nom) else {
            return Trouvaille::Rien;
        };

        if self
            .entrepot
            .poser_machine(
                machine,
                &asl_registre::Machine {
                    provenance: asl_registre::Provenance::Ici,
                    proprietaire: compte,
                    // **SANS CLÉ**, et c'est l'état d'une machine déclarée : la
                    // clé arrivera avec le code, générée sur place.
                    cle: None,
                    annonce: capacites.annonce,
                    lecture: capacites.lecture,
                    nom,
                },
            )
            .is_err()
        {
            return Trouvaille::Rien;
        }
        match self.tirer_un_code(machine) {
            Some((code, expire_a)) => Trouvaille::MachineCreee {
                machine,
                code,
                expire_a,
            },
            None => Trouvaille::Rien,
        }
    }

    /// Émet un nouveau code pour une machine déjà déclarée.
    fn emettre_un_code(&self, machine: Identifiant) -> Trouvaille {
        let (Some(compte), Ok(Some(rangee))) = (
            self.compte_de_la_connexion(),
            self.entrepot.machine(machine),
        ) else {
            return Trouvaille::Rien;
        };
        // **UNE MACHINE QUI N'EST PAS À NOUS NE SE RÉ-ENRÔLE PAS.** Sans ce
        // refus, quiconque a un compte pourrait émettre un code pour la machine
        // d'un autre, puis y lier sa propre clé.
        if asl_auth::decider_gestion(compte, rangee.proprietaire) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        match self.tirer_un_code(machine) {
            Some((code, expire_a)) => Trouvaille::CodeEmis { code, expire_a },
            None => Trouvaille::Rien,
        }
    }

    /// Tire un code pour cette machine, et le range sous son empreinte.
    fn tirer_un_code(&self, machine: Identifiant) -> Option<(asl_auth::TexteCode, u64)> {
        // Huit octets suffisent : dix symboles n'en portent que cinquante bits.
        // On puise à la même source que les identifiants — c'est le même noyau,
        // et la même exigence.
        let graine = (self.tirer_un_identifiant)()?;
        let mut huit = [0_u8; 8];
        for (place, octet) in huit.iter_mut().zip(graine.iter()) {
            *place = *octet;
        }
        let code = asl_auth::CodeEnrolement::depuis_entropie(huit);
        let expire_a = maintenant()
            .saturating_div(1_000)
            .saturating_add(asl_auth::VALIDITE_CODE_SECONDES.saturating_mul(1_000));

        self.entrepot
            .poser_enrolement(
                &code.empreinte(),
                &asl_registre::Enrolement {
                    provenance: asl_registre::Provenance::Ici,
                    machine,
                    expire_a,
                },
            )
            .ok()?;
        Some((code.texte_groupe(), expire_a))
    }

    /// Lie cette clé à la machine que ce code désigne.
    fn enroler(&self, empreinte: &[u8], cle: &ClePublique) -> Trouvaille {
        // **LE CODE MEURT ICI, QU'IL SERVE OU NON.** Consommer d'abord et
        // décider ensuite est ce qui rend « à usage unique » vrai : un code
        // expiré qu'on laisserait en place resterait un secret vivant, et deux
        // enrôlements simultanés du même code en verraient tous deux un valide.
        let Ok(trouve) = self.entrepot.consommer_enrolement(empreinte) else {
            return Trouvaille::Rien;
        };
        let etat = match &trouve {
            None => asl_auth::EtatCode::Inconnu,
            Some(enrolement) if enrolement.expire_a < maintenant().saturating_div(1_000) => {
                asl_auth::EtatCode::Expire
            }
            Some(_) => asl_auth::EtatCode::Utilisable,
        };
        if asl_auth::decider_enrolement(etat) == asl_auth::Decision::Refuser {
            return Trouvaille::Refus;
        }
        let Some(enrolement) = trouve else {
            return Trouvaille::Refus;
        };
        let Ok(Some(rangee)) = self.entrepot.machine(enrolement.machine) else {
            return Trouvaille::Rien;
        };
        match self.entrepot.poser_machine(
            enrolement.machine,
            &asl_registre::Machine {
                cle: Some(cle.octets()),
                ..rangee
            },
        ) {
            Ok(()) => Trouvaille::Enrolee(enrolement.machine),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Accorde une autorisation à un autre compte.
    fn autoriser(&self, a: Identifiant, portee: asl_api::corps::Portee) -> Trouvaille {
        let (Some(par), Some(quelle)) = (
            self.compte_de_la_connexion(),
            self.un_identifiant(asl_id::Genre::Autorisation),
        ) else {
            return Trouvaille::Rien;
        };

        // **LE BÉNÉFICIAIRE DOIT EXISTER.** Une autorisation vers un compte
        // inexistant est MUETTE : elle s'affiche comme accordée et n'ouvre rien.
        // `protocole.md` §2.2 donne `GET /v1/utilisateurs/{u}` pour qu'une faute
        // de frappe se voie ; le vérifier ici est ce qui la rend impossible.
        match self.entrepot.compte(a) {
            Ok(Some(_)) => {}
            Ok(None) => return Trouvaille::Refus,
            Err(_) => return Trouvaille::Rien,
        }

        // **ON N'ACCORDE QUE SUR CE QU'ON POSSÈDE.** Une portée qui nomme la
        // machine d'un autre n'ouvrirait rien — `Autorisation::couvre` vérifie
        // les deux bouts —, mais elle s'afficherait comme accordée. Un droit qui
        // ment sur ce qu'il donne est pire qu'un refus.
        let portee = match portee {
            asl_api::corps::Portee::ToutLeCompte => asl_registre::Portee::ToutLeCompte,
            asl_api::corps::Portee::UneMachine(machine) => {
                let Ok(Some(rangee)) = self.entrepot.machine(machine) else {
                    return Trouvaille::Refus;
                };
                if asl_auth::decider_gestion(par, rangee.proprietaire)
                    == asl_auth::Decision::Refuser
                {
                    return Trouvaille::Refus;
                }
                asl_registre::Portee::UneMachine(machine)
            }
            asl_api::corps::Portee::UnService(service) => {
                let Ok(Some(rangee)) = self.entrepot.service(service) else {
                    return Trouvaille::Refus;
                };
                let Ok(Some(machine)) = self.entrepot.machine(rangee.machine) else {
                    return Trouvaille::Refus;
                };
                if asl_auth::decider_gestion(par, machine.proprietaire)
                    == asl_auth::Decision::Refuser
                {
                    return Trouvaille::Refus;
                }
                asl_registre::Portee::UnService(service)
            }
        };

        // **`Autorisation::nouvelle` REFUSE QU'UN COMPTE S'AUTORISE LUI-MÊME**,
        // et c'est là que ce refus se prend. Le répéter ici en ferait une règle
        // à deux endroits.
        if asl_auth::Autorisation::nouvelle(
            par,
            a,
            match portee {
                asl_registre::Portee::ToutLeCompte => asl_auth::Portee::ToutLeCompte,
                asl_registre::Portee::UneMachine(quoi) => asl_auth::Portee::UneMachine(quoi),
                asl_registre::Portee::UnService(quoi) => asl_auth::Portee::UnService(quoi),
            },
            false,
        )
        .is_err()
        {
            return Trouvaille::Refus;
        }

        match self.entrepot.poser_autorisation(
            quelle,
            &asl_registre::Autorisation {
                provenance: asl_registre::Provenance::Ici,
                par,
                a,
                portee,
                revoquee: false,
            },
        ) {
            Ok(()) => Trouvaille::AutorisationCreee(quelle),
            Err(_) => Trouvaille::Rien,
        }
    }

    /// Prend une annonce, ouvre sa session vivante, et compose la réponse.
    ///
    /// # POURQUOI TOUT CECI EST À L'ÉTAGE 3
    ///
    /// Une annonce OUVRE de l'état vivant, qui n'existe qu'en mémoire et
    /// n'appartient qu'à cette connexion. Ce qui DÉCIDE reste ailleurs et reste
    /// pur : `asl_auth::decider_annonce` pour la permission,
    /// `asl_annuaire::Session::ouvrir` pour tout le reste — le bail, le verdict
    /// de NAT, les candidats. Cette fonction ne fait que les appeler dans
    /// l'ordre, et ranger ce qu'ils rendent.
    ///
    /// Rend `None` sur un refus ou un message mal formé ; `asl-session` en fait
    /// un `403`.
    fn annoncer(&mut self) -> Option<Vec<u8>> {
        // ── LE DEMANDEUR, ET SA PERMISSION ──────────────────────────────────
        let qui = self.session.machine()?;
        let rangee = self.entrepot.machine(qui).ok().flatten()?;
        let demandeur = asl_auth::Machine::nouvelle(
            qui,
            rangee.proprietaire,
            asl_auth::Capacites {
                annonce: rangee.annonce,
                lecture: rangee.lecture,
            },
        )
        .ok()?;
        if asl_auth::decider_annonce(&demandeur) == asl_auth::Decision::Refuser {
            return None;
        }

        // ── LE MESSAGE ──────────────────────────────────────────────────────
        let mut tampons = asl_proto::cadrage::Tampons::nouveaux();
        let annonce = asl_proto::Annonce::decoder(&self.corps, &mut tampons).ok()?;

        // **UNE MACHINE N'ANNONCE QUE POUR ELLE-MÊME.** Le message porte un
        // identifiant de machine ; s'il n'est pas celui qui a prouvé sa clé sur
        // CETTE connexion, c'est une usurpation, et elle se refuse ici.
        if annonce.machine != qui {
            return None;
        }

        // ── LE SERVICE : CELUI QUI EXISTE, OU UN NEUF ───────────────────────
        //
        // Un daemon n'a pas à déclarer son service avant de l'annoncer : la
        // première annonce d'un nom le crée. L'exiger d'abord obligerait à
        // passer par l'application mobile pour lancer un daemon, ce qu'aucun
        // déploiement automatisé ne peut faire.
        let nom = annonce.service.as_str();
        let service = match self.entrepot.service_par_nom(qui, nom).ok()? {
            Some(deja) => deja,
            None => {
                let neuf = Identifiant::depuis_entropie(
                    asl_id::Genre::Service,
                    (self.tirer_un_identifiant)()?,
                );
                self.entrepot
                    .poser_service(
                        neuf,
                        &asl_registre::Service {
                            provenance: asl_registre::Provenance::Ici,
                            machine: qui,
                            nom: asl_registre::NomRange::nouveau(nom).ok()?,
                        },
                    )
                    .ok()?;
                neuf
            }
        };

        // ── LA SESSION VIVANTE ──────────────────────────────────────────────
        let (vivante, _ordres) = asl_annuaire::Session::ouvrir(
            service,
            BAIL_PAR_DEFAUT,
            &annonce,
            self.vu_depuis,
            instant(),
        )
        .ok()?;

        // ── LES SONDES PARTENT, ET LA RÉPONSE N'ATTEND PAS ──────────────────
        //
        // **ON RÉPOND AVANT D'AVOIR MESURÉ**, et c'est ce que
        // `asl_proto::Verdict::EnCours` existe pour dire. Attendre le
        // trois-temps ferait patienter le daemon jusqu'à trois secondes par
        // point, et bloquerait la boucle entière — qui n'a qu'une tâche.
        //
        // Les verdicts reviennent par le canal, et `au_tour` les applique.
        self.lancer_les_sondes(service, &vivante, &_ordres);

        let mut sortie = alloc_reponse();
        let combien = vivante.reponse().ok()?.encoder(&mut sortie).ok()?;
        sortie.truncate(combien);

        self.vivier.poser(service, &self.connexion, vivante);
        Some(sortie)
    }

    /// Lance une sonde par point sondable, et rend la main aussitôt.
    ///
    /// # SEUL LE CANDIDAT RÉFLEXIF EST SONDÉ
    ///
    /// `sonde::sondable` en est le juge, et son en-tête dit pourquoi : sonder
    /// une adresse ANNONCÉE serait inutile — c'est une adresse du réseau du
    /// daemon, pas du nôtre — et ferait de l'annuaire un balayeur de notre
    /// propre réseau, avec notre IP.
    fn lancer_les_sondes(
        &mut self,
        service: Identifiant,
        vivante: &asl_annuaire::Session,
        ordres: &asl_annuaire::Ordres,
    ) {
        for point in ordres.a_sonder() {
            if *self.en_vol >= sonde::EN_VOL_MAX {
                // **ON NE SONDE PAS, ET C'EST HONNÊTE** : le verdict reste
                // `en_cours`, ce qui est exactement la vérité.
                break;
            }
            let mut candidats = [asl_proto::Candidat {
                protocole: point.protocole,
                adresse: core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED),
                port: point.port,
                origine: asl_proto::Origine::Reflexif,
            }; asl_proto::ADRESSES_MAX + 1];
            let combien = vivante.candidats(point, &mut candidats);

            let Some(ou) = candidats
                .get(..combien)
                .unwrap_or_default()
                .iter()
                .find_map(|candidat| sonde::sondable(*candidat).map(|ou| (ou, *candidat)))
            else {
                continue;
            };

            let (adresse, candidat) = ou;
            let rapports = self.rapports.clone();
            *self.en_vol = self.en_vol.saturating_add(1);
            tokio::spawn(async move {
                let aboutie = sonde::aboutit(adresse).await.then_some(candidat);
                // Le canal est fermé quand l'annuaire s'éteint : il n'y a alors
                // plus personne pour le verdict, et ce n'est pas une faute.
                let _ = rapports.send(Verdict {
                    service,
                    point,
                    aboutie,
                    quand: asl_proto::Horodatage::depuis_millisecondes(
                        maintenant().saturating_div(1_000),
                    ),
                    maintenant: instant(),
                });
            });
        }
    }

    /// Rassemble ce qu'il faut pour décider d'une résolution.
    ///
    /// # POURQUOI TANT DE LECTURES POUR UNE QUESTION SI SIMPLE
    ///
    /// « Où est ce service ? » se décide sur quatre faits : ce que le demandeur
    /// a le DROIT de faire (ses capacités), à QUI il appartient, à qui appartient
    /// ce qu'il vise, et ce qu'on lui a accordé. Aucun ne se déduit des autres.
    ///
    /// **Un seul manquant, et l'on ne décide pas** : rendre `None` fait répondre
    /// `404`, exactement comme un refus.
    fn rassembler(&self, machine: Identifiant, nom: &str) -> Option<Resolution> {
        // Le demandeur : c'est la machine qui a prouvé sa clé sur CETTE
        // connexion, jamais une machine qu'une requête nommerait.
        let qui = self.session.machine()?;
        let demandeur = self.entrepot.machine(qui).ok().flatten()?;
        let demandeur = asl_auth::Machine::nouvelle(
            qui,
            demandeur.proprietaire,
            asl_auth::Capacites {
                annonce: demandeur.annonce,
                lecture: demandeur.lecture,
            },
        )
        .ok()?;

        let service = self.entrepot.service_par_nom(machine, nom).ok().flatten()?;
        let visee = self.entrepot.machine(machine).ok().flatten()?;
        let cible = asl_auth::Cible::nouvelle(service, machine, visee.proprietaire).ok()?;

        let autorisations = self
            .entrepot
            .autorisations_recues(demandeur.proprietaire())
            .ok()?
            .into_iter()
            .filter_map(|quoi| {
                asl_auth::Autorisation::nouvelle(
                    quoi.par,
                    quoi.a,
                    match quoi.portee {
                        asl_registre::Portee::ToutLeCompte => asl_auth::Portee::ToutLeCompte,
                        asl_registre::Portee::UneMachine(quelle) => {
                            asl_auth::Portee::UneMachine(quelle)
                        }
                        asl_registre::Portee::UnService(quel) => asl_auth::Portee::UnService(quel),
                    },
                    quoi.revoquee,
                )
                .ok()
            })
            .collect();

        // **CE QUI EST ANNONCÉ, LU MAINTENANT ET RÉVÉLÉ PLUS TARD.** C'est
        // notre propre mémoire : la lire ne dit rien à personne. La RENDRE est
        // une décision, et elle se prend à l'étage 2, après l'autorisation.
        let annonce = self.vivier.annonce(service).and_then(|vivante| {
            let mut sortie = alloc_reponse();
            let combien = vivante.reponse().ok()?.encoder(&mut sortie).ok()?;
            sortie.truncate(combien);
            Some(sortie)
        });

        Some(Resolution {
            demandeur,
            cible,
            autorisations,
            annonce,
        })
    }
}

/// L'instant courant, comme `asl-annuaire` le compte.
///
/// **EN MILLISECONDES, ET MONOTONE PAR CONVENTION.** `asl_annuaire::Instant` est
/// une horloge de DÉCISION — elle sert à dire « ce bail a-t-il expiré ». On la
/// tire de la même source que le reste de la boucle, en divisant les
/// microsecondes : un bail se compte en dizaines de secondes, et la
/// milliseconde y est déjà une précision de trop.
fn instant() -> asl_annuaire::Instant {
    asl_annuaire::Instant::depuis_millisecondes(maintenant().saturating_div(1_000))
}

/// Le bail qu'on accorde.
///
/// **QUINZE SECONDES DE KEEPALIVE, QUARANTE-CINQ D'INACTIVITÉ**, soit trois
/// keepalives manqués. `modele.md` le propose et demande de le MESURER sur de
/// vrais NAT : ce n'est pas une conclusion, et le jour où la mesure sera faite,
/// c'est ici qu'elle atterrira.
const BAIL_PAR_DEFAUT: asl_proto::Bail = match asl_proto::Bail::nouveau(15, 45) {
    Ok(bail) => bail,
    // Ces deux constantes sont valides, et le compilateur le vérifie : cette
    // branche ne compile que parce qu'elle doit exister, jamais parce qu'elle
    // sert.
    Err(_) => panic!("quinze et quarante-cinq forment un bail valide"),
};

/// Combien de temps entre deux balayages des codes périmés, en millisecondes.
///
/// Cinq minutes. Un code vaut dix minutes ; il ne survit donc jamais plus de
/// quinze à sa mort, et il est refusé pendant tout ce temps.
const BALAYAGE_DES_CODES_MS: u64 = 5 * 60 * 1_000;

/// Le port qu'on note quand un pair prétend parler depuis le zéro.
const PORT_DE_SECOURS: asl_proto::Port = match asl_proto::Port::depuis_u16(1) {
    Ok(port) => port,
    Err(_) => panic!("un est un port"),
};

/// Un tampon pour une réponse d'annonce.
///
/// `asl_proto::cadrage::MESSAGE_MAX` est la borne du protocole : au-delà, le
/// message ne serait de toute façon pas lisible par un pair.
fn alloc_reponse() -> Vec<u8> {
    vec![0_u8; asl_proto::cadrage::MESSAGE_MAX]
}

/// L'application qui sert l'API de l'annuaire en HTTP/3.
pub struct Annuaire<'a> {
    /// Un conducteur et une session par connexion vivante.
    connexions: HashMap<Vec<u8>, ParConnexion>,
    /// Ce qui se souvient, partagé par toutes les connexions.
    entrepot: &'a Entrepot,
    /// À quoi les signatures de ce serveur sont liées.
    ///
    /// **L'EMPREINTE DE NOTRE CERTIFICAT**, calculée une fois au démarrage.
    /// Voir `asl_cle::LiaisonDeCanal` pour ce qu'elle ferme et ce qu'elle ne
    /// ferme pas.
    liaison: LiaisonDeCanal,
    /// Toutes les annonces vivantes.
    vivier: Vivier,
    /// Par où les sondes rapportent.
    rapports: tokio::sync::mpsc::UnboundedSender<Verdict>,
    /// Ce qu'elles rapportent, recueilli à chaque tour.
    verdicts: tokio::sync::mpsc::UnboundedReceiver<Verdict>,
    /// Combien de sondes sont en vol.
    en_vol: usize,
    /// De quoi tirer un identifiant de service.
    tirer_un_identifiant: &'a (dyn Fn() -> Option<[u8; 16]> + Send + Sync),
    /// De quoi tirer un défi.
    ///
    /// `Send + Sync` : l'écoute tourne dans une tâche, et ce qu'elle tient doit
    /// pouvoir y aller avec elle.
    tirer_un_defi: &'a (dyn Fn() -> Option<Defi> + Send + Sync),
    /// Combien de connexions ont parlé HTTP/3.
    servies: u64,
    /// Ce que cet annuaire exige d'un appareil qui s'enrôle.
    ///
    /// **Il n'y a pas de défaut** — voir `asl_auth::Politique`. L'exploitant
    /// dit laquelle il tient, et `asl-server` refuse de démarrer sans.
    politique: asl_auth::Politique,
    /// Quand les codes expirés ont été balayés pour la dernière fois.
    dernier_balayage: u64,
}

impl<'a> Annuaire<'a> {
    /// Une application neuve, servant depuis cet entrepôt.
    ///
    /// `liaison` est l'empreinte du certificat que ce serveur présente ;
    /// `tirer_un_defi` rend trente-deux octets imprévisibles, ou `None` si le noyau
    /// a refusé — auquel cas la réponse sera `500`, jamais un défi de repli.
    #[must_use]
    pub fn new(
        entrepot: &'a Entrepot,
        liaison: LiaisonDeCanal,
        tirer_un_defi: &'a (dyn Fn() -> Option<Defi> + Send + Sync),
        tirer_un_identifiant: &'a (dyn Fn() -> Option<[u8; 16]> + Send + Sync),
        politique: asl_auth::Politique,
    ) -> Self {
        let (rapports, verdicts) = tokio::sync::mpsc::unbounded_channel();
        Self {
            connexions: HashMap::new(),
            entrepot,
            liaison,
            vivier: Vivier::nouveau(),
            rapports,
            verdicts,
            en_vol: 0,
            tirer_un_identifiant,
            tirer_un_defi,
            servies: 0,
            politique,
            dernier_balayage: 0,
        }
    }

    /// Combien d'annonces vivent.
    #[must_use]
    pub fn annonces_vivantes(&self) -> usize {
        self.vivier.combien()
    }

    /// Combien de connexions ont parlé HTTP/3.
    #[must_use]
    pub const fn servies(&self) -> u64 {
        self.servies
    }

    /// Efface les codes d'enrôlement périmés, de loin en loin.
    ///
    /// # POURQUOI PAS À CHAQUE TOUR
    ///
    /// C'est un balayage de table, et la boucle en fait des milliers par
    /// seconde. **Il ne change aucune décision** — un code expiré est refusé de
    /// toute façon, `asl_auth::decider_enrolement` le dit —, donc rien n'exige
    /// qu'il soit prompt. Il empêche seulement une table de secrets morts de
    /// grandir sans fin.
    fn balayer_les_codes(&mut self) {
        let maintenant_ms = maintenant().saturating_div(1_000);
        if maintenant_ms.saturating_sub(self.dernier_balayage) < BALAYAGE_DES_CODES_MS {
            return;
        }
        self.dernier_balayage = maintenant_ms;
        // Une base qui refuse ne doit pas arrêter la boucle : le balayage
        // reviendra, et rien ne dépend de lui.
        let _ = self.entrepot.expirer_les_enrolements(maintenant_ms);
    }

    /// Ferme cette connexion sur une faute d'HTTP/3.
    ///
    /// §8.1 : le code applicatif dit au pair ce qu'il a fait de travers. Sans
    /// lui, il attendrait son délai d'inactivité sans savoir pourquoi.
    fn condamner(connexion: &mut Connection, faute: &ams_h3::Error) {
        connexion.close_with(faute.close_code(), maintenant());
    }
}

impl Application for Annuaire<'_> {
    fn au_tour(&mut self, _maintenant: u64) {
        // **LES VERDICTS ARRIVENT ICI, ET NULLE PART AILLEURS.** Une sonde est
        // une tâche à part : elle ne touche pas au vivier, elle rapporte. C'est
        // ce qui permet d'attendre trois secondes un trois-temps sans arrêter
        // la boucle, qui n'a qu'une tâche pour toutes les connexions.
        while let Ok(verdict) = self.verdicts.try_recv() {
            self.en_vol = self.en_vol.saturating_sub(1);
            self.vivier.appliquer(&verdict);
        }
        // Et l'on oublie ce qui a expiré — une annonce dont la connexion est
        // tombée sans qu'on l'apprenne n'a personne pour la retirer.
        self.vivier.oublier_les_expirees(instant());
        self.balayer_les_codes();
    }

    fn a_l_etablissement(&mut self, connexion: &mut Connection, _pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let liaison = self.liaison;
        let etat = self.connexions.entry(clef).or_insert_with(|| ParConnexion {
            conducteur: Http3::default(),
            session: Session::new(liaison),
        });
        self.servies = self.servies.saturating_add(1);
        // §6.2.1 : notre flux de contrôle et nos réglages, tout de suite — puis
        // les deux flux QPACK de §4.2 de RFC 9204.
        if let Err(faute) = etat.conducteur.on_established(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    fn a_la_lecture(&mut self, connexion: &mut Connection, flux: StreamId, pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();

        // **LA CONNEXION VIVANTE EST LE KEEPALIVE.** `protocole.md` §1.2 : il
        // n'y a pas de verbe pour rafraîchir, et cette ligne est ce qui le
        // rend vrai. Sans elle, une annonce expirerait sous un daemon qui n'a
        // rien fait de mal — il tient sa connexion, et c'est ce qu'on lui
        // demande.
        self.vivier.keepalive(&clef, instant());
        let Some(etat) = self.connexions.get_mut(&clef) else {
            return;
        };
        // **DEUX EMPRUNTS DISJOINTS D'UN MÊME `etat`** : le conducteur pilote le
        // transport, la session sert la requête. Les séparer ici évite de
        // recopier l'un ou l'autre à chaque flux.
        let ParConnexion {
            conducteur,
            session,
        } = etat;
        let mut service = Service {
            session,
            politique: self.politique,
            entrepot: self.entrepot,
            vivier: &mut self.vivier,
            rapports: self.rapports.clone(),
            en_vol: &mut self.en_vol,
            connexion: clef.clone(),
            tirer_un_identifiant: self.tirer_un_identifiant,
            corps: Vec::new(),
            vu_depuis: asl_proto::VuDepuis {
                adresse: pair.ip(),
                // Un pair qui parle depuis le port zéro n'existe pas : une
                // socket connectée en a toujours un.
                port: asl_proto::Port::depuis_u16(pair.port()).unwrap_or(PORT_DE_SECOURS),
            },
            defi: (self.tirer_un_defi)(),
        };
        if let Err(faute) = conducteur.on_readable(&mut Pont(connexion), &mut service, flux) {
            Self::condamner(connexion, &faute);
        }
    }

    fn a_l_arret(&mut self, connexion: &mut Connection, _pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(etat) = self.connexions.get_mut(&clef) else {
            return;
        };
        // §5.2, premier temps : l'identifiant maximal. Il dit « n'ouvre plus
        // rien » sans condamner une seule requête déjà en vol.
        if let Err(faute) = etat.conducteur.shutdown(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    fn a_l_epuisement(&mut self, connexion: &mut Connection, _pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(etat) = self.connexions.get_mut(&clef) else {
            return;
        };
        // §5.2, second temps : le rang qui suit la dernière requête servie.
        // Au-delà, le client sait que rien n'a été fait et peut rejouer
        // ailleurs.
        if let Err(faute) = etat.conducteur.drain(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    /// §5.2 : « `H3_NO_ERROR` » — on s'en va, et tout s'est bien passé. Fermer
    /// avec autre chose ferait chercher au client une faute qui n'existe pas.
    fn code_de_fermeture(&self) -> u64 {
        ams_h3::NO_ERROR
    }

    fn a_la_fermeture(&mut self, connexion: &Connection, _pair: SocketAddr) {
        // **ET C'EST ICI QUE LE BAIL TOMBE.** Tout ce que cette connexion avait
        // annoncé cesse d'exister, immédiatement — c'est le gain le plus net du
        // transport tenu. Avec des annonces périodiques, un daemon arrêté
        // proprement restait faussement présent jusqu'à l'expiration.
        //
        // **`Volontaire`, ET NON `Inactivite`.** La distinction compte pour qui
        // regarde (`protocole.md` §1.3), et l'écoute ne sait pas encore la
        // faire : elle ferme sur signal comme sur délai. Le motif juste viendra
        // avec ce qui distingue les deux — le dire ici plutôt que de laisser
        // croire que c'est déjà fait.
        let partis = self.vivier.retirer(
            connexion.local_id().as_bytes(),
            asl_annuaire::MotifDeDepart::Volontaire,
        );
        let _ = partis;
        self.connexions.remove(connexion.local_id().as_bytes());
    }
}
