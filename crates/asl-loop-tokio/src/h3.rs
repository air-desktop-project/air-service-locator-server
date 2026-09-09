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
use asl_session::{Besoin, Session, Trouvaille};
use asl_store::Entrepot;

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
    /// Ce qui se souvient.
    entrepot: &'a Entrepot,
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
    fn chercher(&self, besoin: &Besoin<'_>) -> Trouvaille {
        match besoin {
            Besoin::Deja(_) | Besoin::DefiATirer => Trouvaille::Rien,

            // **LA CLÉ VIENT DE L'ENREGISTREMENT DE LA MACHINE**, et rien
            // d'autre : une machine inconnue, une clé illisible et une
            // signature fausse donnent le même refus, et c'est `asl-session`
            // qui le compose.
            Besoin::ClePourPreuve { machine, .. } => match self.entrepot.machine(*machine) {
                Ok(Some(rangee)) => match ClePublique::depuis_octets(rangee.cle) {
                    Ok(cle) => Trouvaille::Cle(cle),
                    Err(_) => Trouvaille::Rien,
                },
                Ok(None) | Err(_) => Trouvaille::Rien,
            },
            Besoin::Compte(qui) => match self.entrepot.compte(*qui) {
                Ok(Some(compte)) => Trouvaille::Compte {
                    qui: *qui,
                    alias: compte.alias,
                },
                Ok(None) | Err(_) => Trouvaille::Rien,
            },
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
    /// De quoi tirer un défi.
    ///
    /// `Send + Sync` : l'écoute tourne dans une tâche, et ce qu'elle tient doit
    /// pouvoir y aller avec elle.
    tirer_un_defi: &'a (dyn Fn() -> Option<Defi> + Send + Sync),
    /// Combien de connexions ont parlé HTTP/3.
    servies: u64,
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
    ) -> Self {
        Self {
            connexions: HashMap::new(),
            entrepot,
            liaison,
            tirer_un_defi,
            servies: 0,
        }
    }

    /// Combien de connexions ont parlé HTTP/3.
    #[must_use]
    pub const fn servies(&self) -> u64 {
        self.servies
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

    fn a_la_lecture(&mut self, connexion: &mut Connection, flux: StreamId, _pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();
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
            entrepot: self.entrepot,
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
        // **ET C'EST ICI QUE LE BAIL TOMBERA.** Aujourd'hui on ne libère que le
        // conducteur et la session ; le jour où une machine se sera annoncée sur
        // cette connexion, c'est ce rendez-vous qui fera passer ses services de
        // `joignable` à `parti` — sans quoi l'annuaire annoncerait des services
        // que plus personne ne sert.
        self.connexions.remove(connexion.local_id().as_bytes());
    }
}
