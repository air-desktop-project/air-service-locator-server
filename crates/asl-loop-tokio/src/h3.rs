//! L'application HTTP/3 : elle relie la boucle QUIC à ce qui décide.
//!
//! # ELLE NE DÉCIDE RIEN, ET C'EST LA TROISIÈME FOIS QU'ON LE DIT
//!
//! `asl-session` décide de la réponse — statut, corps, champs — et le fait
//! **sans entrée-sortie**, sous le régime de couverture. `ams-h3` sait quel flux
//! ouvrir et dans quel ordre. Ce module ne fait que les présenter l'un à
//! l'autre, connexion par connexion.
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

use ams_h3::Http3;
use ams_proto_quic::StreamId;
use ams_quic_tls::Connection;
use asl_session::Session;

use crate::pont::Pont;
use crate::quic::{Application, maintenant};

/// Ce qu'on tient pour une connexion vivante.
#[derive(Default)]
struct ParConnexion {
    /// Le conducteur HTTP/3 : flux de contrôle, QPACK, cadrage.
    conducteur: Http3,
    /// Ce qui décide des réponses de CETTE connexion.
    session: Session,
}

/// L'application qui sert l'API de l'annuaire en HTTP/3.
#[derive(Default)]
pub struct Annuaire {
    /// Un conducteur et une session par connexion vivante.
    connexions: HashMap<Vec<u8>, ParConnexion>,
    /// Combien de connexions ont parlé HTTP/3.
    servies: u64,
}

impl Annuaire {
    /// Une application neuve.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

impl Application for Annuaire {
    fn a_l_etablissement(&mut self, connexion: &mut Connection, _pair: SocketAddr) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let etat = self.connexions.entry(clef).or_default();
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
        if let Err(faute) = conducteur.on_readable(&mut Pont(connexion), session, flux) {
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
