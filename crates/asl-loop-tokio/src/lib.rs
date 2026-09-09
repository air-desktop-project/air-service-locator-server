//! La boucle d'entrées-sorties sur tokio : sockets, horloge, et rien qui décide.
//!
//! # Pourquoi le moteur est dans le NOM de la crate
//!
//! Il n'y a AUCUNE abstraction d'exécution ici, et ce n'est pas un oubli. Le jour
//! où ce service tournera sur le stack Air, il aura une deuxième boucle — écrite
//! contre `air-async`, dans une autre crate — qui pilotera LA MÊME machine à
//! états. Rien à adapter, rien à maintenir entre les deux, et la logique du
//! service n'est écrite qu'une fois.
//!
//! Une couche d'abstraction, elle, devrait être maintenue pour les deux, et
//! finirait par ne convenir à aucun.
//!
//! # CE QUI A ÉTÉ REPRIS D'`air-mail-server`, ET CE QUI NE L'A PAS ÉTÉ
//!
//! La pile QUIC et HTTP/3 est reprise ENTIÈRE et sans une ligne modifiée :
//! `ams-proto-quic`, `ams-quic-crypto`, `ams-quic`, `ams-quic-tls`,
//! `ams-proto-h3`, `ams-h3`. C'est possible parce qu'aucune ne fait
//! d'entrée-sortie : `ams-quic` annonce en tête de son manifeste « la machine de
//! connexion QUIC, **sans entrée-sortie** ».
//!
//! **`ams-loop-tokio` n'est PAS reprise**, et c'est ce qui justifie cette crate.
//! Son `serve_quic` est générique par sa forme, mais il est tissé avec
//! `ams-guard` — le garde anti-abus du serveur de courrier — et avec sa notion
//! de source. Le reprendre ferait entrer ici les décisions d'un autre produit.
//!
//! **`ams-quic-client` non plus.** Malgré son nom, ce n'est pas une bibliothèque
//! cliente : elle expose un `atelier()` qui crée un répertoire temporaire, un
//! `materiel()` qui fabrique des certificats, des identifiants de connexion
//! fixes, et une constante qui annonce qu'elle EXIGE openssl. C'est un harnais
//! d'essai, et rien de cela n'a sa place dans un produit.
//!
//! # ÉTAT : LE PONT, ET RIEN D'AUTRE ENCORE
//!
//! Ce qui manque pour qu'un serveur tourne est nommé, pour qu'on ne le
//! redécouvre pas : la socket UDP et le routage des paquets vers les connexions,
//! l'horloge des délais de renvoi, et **la question qui n'est pas tranchée — d'où
//! viennent les certificats.** Un serveur QUIC en présente un ; le produit n'a
//! pas encore dit s'il est auto-signé, obtenu par ACME, ou fourni par
//! l'administrateur de l'annuaire.

use ams_h3::Transport;
use ams_proto_quic::{Directional, StreamId};
use ams_quic::RecvState;
use ams_quic_tls::Connection;

/// Le pont entre HTTP/3 et une connexion QUIC.
///
/// # POURQUOI UN TYPE À NOUS PLUTÔT QU'UNE IMPLÉMENTATION DIRECTE
///
/// [`ams_h3::Transport`] appartient à `ams-h3`, [`Connection`] à `ams-quic-tls` :
/// aucun des deux n'est à nous, et la règle de l'orphelin interdit de les marier
/// ailleurs que chez l'un d'eux. **Ce n'est pas une gêne, c'est le bon endroit** :
/// l'assemblage demande une vraie connexion pour être éprouvé, et sa place est
/// donc à l'étage qui en tient une.
///
/// Il ne décide de rien : chaque méthode transmet, et traduit l'erreur du
/// transport en l'erreur qu'`ams-h3` sait lire.
pub struct Pont<'a>(pub &'a mut Connection);

impl Transport for Pont<'_> {
    fn open_uni(&mut self) -> Result<StreamId, ams_h3::Error> {
        self.0
            .open_stream(Directional::Unidirectional)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize {
        self.0.read(flux, vers)
    }

    fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, ams_h3::Error> {
        self.0
            .write(flux, octets)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn reset(&mut self, flux: StreamId, code: u64) -> Result<(), ams_h3::Error> {
        self.0
            .reset(flux, code)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn finish(&mut self, flux: StreamId) -> Result<(), ams_h3::Error> {
        self.0.finish(flux).map_err(|_| ams_h3::Error::transport())
    }

    fn recv_state(&self, flux: StreamId) -> Option<RecvState> {
        self.0.recv_state(flux)
    }
}
