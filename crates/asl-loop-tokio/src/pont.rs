//! Le pont entre HTTP/3 et une connexion QUIC.

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
