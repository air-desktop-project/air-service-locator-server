//! La sonde de joignabilité : une connexion TCP qui ne dit qu'une chose.
//!
//! # LE KEEPALIVE NE REMPLACE PAS LA SONDE
//!
//! Le keepalive prouve que le daemon est vivant et que SA connexion vers
//! l'annuaire fonctionne. Il ne prouve **rien** sur la capacité d'un tiers à
//! atteindre son port de service : une connexion sortante réussit là où une
//! entrante échoue, et c'est précisément le cas derrière un NAT. Deux choses
//! différentes, deux mesures différentes (`modele.md` §4.3).
//!
//! # ON NE SONDE QUE LE CANDIDAT RÉFLEXIF, ET C'EST LA RÈGLE À NE PAS PERDRE
//!
//! `asl_annuaire::Session::candidats` en propose deux sortes : celui qu'on a
//! CONSTATÉ — l'adresse d'où le pair nous parle — et ceux qu'il a ANNONCÉS, ses
//! adresses locales.
//!
//! **Sonder les seconds serait inutile et dangereux.**
//!
//! Inutile : `192.168.1.20` est une adresse du réseau du daemon. S'y connecter
//! DEPUIS L'ANNUAIRE joint ce qui se trouve à cette adresse sur NOTRE réseau,
//! c'est-à-dire une machine sans aucun rapport. La mesure ne mesurerait rien.
//!
//! Dangereux : ces adresses sont choisies par le client. Les sonder ferait de
//! l'annuaire un intermédiaire qui ouvre des connexions vers des cibles qu'un
//! inconnu désigne — `10.0.0.5:22`, `169.254.169.254:80`, un tiers quelconque.
//! Le trois-temps aboutit ou non, et cette seule différence est un **oracle de
//! balayage**, avec notre adresse IP dans les journaux d'en face.
//!
//! **Le candidat réflexif n'a aucun de ces défauts** : c'est l'adresse d'où ce
//! pair vient de nous parler, et la poignée de main QUIC a déjà prouvé qu'il
//! tient ce chemin. Lui répondre n'ouvre aucune cible nouvelle — nous ne
//! parlons qu'à qui nous a parlé.
//!
//! # ELLE NE TRANSMET RIEN
//!
//! Ouverte, puis refermée. Aucun octet, aucun protocole applicatif : une seule
//! question, « le trois-temps aboutit-il ? ». Envoyer quoi que ce soit ferait de
//! la sonde un client, avec tout ce qu'un client peut casser en face.

use std::net::SocketAddr;

use asl_annuaire::Instant;
use asl_id::Identifiant;
use asl_proto::{Candidat, Horodatage, Origine, PointEcoute, Protocole};

/// Combien de temps on laisse au trois-temps.
///
/// **TROIS SECONDES, ET C'EST UN COMPROMIS ASSUMÉ.** Plus court ferait déclarer
/// injoignable un service simplement lointain ; plus long ferait attendre le
/// daemon pour une réponse qui n'arrivera pas. Un port filtré ne répond
/// jamais — c'est le délai qui tranche, et non un refus.
pub const ATTENTE: core::time::Duration = core::time::Duration::from_secs(3);

/// Combien de sondes peuvent être en vol à la fois.
///
/// **C'EST UNE BORNE DE NOTRE CÔTÉ** : chaque sonde est une tâche et un
/// descripteur. Sans elle, un pair qui annoncerait beaucoup de services nous
/// ferait ouvrir autant de connexions. Au-delà, on ne sonde pas — et le verdict
/// reste `en_cours`, ce qui est exact.
pub const EN_VOL_MAX: usize = 64;

/// Ce qu'une sonde rapporte.
#[derive(Debug, Clone, Copy)]
pub struct Verdict {
    /// Le service dont on a sondé un point.
    pub service: Identifiant,
    /// Le point sondé.
    pub point: PointEcoute,
    /// Le candidat qui a abouti, s'il y en a un.
    pub aboutie: Option<Candidat>,
    /// Quand la mesure a été faite.
    pub quand: Horodatage,
    /// L'instant de la mesure, pour la machine à états.
    pub maintenant: Instant,
}

/// Le candidat qu'on a le droit de sonder, s'il y en a un.
///
/// Rend `None` pour tout ce qui n'est pas un candidat TCP **réflexif** — voir
/// l'en-tête du module pour ce que cela évite.
#[must_use]
pub fn sondable(candidat: Candidat) -> Option<SocketAddr> {
    if candidat.origine != Origine::Reflexif {
        return None;
    }
    // **L'UDP NE SE SONDE PAS.** Il n'y a pas de poignée de main, et aucun écho
    // générique : une sonde UDP ne distingue pas « écoute et ignore » de « rien
    // n'écoute ». Un point UDP reste donc `annoncé`, jamais `joignable`.
    if candidat.protocole != Protocole::Tcp {
        return None;
    }
    Some(SocketAddr::new(candidat.adresse, candidat.port.valeur()))
}

/// Ouvre puis referme une connexion vers cette adresse. Le trois-temps
/// aboutit-il ?
///
/// # POURQUOI LE RÉSULTAT EST UN BOOLÉEN, ET NON UNE ERREUR
///
/// Refus, filtrage, délai, réseau injoignable : du point de vue de la question
/// posée, c'est la même réponse — **non**. Les distinguer donnerait à
/// l'annuaire un vocabulaire qu'il ne saurait pas employer, et à qui le lit une
/// nuance dont il ne pourrait rien faire.
pub async fn aboutit(ou: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(ATTENTE, tokio::net::TcpStream::connect(ou)).await,
        Ok(Ok(_))
    )
    // Le flux est refermé en sortant : on n'a rien à lui dire.
}

#[cfg(test)]
mod tests {
    use asl_proto::{Candidat, Origine, Port, Protocole};

    use super::{aboutit, sondable};

    fn un_candidat(origine: Origine, protocole: Protocole, adresse: &str) -> Candidat {
        Candidat {
            protocole,
            adresse: adresse.parse().expect("une adresse"),
            port: Port::depuis_u16(443).expect("un port"),
            origine,
        }
    }

    #[test]
    fn le_candidat_reflexif_en_tcp_se_sonde() {
        let quoi = un_candidat(Origine::Reflexif, Protocole::Tcp, "203.0.113.4");
        assert_eq!(
            sondable(quoi).map(|ou| ou.to_string()),
            Some("203.0.113.4:443".to_owned())
        );
    }

    #[test]
    fn une_adresse_annoncee_ne_se_sonde_jamais() {
        // **C'EST L'ESSAI QUI TIENT LA RÈGLE DE SÛRETÉ.** Ces adresses sont
        // choisies par le client ; les sonder ferait de l'annuaire un balayeur
        // de notre propre réseau, avec notre IP.
        for adresse in [
            "192.168.1.20",
            "10.0.0.5",
            "169.254.169.254",
            "127.0.0.1",
            "203.0.113.9",
        ] {
            let quoi = un_candidat(Origine::Annonce, Protocole::Tcp, adresse);
            assert_eq!(
                sondable(quoi),
                None,
                "{adresse} a été jugée sondable alors qu'elle est ANNONCÉE"
            );
        }
    }

    #[test]
    fn l_udp_ne_se_sonde_pas_meme_en_reflexif() {
        // Une sonde UDP ne distingue pas « écoute et ignore » de « rien
        // n'écoute » : elle ne mesurerait rien, et prétendrait le contraire.
        let quoi = un_candidat(Origine::Reflexif, Protocole::Udp, "203.0.113.4");
        assert_eq!(sondable(quoi), None);
    }

    #[test]
    fn le_reflexif_en_ipv6_se_sonde_aussi() {
        let quoi = un_candidat(Origine::Reflexif, Protocole::Tcp, "2001:db8::1");
        assert_eq!(
            sondable(quoi).map(|ou| ou.to_string()),
            Some("[2001:db8::1]:443".to_owned())
        );
    }

    #[tokio::test]
    async fn une_ecoute_reelle_aboutit() {
        let ecoute = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("une écoute");
        let ou = ecoute.local_addr().expect("une adresse");
        assert!(aboutit(ou).await, "le trois-temps devait aboutir");
    }

    #[tokio::test]
    async fn un_port_ou_personne_n_ecoute_n_aboutit_pas() {
        // On prend un port, on rend la socket, puis on sonde : plus personne
        // n'écoute, et le noyau refuse tout de suite.
        let ou = {
            let ecoute = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("une écoute");
            ecoute.local_addr().expect("une adresse")
        };
        assert!(!aboutit(ou).await, "le trois-temps ne devait pas aboutir");
    }
}
