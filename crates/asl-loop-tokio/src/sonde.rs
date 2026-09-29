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
    /// **Pour une sonde par l'écho, ce qu'elle a constaté** — et c'est ce que
    /// l'état par machine dit (`protocole.md` §3 quater) ; `aboutie` n'est
    /// posé que sur [`ResultatEcho::Verifie`]. `None` pour un trois-temps.
    pub echo: Option<ResultatEcho>,
    /// Par où la preuve est arrivée, quand elle l'est (décision 97).
    pub via: Option<asl_api::corps::ViaDEcho>,
    /// **Une sonde d'une racine, du dehors, vers l'écho d'une machine d'un
    /// domaine hébergé** (décision 92) : la machine. Son verdict ne touche
    /// pas au vivier — le bail est chez l'annuaire local.
    pub dehors: Option<Identifiant>,
}

/// Ce que l'annuaire retient des sondes par l'écho, en mémoire — jamais
/// rangé ni répliqué : c'est un état vivant, comme le vivier.
#[derive(Debug, Default)]
pub struct Echos {
    /// Par service d'écho tenu ici, le dernier constat.
    pub constats: std::collections::HashMap<Identifiant, ConstatDEcho>,
    /// Par service d'écho tenu ici, sa machine et l'instant de la dernière
    /// sonde lancée, en millisecondes — pour la cadence de quinze minutes.
    pub sondes: std::collections::HashMap<Identifiant, (Identifiant, u64)>,
    /// Côté racine : par machine d'un domaine hébergé, la sonde du dehors
    /// (décision 92).
    pub du_dehors: std::collections::HashMap<Identifiant, DuDehors>,
    /// Côté racine : par machine d'un domaine hébergé, ce que le journal a
    /// dit en dernier de la sonde en IPv4 (décision 107) — pour ne le redire
    /// qu'au changement.
    pub ipv4_dits: std::collections::HashMap<Identifiant, String>,
}

/// Un constat de l'écho, et quand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstatDEcho {
    /// Ce qui a été constaté.
    pub resultat: ResultatEcho,
    /// Quand, en millisecondes d'époque.
    pub a: u64,
    /// Par où la preuve est arrivée — `verifie` seulement.
    pub via: Option<asl_api::corps::ViaDEcho>,
}

/// Ce qu'une racine a sondé du dehors, vers l'écho d'une machine hébergée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuDehors {
    /// L'adresse sondée — celle que le membre a vue.
    pub cible: SocketAddr,
    /// Quand la sonde est partie.
    pub lancee: Instant,
    /// Ce qu'elle a constaté, une fois revenue.
    pub constat: Option<ConstatDEcho>,
}

/// Ce qu'une sonde par l'écho constate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultatEcho {
    /// Une réponse signée de la clé attendue : **preuve de clé vérifiée**.
    Verifie,
    /// Rien, ou rien de lisible, en trois envois.
    Injoignable,
    /// Une réponse bien formée, pour ce défi et ce sondeur, mais signée d'une
    /// AUTRE clé ou au nom d'une autre machine : quelqu'un d'autre répond à
    /// cette adresse.
    AutreCle,
}

impl ResultatEcho {
    /// Le mot de l'état par machine.
    #[must_use]
    pub const fn mot(self) -> asl_api::corps::MotDEcho {
        match self {
            Self::Verifie => asl_api::corps::MotDEcho::Verifie,
            Self::Injoignable => asl_api::corps::MotDEcho::Injoignable,
            Self::AutreCle => asl_api::corps::MotDEcho::AutreCle,
        }
    }
}

/// Combien d'envois : **trois**, d'une seconde chacun — trois secondes en
/// tout, [`ATTENTE`] (décision 92). L'UDP perd, et un seul envoi confondrait
/// perte et silence.
pub const ENVOIS_D_ECHO: u32 = 3;

/// L'attente de chaque envoi.
pub const ATTENTE_PAR_ENVOI: core::time::Duration = core::time::Duration::from_secs(1);

/// Le point qu'on a le droit de sonder par l'écho, s'il y en a un : le
/// candidat **réflexif**, en UDP — l'adresse et le port d'où le bail nous
/// parle. Jamais une adresse annoncée, pour la raison d'en tête.
#[must_use]
pub fn sondable_par_l_echo(candidat: Candidat) -> Option<SocketAddr> {
    if candidat.origine != Origine::Reflexif || candidat.protocole != Protocole::Udp {
        return None;
    }
    Some(SocketAddr::new(candidat.adresse, candidat.port.valeur()))
}

/// Ce que la réponse doit prouver : le défi de la sonde, la machine visée,
/// l'annuaire qui sonde, et la clé que l'annuaire tient pour la machine.
pub struct Attendu {
    /// Le défi envoyé.
    pub defi: asl_echo::DefiEcho,
    /// La machine visée.
    pub machine: Identifiant,
    /// L'annuaire qui sonde — celui qui a signé.
    pub sondeur: Identifiant,
    /// La clé de la machine, telle que l'annuaire la tient.
    pub cle: asl_cle::ClePublique,
}

/// **Sonde un écho** : depuis une socket UDP ÉPHÉMÈRE — pas le port
/// d'écoute de l'annuaire, sans quoi la sonde passerait le pare-feu à état
/// que le bail a ouvert et ne mesurerait que le bail (décision 92) —, trois
/// envois d'une seconde vers `ou`, et la première réponse qui prouve.
///
/// **Seule la source sondée est lue** : un datagramme d'ailleurs est ignoré.
/// Une réponse pour un autre défi ou un autre sondeur n'est pas la nôtre, et
/// l'on attend encore ; une réponse d'une autre machine, ou dont la signature
/// ne tient pas, fait [`ResultatEcho::AutreCle`] si rien de mieux ne vient.
pub async fn prouver(ou: SocketAddr, sonde: &[u8], attendu: &Attendu) -> ResultatEcho {
    let locale: SocketAddr = if ou.is_ipv6() {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
    };
    let Ok(socket) = tokio::net::UdpSocket::bind(locale).await else {
        return ResultatEcho::Injoignable;
    };
    let mut autre_cle = false;
    let mut tampon = [0_u8; 512];
    for _ in 0..ENVOIS_D_ECHO {
        let _ = socket.send_to(sonde, ou).await;
        let echeance = tokio::time::Instant::now()
            .checked_add(ATTENTE_PAR_ENVOI)
            .unwrap_or_else(tokio::time::Instant::now);
        while let Ok(Ok((lus, source))) =
            tokio::time::timeout_at(echeance, socket.recv_from(&mut tampon)).await
        {
            if source.ip().to_canonical() != ou.ip().to_canonical() || source.port() != ou.port() {
                continue;
            }
            let Ok(reponse) = asl_echo::Reponse::lire(tampon.get(..lus).unwrap_or_default()) else {
                continue;
            };
            match reponse.verifier(
                &attendu.defi,
                attendu.machine,
                attendu.sondeur,
                &attendu.cle,
            ) {
                Ok(()) => return ResultatEcho::Verifie,
                Err(asl_echo::RefusReponse::AutreMachine | asl_echo::RefusReponse::Signature) => {
                    autre_cle = true;
                }
                Err(_) => {}
            }
        }
    }
    if autre_cle {
        ResultatEcho::AutreCle
    } else {
        ResultatEcho::Injoignable
    }
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

    #[test]
    fn seul_le_reflexif_en_udp_se_sonde_par_l_echo() {
        use super::sondable_par_l_echo;
        let quoi = un_candidat(Origine::Reflexif, Protocole::Udp, "203.0.113.4");
        assert_eq!(
            sondable_par_l_echo(quoi).map(|ou| ou.to_string()),
            Some("203.0.113.4:443".to_owned())
        );
        for (origine, protocole) in [
            (Origine::Annonce, Protocole::Udp),
            (Origine::Reflexif, Protocole::Tcp),
        ] {
            assert_eq!(
                sondable_par_l_echo(un_candidat(origine, protocole, "192.168.1.20")),
                None
            );
        }
    }

    /// Un faux écho sur la boucle locale : il lit la sonde, la croit sous la
    /// clé de la racine, et répond signé de `cle` — la bonne, ou une autre.
    async fn un_echo(
        machine: asl_id::Identifiant,
        racine: &'static asl_cle::CleSecrete,
        cle: asl_cle::CleSecrete,
    ) -> std::net::SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("une socket");
        let ou = socket.local_addr().expect("une adresse");
        tokio::spawn(async move {
            let mut tampon = [0_u8; 512];
            while let Ok((lus, source)) = socket.recv_from(&mut tampon).await {
                let Ok(sonde) = asl_echo::SondeAnnuaire::lire(&tampon[..lus]) else {
                    continue;
                };
                let n = asl_cle::identifiant_de_racine(&racine.publique());
                let cle_de = |quel| (quel == n).then(|| racine.publique());
                let maintenant = sonde.emise_a();
                if let Ok(acceptee) = sonde.accepter(machine, &cle_de, maintenant) {
                    let _ = socket
                        .send_to(&acceptee.repondre(source, &cle).octets(), source)
                        .await;
                }
            }
        });
        ou
    }

    fn attendu_de(
        machine: asl_id::Identifiant,
        racine: &asl_cle::CleSecrete,
        cle: &asl_cle::CleSecrete,
    ) -> (super::Attendu, [u8; asl_echo::REQUETE_OCTETS]) {
        let defi = asl_echo::DefiEcho::depuis_octets([0x5E; 16]);
        let n = asl_cle::identifiant_de_racine(&racine.publique());
        let sonde = asl_echo::SondeAnnuaire::signer(defi, n, machine, 1_789_217_751_000, racine)
            .expect("une sonde");
        (
            super::Attendu {
                defi,
                machine,
                sondeur: n,
                cle: cle.publique(),
            },
            sonde.octets(),
        )
    }

    #[tokio::test]
    async fn un_echo_qui_signe_de_la_bonne_cle_est_verifie_et_d_une_autre_autre_cle() {
        static RACINE: std::sync::LazyLock<asl_cle::CleSecrete> =
            std::sync::LazyLock::new(|| asl_cle::CleSecrete::depuis_entropie([0x11; 32]));
        let machine = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x70; 16]);
        let cle = asl_cle::CleSecrete::depuis_entropie([0x33; 32]);

        let ou = un_echo(
            machine,
            &RACINE,
            asl_cle::CleSecrete::depuis_entropie([0x33; 32]),
        )
        .await;
        let (attendu, sonde) = attendu_de(machine, &RACINE, &cle);
        assert_eq!(
            super::prouver(ou, &sonde, &attendu).await,
            super::ResultatEcho::Verifie
        );

        let ailleurs = un_echo(
            machine,
            &RACINE,
            asl_cle::CleSecrete::depuis_entropie([0x66; 32]),
        )
        .await;
        assert_eq!(
            super::prouver(ailleurs, &sonde, &attendu).await,
            super::ResultatEcho::AutreCle,
            "quelqu'un d'autre répond à cette adresse"
        );
    }

    #[tokio::test]
    async fn un_echo_muet_est_injoignable_apres_trois_envois() {
        let racine = asl_cle::CleSecrete::depuis_entropie([0x11; 32]);
        let machine = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x70; 16]);
        let muet = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("une socket");
        let ou = muet.local_addr().expect("une adresse");
        let (attendu, sonde) = attendu_de(machine, &racine, &racine);
        let depart = std::time::Instant::now();
        assert_eq!(
            super::prouver(ou, &sonde, &attendu).await,
            super::ResultatEcho::Injoignable
        );
        assert!(
            depart.elapsed() >= super::ATTENTE,
            "trois envois d'une seconde"
        );
        let mut recus = 0;
        let mut tampon = [0_u8; 512];
        while let Ok(Ok(_)) = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            muet.recv_from(&mut tampon),
        )
        .await
        {
            recus += 1;
        }
        assert_eq!(recus, 3, "trois envois, de 384 octets");
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
