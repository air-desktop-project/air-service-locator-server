//! L'`asl-echo` dans la machine à états (`protocole.md` §3 quater,
//! décisions 90 et 92) : son point UDP se sonde, son candidat réflexif porte
//! le port observé, il se resonde toutes les quinze minutes — et rien de cela
//! ne vaut pour un autre service.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use asl_annuaire::{CADENCE_D_ECHO_MS, Faute, Instant, Session, adresse_globale, sonder_du_dehors};
use asl_id::{Genre, Identifiant};
use asl_proto::{
    Annonce, Bail, Candidat, Horodatage, NomService, Origine, PointEcoute, Port, Protocole,
    RaisonNonSonde, Verdict, VuDepuis,
};

fn service() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Service, [0x22; 16])
}

fn machine() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, [0x11; 16])
}

fn port(valeur: u16) -> Port {
    Port::depuis_u16(valeur).expect("port d'essai")
}

fn bail() -> Bail {
    Bail::nouveau(15, 45).expect("bail d'essai")
}

fn instant(millisecondes: u64) -> Instant {
    Instant::depuis_millisecondes(millisecondes)
}

fn publique() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
}

/// Le daemon, vu depuis ce port — celui que le NAT a ouvert.
fn vu() -> VuDepuis {
    VuDepuis {
        adresse: publique(),
        port: port(53211),
    }
}

fn annonce<'a>(nom: &'a str, points: &'a [PointEcoute], adresses: &'a [IpAddr]) -> Annonce<'a> {
    let nom = NomService::analyser(nom).expect("nom d'essai");
    Annonce::nouvelle(machine(), nom, points, adresses).expect("annonce d'essai")
}

fn udp() -> PointEcoute {
    PointEcoute::nouveau(Protocole::Udp, port(41877))
}

fn ouvrir(nom: &str) -> (Session, asl_annuaire::Ordres) {
    let points = [udp()];
    let locale = [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))];
    Session::ouvrir(
        service(),
        bail(),
        &annonce(nom, &points, &locale),
        vu(),
        instant(0),
    )
    .expect("ouverture")
}

#[test]
fn le_point_udp_de_l_echo_se_sonde_au_port_observe() {
    let (session, ordres) = ouvrir("asl-echo");
    assert!(session.est_un_echo());
    assert!(session.se_sonde(udp()));
    assert_eq!(ordres.a_sonder().collect::<Vec<_>>(), vec![udp()]);
    assert_eq!(
        session.reponse().expect("réponse").joignabilite[0].verdict,
        Verdict::EnCours,
        "pas encore sondé : en cours"
    );
    assert_eq!(session.vu_depuis(), vu());

    let mut candidats = [Candidat {
        protocole: Protocole::Udp,
        adresse: publique(),
        port: port(1),
        origine: Origine::Annonce,
    }; asl_annuaire::CANDIDATS_MAX];
    let combien = session.candidats(udp(), &mut candidats);
    let reflexif = candidats[..combien]
        .iter()
        .find(|candidat| candidat.origine == Origine::Reflexif)
        .expect("un candidat réflexif");
    assert_eq!(reflexif.adresse, publique());
    assert_eq!(reflexif.port, port(53211), "le port OBSERVÉ, pas l'annoncé");
    let annonce = candidats[..combien]
        .iter()
        .find(|candidat| candidat.origine == Origine::Annonce)
        .expect("un candidat annoncé");
    assert_eq!(annonce.port, port(41877), "l'annoncé garde le port local");
}

#[test]
fn une_preuve_verifiee_rend_le_point_joignable_et_une_absence_injoignable() {
    let (mut session, _) = ouvrir("asl-echo");
    let candidat = Candidat {
        protocole: Protocole::Udp,
        adresse: publique(),
        port: port(53211),
        origine: Origine::Reflexif,
    };
    let a = Horodatage::depuis_millisecondes(1_789_217_751_000);
    assert_eq!(
        session.verdict_de_sonde(udp(), Some(candidat), a, instant(10)),
        Ok(true)
    );
    let reponse = session.reponse().expect("une mesure sur UDP se rend");
    assert_eq!(
        reponse.joignabilite[0].verdict,
        Verdict::Joignable { candidat, a }
    );
    assert_eq!(
        session.verdict_de_sonde(udp(), None, a, instant(20)),
        Ok(true)
    );
    assert_eq!(
        session.reponse().expect("réponse").joignabilite[0].verdict,
        Verdict::Injoignable { a }
    );
}

#[test]
fn un_autre_service_udp_ne_se_sonde_toujours_pas() {
    let (mut session, ordres) = ouvrir("metriques");
    assert!(!session.est_un_echo());
    assert!(ordres.est_vide());
    assert_eq!(
        session.reponse().expect("réponse").joignabilite[0].verdict,
        Verdict::NonSonde {
            raison: RaisonNonSonde::ProtocoleNonSondable
        }
    );
    assert_eq!(
        session.verdict_de_sonde(udp(), None, Horodatage::depuis_millisecondes(1), instant(1)),
        Err(Faute::PointNonSondable { point: udp() })
    );
    assert!(
        session.a_resonder().est_vide(),
        "rien à resonder hors de l'écho"
    );
    let mut candidats = [Candidat {
        protocole: Protocole::Udp,
        adresse: publique(),
        port: port(1),
        origine: Origine::Annonce,
    }; asl_annuaire::CANDIDATS_MAX];
    let combien = session.candidats(udp(), &mut candidats);
    assert!(
        candidats[..combien]
            .iter()
            .all(|candidat| candidat.port == port(41877)),
        "hors de l'écho, le port annoncé"
    );
}

#[test]
fn l_echo_se_resonde_et_garde_son_verdict_en_attendant() {
    let (mut session, _) = ouvrir("asl-echo");
    let a = Horodatage::depuis_millisecondes(5);
    session
        .verdict_de_sonde(udp(), None, a, instant(1))
        .expect("un verdict");
    assert_eq!(
        session.a_resonder().a_sonder().collect::<Vec<_>>(),
        vec![udp()]
    );
    assert_eq!(
        session.reponse().expect("réponse").joignabilite[0].verdict,
        Verdict::Injoignable { a },
        "le verdict d'avant reste rendu"
    );
}

#[test]
fn une_reannonce_garde_l_echo_et_une_reannonce_sous_un_autre_nom_le_perd() {
    let (mut session, _) = ouvrir("asl-echo");
    let points = [udp()];
    let ordres = session
        .reannoncer(&annonce("asl-echo", &points, &[]), vu(), instant(5))
        .expect("réannonce");
    assert!(session.est_un_echo());
    assert!(!ordres.est_vide(), "un changement d'adresses resonde");
    session
        .reannoncer(&annonce("metriques", &points, &[]), vu(), instant(6))
        .expect("réannonce");
    assert!(!session.est_un_echo());
}

#[test]
fn une_adresse_globale_est_de_l_internet() {
    for globale in [
        "2a01:e0a:1::1",
        "2001:db8::1c2d",
        "8.8.8.8",
        "203.0.113.7",
        "::ffff:8.8.4.4",
    ] {
        let ip: IpAddr = globale.parse().unwrap();
        assert!(adresse_globale(ip), "{globale}");
    }
    for locale in [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.20",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "100.127.255.254",
        "0.0.0.0",
        "0.1.2.3",
        "255.255.255.255",
        "224.0.0.1",
        "::1",
        "::",
        "fe80::1",
        "fd00::1",
        "ff02::c",
        "::ffff:192.168.1.1",
    ] {
        let ip: IpAddr = locale.parse().unwrap();
        assert!(!adresse_globale(ip), "{locale}");
    }
    assert!(adresse_globale("100.128.0.1".parse().unwrap()));
}

#[test]
fn une_racine_sonde_du_dehors_une_fois_par_changement_et_par_quart_d_heure() {
    let cible: SocketAddr = "[2a01:e0a:1::1]:53211".parse().unwrap();
    let autre: SocketAddr = "[2a01:e0a:1::1]:53212".parse().unwrap();
    let privee: SocketAddr = "192.168.1.20:53211".parse().unwrap();
    assert!(sonder_du_dehors(cible, None, instant(0)));
    assert!(
        !sonder_du_dehors(privee, None, instant(0)),
        "jamais vers une privée"
    );
    assert!(!sonder_du_dehors(
        cible,
        Some((cible, instant(0))),
        instant(60_000)
    ));
    assert!(sonder_du_dehors(
        cible,
        Some((autre, instant(0))),
        instant(60_000)
    ));
    assert!(sonder_du_dehors(
        cible,
        Some((cible, instant(0))),
        instant(CADENCE_D_ECHO_MS)
    ));
}

// ── La passerelle (décision 97, 0.44.0) ─────────────────────────────────────

fn avec_passerelle<'a>(
    points: &'a [PointEcoute],
    adresses: &'a [IpAddr],
    port_accorde: u16,
) -> Annonce<'a> {
    annonce("asl-echo", points, adresses)
        .avec_passerelle(asl_proto::Passerelle {
            port: port(port_accorde),
            via: asl_proto::ViaPasserelle::Upnp,
        })
        .expect("l'écho porte une passerelle")
}

fn candidats_de(session: &Session) -> Vec<Candidat> {
    let mut candidats = [Candidat {
        protocole: Protocole::Udp,
        adresse: publique(),
        port: port(1),
        origine: Origine::Annonce,
    }; asl_annuaire::CANDIDATS_MAX];
    let combien = session.candidats(udp(), &mut candidats);
    candidats[..combien].to_vec()
}

#[test]
fn la_passerelle_passe_en_tete_a_l_adresse_observee() {
    let points = [udp()];
    let locales = [
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20)),
    ];
    // Un port accordé plus petit que l'observé : l'ordre ordinaire le
    // mettrait ailleurs, la passerelle le remet en tête.
    for accorde in [1_024, 60_000] {
        let (session, _) = Session::ouvrir(
            service(),
            bail(),
            &avec_passerelle(&points, &locales, accorde),
            vu(),
            instant(0),
        )
        .expect("ouverture");
        assert_eq!(session.passerelle().map(|p| p.port), Some(port(accorde)));
        let candidats = candidats_de(&session);
        assert_eq!(candidats.len(), 2 + locales.len());
        assert_eq!(
            (
                candidats[0].adresse,
                candidats[0].port,
                candidats[0].origine
            ),
            (publique(), port(accorde), Origine::Reflexif),
            "la passerelle d'abord, à l'adresse OBSERVÉE"
        );
        assert!(
            candidats[1..]
                .iter()
                .any(|c| c.origine == Origine::Reflexif && c.port == port(53211)),
            "puis le bail"
        );
    }
    // Un port accordé égal à l'observé ne fait pas deux candidats.
    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &avec_passerelle(&points, &[], 53211),
        vu(),
        instant(0),
    )
    .expect("ouverture");
    assert_eq!(candidats_de(&session).len(), 1);
}

#[test]
fn une_passerelle_nouvelle_fait_resonder_l_echo() {
    let points = [udp()];
    let (mut session, _) = ouvrir("asl-echo");
    let a = Horodatage::depuis_millisecondes(5);
    session
        .verdict_de_sonde(udp(), None, a, instant(1))
        .expect("un verdict");
    let locale = [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))];
    // Même adresse, même point, mais une passerelle : on resonde.
    let ordres = session
        .reannoncer(&avec_passerelle(&points, &locale, 51_377), vu(), instant(2))
        .expect("réannonce");
    assert!(!ordres.est_vide(), "la passerelle se mesure");
    // La même passerelle une seconde fois : rien de neuf.
    let ordres = session
        .reannoncer(&avec_passerelle(&points, &locale, 51_377), vu(), instant(3))
        .expect("réannonce");
    assert!(ordres.est_vide());
}
