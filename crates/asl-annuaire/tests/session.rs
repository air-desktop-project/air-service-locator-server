//! La vie d'un service, pilotée pas à pas.
//!
//! **C'est ici que l'heure en paramètre se paie en retour.** Éprouver une
//! expiration à la dernière milliseconde coûte une ligne ; avec une horloge
//! lue au fond d'une boucle, il faudrait attendre quarante-cinq secondes, et
//! personne n'écrirait cet essai.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_annuaire::{CANDIDATS_MAX, Etat, Faute, Instant, MotifDeDepart, Session};
use asl_id::{Genre, Identifiant};
use asl_proto::{
    Annonce, Bail, Candidat, Horodatage, NomService, Origine, PointEcoute, Port, Protocole,
    RaisonNonSonde, Verdict, VerdictNat, VuDepuis,
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

/// L'adresse publique sous laquelle l'annuaire voit le daemon.
fn publique() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
}

fn vu(adresse: IpAddr) -> VuDepuis {
    VuDepuis {
        adresse,
        port: port(51840),
    }
}

/// Une annonce, avec les points et adresses qu'on lui donne.
fn annonce<'a>(points: &'a [PointEcoute], adresses: &'a [IpAddr]) -> Annonce<'a> {
    let nom = NomService::analyser("depot").expect("nom d'essai");
    Annonce::nouvelle(machine(), nom, points, adresses).expect("annonce d'essai")
}

// ── L'ouverture ─────────────────────────────────────────────────────────────

#[test]
fn a_l_ouverture_le_tcp_est_en_cours_et_l_udp_non_sonde() {
    // N'avoir rien encore mesuré n'est PAS avoir mesuré un échec.
    let points = [
        PointEcoute::nouveau(Protocole::Tcp, port(49152)),
        PointEcoute::nouveau(Protocole::Udp, port(49152)),
    ];
    let (session, ordres) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[publique()]),
        vu(publique()),
        instant(0),
    )
    .expect("ouverture");

    let reponse = session.reponse().expect("réponse valide");
    assert_eq!(reponse.joignabilite[0].verdict, Verdict::EnCours);
    assert_eq!(
        reponse.joignabilite[1].verdict,
        Verdict::NonSonde {
            raison: RaisonNonSonde::ProtocoleNonSondable
        }
    );

    // Seul le point TCP est à sonder.
    let a_sonder: Vec<PointEcoute> = ordres.a_sonder().collect();
    assert_eq!(a_sonder, [points[0]]);
    assert!(!ordres.est_vide());
}

#[test]
fn un_identifiant_qui_n_est_pas_un_service_est_refuse() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    for genre in [
        Genre::Utilisateur,
        Genre::Appareil,
        Genre::Machine,
        Genre::Autorisation,
        Genre::Annuaire,
    ] {
        let autre = Identifiant::depuis_entropie(genre, [0x22; 16]);
        assert_eq!(
            Session::ouvrir(
                autre,
                bail(),
                &annonce(&points, &[]),
                vu(publique()),
                instant(0)
            )
            .map(|_| ()),
            Err(Faute::PasUnService { obtenu: genre })
        );
    }
}

#[test]
fn un_daemon_purement_udp_n_a_rien_a_sonder() {
    let points = [PointEcoute::nouveau(Protocole::Udp, port(53))];
    let (_, ordres) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .expect("ouverture");
    assert!(ordres.est_vide());
    assert_eq!(ordres.a_sonder().count(), 0);
}

// ── Le verdict de NAT ───────────────────────────────────────────────────────

#[test]
fn le_verdict_de_nat_compare_l_observe_a_l_annonce() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let privee = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

    // L'adresse observée figure parmi les annoncées : pas de NAT.
    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[publique(), privee]),
        vu(publique()),
        instant(0),
    )
    .unwrap();
    assert_eq!(session.derriere_nat(), VerdictNat::Non);

    // Elle n'y figure pas : NAT.
    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[privee]),
        vu(publique()),
        instant(0),
    )
    .unwrap();
    assert_eq!(session.derriere_nat(), VerdictNat::Oui);
}

#[test]
fn sans_adresse_annoncee_le_nat_est_indetermine_et_non_faux() {
    // C6 : répondre « non » sans avoir comparé serait affirmer une chose qu'on
    // n'a pas mesurée. Un daemon derrière un NAT chercherait alors la panne
    // partout sauf là où elle est.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();
    assert_eq!(session.derriere_nat(), VerdictNat::Indetermine);
}

// ── Le bail, et ce que l'heure en paramètre achète ──────────────────────────

#[test]
fn l_expiration_se_pousse_a_la_derniere_milliseconde() {
    // AVEC UNE HORLOGE LUE AU FOND D'UNE BOUCLE, CET ESSAI COÛTERAIT
    // QUARANTE-CINQ SECONDES. Ici il coûte trois lignes — et c'est exactement
    // ce que la contrainte C1 achète.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    // 45 000 ms pile : le délai n'est pas DÉPASSÉ.
    assert!(!session.expiree(instant(45_000)));
    // Une milliseconde de plus : il l'est.
    assert!(session.expiree(instant(45_001)));
}

#[test]
fn un_keepalive_repousse_l_expiration() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    assert!(session.expiree(instant(45_001)));
    session.keepalive(instant(30_000)).expect("keepalive");
    assert!(!session.expiree(instant(45_001)));
    assert!(session.expiree(instant(75_001)));
}

#[test]
fn une_horloge_qui_recule_est_refusee() {
    // Avec une horloge MONOTONE cela ne peut pas arriver : c'est donc une faute
    // de l'appelant, qui a mélangé deux horloges ou rejoué un événement.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(1_000),
    )
    .unwrap();

    assert_eq!(
        session.keepalive(instant(999)),
        Err(Faute::TempsRecule {
            precedent: instant(1_000),
            recu: instant(999),
        })
    );
    // Le même instant, lui, passe.
    assert!(session.keepalive(instant(1_000)).is_ok());
}

#[test]
fn une_session_close_n_expire_plus() {
    // Elle est partie, et pour un motif qu'on connaît déjà.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();
    session.fermer(MotifDeDepart::Volontaire);
    assert!(!session.expiree(instant(1_000_000)));
    assert_eq!(
        session.etat(instant(1_000_000)),
        Etat::Parti {
            motif: MotifDeDepart::Volontaire
        }
    );
}

// ── Les trois états ─────────────────────────────────────────────────────────

#[test]
fn les_trois_etats_et_jamais_en_ligne() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(49152))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[publique()]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    // Tant que rien n'a été mesuré : annoncé, et pas « en ligne ».
    assert_eq!(session.etat(instant(0)), Etat::Annonce);

    // Une sonde qui aboutit : joignable, avec sa date et son candidat.
    let candidat = Candidat {
        protocole: Protocole::Tcp,
        adresse: publique(),
        port: port(49152),
        origine: Origine::Reflexif,
    };
    let a = Horodatage::depuis_millisecondes(1_789_217_731_000);
    assert!(
        session
            .verdict_de_sonde(points[0], Some(candidat), a, instant(100))
            .unwrap()
    );
    assert_eq!(session.etat(instant(100)), Etat::Joignable { candidat, a });

    // L'inactivité : parti, et le motif le dit.
    assert_eq!(
        session.etat(instant(45_101)),
        Etat::Parti {
            motif: MotifDeDepart::Inactivite
        }
    );
}

#[test]
fn une_sonde_qui_echoue_ne_rend_pas_le_service_joignable() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();
    let a = Horodatage::depuis_millisecondes(2);
    assert!(
        session
            .verdict_de_sonde(points[0], None, a, instant(1))
            .unwrap()
    );
    assert_eq!(session.etat(instant(1)), Etat::Annonce);
    assert_eq!(
        session.reponse().unwrap().joignabilite[0].verdict,
        Verdict::Injoignable { a }
    );
}

#[test]
fn un_verdict_identique_ne_declenche_pas_de_poussee() {
    // Pousser une mise à jour qui ne change rien réveillerait un daemon pour
    // rien, et ferait douter de ce qui a changé quand quelque chose changera.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();
    let a = Horodatage::depuis_millisecondes(2);
    assert!(
        session
            .verdict_de_sonde(points[0], None, a, instant(1))
            .unwrap()
    );
    assert!(
        !session
            .verdict_de_sonde(points[0], None, a, instant(2))
            .unwrap()
    );
}

#[test]
fn une_sonde_sur_un_point_inconnu_ou_non_sondable_est_refusee() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();
    let a = Horodatage::depuis_millisecondes(2);

    let inconnu = PointEcoute::nouveau(Protocole::Tcp, port(2));
    assert_eq!(
        session.verdict_de_sonde(inconnu, None, a, instant(1)),
        Err(Faute::PointInconnu { point: inconnu })
    );

    // C6 : l'annuaire ne peut rien affirmer d'un point UDP.
    let udp = PointEcoute::nouveau(Protocole::Udp, port(1));
    assert_eq!(
        session.verdict_de_sonde(udp, None, a, instant(1)),
        Err(Faute::PointNonSondable { point: udp })
    );

    // Et le temps qui recule est refusé là aussi.
    assert!(matches!(
        session.verdict_de_sonde(points[0], None, a, instant(0)),
        Err(Faute::TempsRecule { .. })
    ));
}

// ── La réannonce ────────────────────────────────────────────────────────────

#[test]
fn une_reannonce_identique_garde_les_verdicts_deja_mesures() {
    // Remettre à `EnCours` perdrait une mesure déjà faite, et ferait clignoter
    // l'état d'un service à chaque fois qu'un daemon en ajoute un autre.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[publique()]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    let candidat = Candidat {
        protocole: Protocole::Tcp,
        adresse: publique(),
        port: port(1),
        origine: Origine::Reflexif,
    };
    let a = Horodatage::depuis_millisecondes(5);
    session
        .verdict_de_sonde(points[0], Some(candidat), a, instant(10))
        .unwrap();

    let ordres = session
        .reannoncer(
            &annonce(&points, &[publique()]),
            vu(publique()),
            instant(20),
        )
        .unwrap();
    assert!(ordres.est_vide(), "rien n'a changé, rien à resonder");
    assert_eq!(session.etat(instant(20)), Etat::Joignable { candidat, a });
}

#[test]
fn un_point_nouveau_est_sonde_et_les_anciens_gardes() {
    let un = PointEcoute::nouveau(Protocole::Tcp, port(1));
    let deux = PointEcoute::nouveau(Protocole::Tcp, port(2));
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&[un], &[publique()]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    let a = Horodatage::depuis_millisecondes(5);
    session.verdict_de_sonde(un, None, a, instant(10)).unwrap();

    let ordres = session
        .reannoncer(
            &annonce(&[un, deux], &[publique()]),
            vu(publique()),
            instant(20),
        )
        .unwrap();
    let a_sonder: Vec<PointEcoute> = ordres.a_sonder().collect();
    assert_eq!(a_sonder, [deux], "seul le point nouveau est à sonder");

    let reponse = session.reponse().unwrap();
    assert_eq!(reponse.joignabilite[0].verdict, Verdict::Injoignable { a });
    assert_eq!(reponse.joignabilite[1].verdict, Verdict::EnCours);
}

#[test]
fn une_migration_de_connexion_fait_tout_resonder() {
    // Les candidats ne sont plus les mêmes : ce qu'on avait mesuré ne vaut plus.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[publique()]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    let candidat = Candidat {
        protocole: Protocole::Tcp,
        adresse: publique(),
        port: port(1),
        origine: Origine::Reflexif,
    };
    session
        .verdict_de_sonde(
            points[0],
            Some(candidat),
            Horodatage::depuis_millisecondes(5),
            instant(10),
        )
        .unwrap();

    let apres = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
    let ordres = session
        .reannoncer(&annonce(&points, &[publique()]), vu(apres), instant(20))
        .unwrap();
    assert_eq!(ordres.a_sonder().count(), 1, "tout est resondé");
    assert_eq!(session.etat(instant(20)), Etat::Annonce);
    // Et le verdict de NAT a changé avec l'adresse observée.
    assert_eq!(session.derriere_nat(), VerdictNat::Oui);
}

#[test]
fn un_changement_d_adresses_annoncees_fait_tout_resonder() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[publique()]),
        vu(publique()),
        instant(0),
    )
    .unwrap();
    session
        .verdict_de_sonde(
            points[0],
            None,
            Horodatage::depuis_millisecondes(5),
            instant(10),
        )
        .unwrap();

    let autre = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    let ordres = session
        .reannoncer(
            &annonce(&points, &[publique(), autre]),
            vu(publique()),
            instant(20),
        )
        .unwrap();
    assert_eq!(ordres.a_sonder().count(), 1);
    assert_eq!(
        session.reponse().unwrap().joignabilite[0].verdict,
        Verdict::EnCours
    );
}

#[test]
fn une_reannonce_avec_une_horloge_qui_recule_est_refusee() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(100),
    )
    .unwrap();
    assert!(matches!(
        session.reannoncer(&annonce(&points, &[]), vu(publique()), instant(99)),
        Err(Faute::TempsRecule { .. })
    ));
}

#[test]
fn un_point_udp_ajoute_par_reannonce_n_est_pas_sonde() {
    let tcp = PointEcoute::nouveau(Protocole::Tcp, port(1));
    let udp = PointEcoute::nouveau(Protocole::Udp, port(1));
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&[tcp], &[publique()]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    let ordres = session
        .reannoncer(
            &annonce(&[tcp, udp], &[publique()]),
            vu(publique()),
            instant(1),
        )
        .unwrap();
    assert!(ordres.est_vide());
    assert_eq!(
        session.reponse().unwrap().joignabilite[1].verdict,
        Verdict::NonSonde {
            raison: RaisonNonSonde::ProtocoleNonSondable
        }
    );
}

// ── Les candidats ───────────────────────────────────────────────────────────

#[test]
fn les_candidats_portent_le_port_annonce_et_non_le_port_observe() {
    // Le port source d'une connexion QUIC n'est pas celui du service :
    // l'employer désignerait la socket du client.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(49152))];
    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()), // port observé : 51840
        instant(0),
    )
    .unwrap();

    let mut sortie = [Candidat {
        protocole: Protocole::Tcp,
        adresse: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: port(1),
        origine: Origine::Annonce,
    }; CANDIDATS_MAX];
    let compte = session.candidats(points[0], &mut sortie);

    assert_eq!(compte, 1);
    assert_eq!(sortie[0].port, port(49152));
    assert_eq!(sortie[0].adresse, publique());
    assert_eq!(sortie[0].origine, Origine::Reflexif);
}

#[test]
fn les_candidats_sont_ordonnes_ipv6_puis_reflexif_d_abord() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(80))];
    let reflexif_v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
    let annoncee_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    let annoncee_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[annoncee_v4, annoncee_v6]),
        vu(reflexif_v4),
        instant(0),
    )
    .unwrap();

    let mut sortie = [Candidat {
        protocole: Protocole::Tcp,
        adresse: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: port(1),
        origine: Origine::Annonce,
    }; CANDIDATS_MAX];
    let compte = session.candidats(points[0], &mut sortie);

    assert_eq!(compte, 3);
    // IPv6 d'abord, quelle que soit son origine.
    assert_eq!(sortie[0].adresse, annoncee_v6);
    // Puis l'IPv4 réflexive avant l'IPv4 annoncée.
    assert_eq!(sortie[1].adresse, reflexif_v4);
    assert_eq!(sortie[1].origine, Origine::Reflexif);
    assert_eq!(sortie[2].adresse, annoncee_v4);
}

#[test]
fn un_tampon_de_candidats_trop_petit_ne_deborde_pas() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(80))];
    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[publique()]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    let mut rien: [Candidat; 0] = [];
    assert_eq!(session.candidats(points[0], &mut rien), 0);
}

// ── La réponse et la poussée ────────────────────────────────────────────────

#[test]
fn la_session_rend_une_reponse_et_une_poussee_coherentes() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(49152))];
    let (session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[publique()]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    let reponse = session.reponse().expect("réponse valide");
    assert_eq!(reponse.service, service());
    assert_eq!(reponse.bail, bail());
    assert_eq!(reponse.vu_depuis, vu(publique()));
    assert_eq!(reponse.derriere_nat, VerdictNat::Non);

    let poussee = session.poussee().expect("poussée valide");
    assert_eq!(poussee.vu_depuis, reponse.vu_depuis);
    assert_eq!(poussee.derriere_nat, reponse.derriere_nat);
    assert_eq!(poussee.joignabilite, reponse.joignabilite);
    assert!(poussee.attend_encore());

    assert_eq!(session.service(), service());
}

#[test]
fn l_ecoulement_ne_devient_jamais_negatif() {
    assert_eq!(instant(10).depuis(instant(4)), 6);
    assert_eq!(instant(4).depuis(instant(10)), 0);
    assert_eq!(instant(7).millisecondes(), 7);
}

// ── L'expiration ne se défait pas ───────────────────────────────────────────

#[test]
fn un_keepalive_tardif_ne_ressuscite_pas_une_session_expiree() {
    // TROUVÉ PAR LE FUZZ, PAS PAR LA RELECTURE. Sans ce verrou, une session
    // expirée redevenait vivante au premier signe de vie : l'état passait de
    // `parti` à `annoncé` puis de nouveau à `parti`. Un service qui clignote,
    // alors qu'on a déjà dit à ses clients qu'il était parti.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    assert!(session.expiree(instant(45_001)));
    assert_eq!(
        session.keepalive(instant(45_001)),
        Err(Faute::SessionExpiree {
            dernier_signe: instant(0)
        })
    );
    // Et elle reste expirée.
    assert!(session.expiree(instant(45_001)));
    assert_eq!(
        session.etat(instant(45_001)),
        Etat::Parti {
            motif: MotifDeDepart::Inactivite
        }
    );
}

#[test]
fn une_reannonce_et_une_sonde_tardives_sont_refusees_aussi() {
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(0),
    )
    .unwrap();

    assert!(matches!(
        session.reannoncer(&annonce(&points, &[]), vu(publique()), instant(45_001)),
        Err(Faute::SessionExpiree { .. })
    ));
    assert!(matches!(
        session.verdict_de_sonde(
            points[0],
            None,
            Horodatage::depuis_millisecondes(1),
            instant(45_001)
        ),
        Err(Faute::SessionExpiree { .. })
    ));
}

#[test]
fn le_temps_qui_recule_est_signale_avant_l_expiration() {
    // L'ordre des deux contrôles compte : sur une horloge monotone, un temps qui
    // recule ne peut pas arriver — c'est donc le symptôme le plus grave, et le
    // signaler comme une expiration enverrait chercher au mauvais endroit.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let (mut session, _) = Session::ouvrir(
        service(),
        bail(),
        &annonce(&points, &[]),
        vu(publique()),
        instant(100_000),
    )
    .unwrap();
    assert!(matches!(
        session.keepalive(instant(1)),
        Err(Faute::TempsRecule { .. })
    ));
}
