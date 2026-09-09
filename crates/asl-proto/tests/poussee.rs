//! La poussée de verdict — ce que l'annuaire envoie de sa propre initiative.
//!
//! **C'est le message qui referme `en_cours`.** Sans lui, un daemon qui reçoit
//! « la sonde n'a pas fini » n'apprendrait jamais le résultat.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_proto::{
    Candidat, Erreur, Horodatage, Joignabilite, MESSAGE_MAX, Origine, POINTS_MAX, PointEcoute,
    Port, Poussee, Protocole, RaisonNonSonde, TamponsReponse, Verdict, VerdictNat, VuDepuis,
};

fn port(valeur: u16) -> Port {
    Port::depuis_u16(valeur).expect("port d'essai valide")
}

fn vu_depuis() -> VuDepuis {
    VuDepuis {
        adresse: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        port: port(51840),
    }
}

fn decoder(texte: &str) -> Result<(), Erreur> {
    let mut tampons = TamponsReponse::nouveaux();
    Poussee::decoder(texte.as_bytes(), &mut tampons).map(|_| ())
}

const MESSAGE: &str = r#"{"vu_depuis":{"adresse":"2001:db8::1","port":51840},"derriere_nat":"non","joignabilite":[{"protocole":"tcp","port":49152,"verdict":"joignable","candidat":"[2001:db8::1]:49152","origine":"reflexif","a":1789217731000}]}"#;

#[test]
fn une_poussee_ordinaire_se_decode_et_se_reecrit_a_l_identique() {
    let mut tampons = TamponsReponse::nouveaux();
    let poussee = Poussee::decoder(MESSAGE.as_bytes(), &mut tampons).expect("doit se décoder");

    assert_eq!(poussee.vu_depuis, vu_depuis());
    assert_eq!(poussee.derriere_nat, VerdictNat::Non);
    assert_eq!(poussee.joignabilite.len(), 1);
    assert!(!poussee.attend_encore());

    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = poussee.encoder(&mut sortie).unwrap();
    assert_eq!(core::str::from_utf8(&sortie[..ecrits]).unwrap(), MESSAGE);
}

#[test]
fn elle_ne_porte_aucun_identifiant_de_service() {
    // La connexion le détermine déjà. L'y remettre serait un champ qui peut
    // CONTREDIRE la connexion sur laquelle il arrive.
    assert!(!MESSAGE.contains("service"));
    let avec = r#"{"service":"s-00000000000000000000000000","vu_depuis":{"adresse":"10.0.0.1","port":1},"derriere_nat":"non","joignabilite":[{"protocole":"tcp","port":80,"verdict":"en_cours"}]}"#;
    assert!(matches!(decoder(avec), Err(Erreur::ChampInconnu { .. })));
}

#[test]
fn elle_ne_porte_pas_le_bail() {
    // Il est accordé une fois, à l'annonce. Le changer en cours de connexion
    // demanderait son propre message et sa propre règle.
    for champ in [r#""keepalive_secondes":15"#, r#""inactivite_secondes":45"#] {
        let texte = format!(
            r#"{{{champ},"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":80,"verdict":"en_cours"}}]}}"#
        );
        assert!(
            matches!(decoder(&texte), Err(Erreur::ChampInconnu { .. })),
            "{champ}"
        );
    }
}

#[test]
fn attend_encore_distingue_la_sonde_finie_de_la_sonde_en_cours() {
    // Sans cela, un daemon ne saurait pas s'il faut attendre une autre poussée.
    let en_cours = [Joignabilite {
        point: PointEcoute::nouveau(Protocole::Tcp, port(80)),
        verdict: Verdict::EnCours,
    }];
    let poussee = Poussee::nouvelle(vu_depuis(), VerdictNat::Non, &en_cours).unwrap();
    assert!(poussee.attend_encore());

    let fini = [Joignabilite {
        point: PointEcoute::nouveau(Protocole::Tcp, port(80)),
        verdict: Verdict::Injoignable {
            a: Horodatage::depuis_millisecondes(1),
        },
    }];
    let poussee = Poussee::nouvelle(vu_depuis(), VerdictNat::Non, &fini).unwrap();
    assert!(!poussee.attend_encore());
}

#[test]
fn les_invariants_sont_ceux_de_la_reponse() {
    // Ils sont écrits une seule fois et appliqués aux deux : deux copies
    // finiraient par diverger, et celle qu'on oublie laisse passer ce que
    // l'autre refuse.
    assert_eq!(
        Poussee::nouvelle(vu_depuis(), VerdictNat::Non, &[]),
        Err(Erreur::AucuneJoignabilite)
    );

    let trop: Vec<Joignabilite> = (1..=u16::try_from(POINTS_MAX + 1).unwrap())
        .map(|n| Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port(n)),
            verdict: Verdict::EnCours,
        })
        .collect();
    assert_eq!(
        Poussee::nouvelle(vu_depuis(), VerdictNat::Non, &trop),
        Err(Erreur::TropDeJoignabilites {
            obtenu: POINTS_MAX + 1
        })
    );

    let doublon = [
        Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port(1)),
            verdict: Verdict::EnCours,
        },
        Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port(1)),
            verdict: Verdict::EnCours,
        },
    ];
    assert_eq!(
        Poussee::nouvelle(vu_depuis(), VerdictNat::Non, &doublon),
        Err(Erreur::PointEnDouble)
    );

    // C6 : un point UDP ne peut pas être dit mesuré, ici comme là-bas.
    let impossible = [Joignabilite {
        point: PointEcoute::nouveau(Protocole::Udp, port(1)),
        verdict: Verdict::Injoignable {
            a: Horodatage::depuis_millisecondes(1),
        },
    }];
    assert_eq!(
        Poussee::nouvelle(vu_depuis(), VerdictNat::Non, &impossible),
        Err(Erreur::VerdictImpossible)
    );
}

#[test]
fn le_verdict_de_nat_peut_changer_avec_la_migration() {
    // QUIC fait migrer une connexion quand la machine change d'adresse ; ce
    // message est ce qui le dit au daemon.
    let entrees = [Joignabilite {
        point: PointEcoute::nouveau(Protocole::Tcp, port(80)),
        verdict: Verdict::Joignable {
            candidat: Candidat {
                protocole: Protocole::Tcp,
                adresse: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)),
                port: port(80),
                origine: Origine::Reflexif,
            },
            a: Horodatage::depuis_millisecondes(2),
        },
    }];
    let apres_bascule = VuDepuis {
        adresse: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)),
        port: port(61003),
    };
    let poussee = Poussee::nouvelle(apres_bascule, VerdictNat::Oui, &entrees).unwrap();
    assert!(!poussee.vu_depuis.est_ipv6());
    assert_eq!(poussee.derriere_nat, VerdictNat::Oui);

    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = poussee.encoder(&mut sortie).unwrap();
    let rendu = core::str::from_utf8(&sortie[..ecrits]).unwrap();
    assert!(rendu.contains(r#""derriere_nat":"oui""#), "{rendu}");
    assert!(decoder(rendu).is_ok());
}

#[test]
fn les_quatre_verdicts_font_l_aller_retour_dans_une_poussee() {
    for fragment in [
        r#""verdict":"joignable","candidat":"10.0.0.1:80","origine":"annonce","a":1"#,
        r#""verdict":"injoignable","a":2"#,
        r#""verdict":"non_sonde","raison":"protocole_non_sondable""#,
        r#""verdict":"en_cours""#,
    ] {
        let texte = format!(
            r#"{{"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"indetermine","joignabilite":[{{"protocole":"tcp","port":80,{fragment}}}]}}"#
        );
        let mut tampons = TamponsReponse::nouveaux();
        let poussee = Poussee::decoder(texte.as_bytes(), &mut tampons)
            .unwrap_or_else(|e| panic!("{fragment} : {e}"));
        let mut sortie = [0_u8; MESSAGE_MAX];
        let ecrits = poussee.encoder(&mut sortie).unwrap();
        assert_eq!(
            core::str::from_utf8(&sortie[..ecrits]).unwrap(),
            texte,
            "{fragment}"
        );
    }
}

#[test]
fn les_fautes_de_forme_de_la_poussee() {
    assert!(matches!(
        decoder("[]"),
        Err(Erreur::JsonAttendu {
            attendu: "un objet",
            ..
        })
    ));
    assert!(matches!(
        decoder("{1:2}"),
        Err(Erreur::JsonAttendu {
            attendu: "une chaîne",
            ..
        })
    ));
    assert!(matches!(
        decoder(r#"{"vu_depuis"}"#),
        Err(Erreur::JsonAttendu {
            attendu: "deux-points",
            ..
        })
    ));
    assert!(matches!(
        decoder(r#"{"derriere_nat":1}"#),
        Err(Erreur::JsonAttendu {
            attendu: "une chaîne",
            ..
        })
    ));
    assert!(matches!(
        decoder(r#"{"vu_depuis":{"adresse":"10.0.0.1","port":1} "derriere_nat":"non"}"#),
        Err(Erreur::JsonAttendu {
            attendu: "une virgule ou la fin de l'objet",
            ..
        })
    ));
    assert!(matches!(
        decoder(
            r#"{"derriere_nat":"non","derriere_nat":"oui","vu_depuis":{"adresse":"10.0.0.1","port":1}}"#
        ),
        Err(Erreur::ChampEnDouble { .. })
    ));
    assert_eq!(
        decoder("{}"),
        Err(Erreur::ChampManquant { nom: "vu_depuis" })
    );
    assert_eq!(
        decoder(r#"{"vu_depuis":{"adresse":"10.0.0.1","port":1}}"#),
        Err(Erreur::ChampManquant {
            nom: "derriere_nat"
        })
    );
    assert_eq!(
        decoder(r#"{"vu_depuis":{"adresse":"10.0.0.1","port":1},"derriere_nat":"non"}"#),
        Err(Erreur::ChampManquant {
            nom: "joignabilite"
        })
    );

    let mut trop = MESSAGE.to_owned();
    trop.push_str("{}");
    assert!(matches!(decoder(&trop), Err(Erreur::DonneesEnTrop { .. })));

    let long = vec![b' '; MESSAGE_MAX + 1];
    let mut tampons = TamponsReponse::nouveaux();
    assert_eq!(
        Poussee::decoder(&long, &mut tampons).map(|_| ()),
        Err(Erreur::MessageTropLong {
            obtenue: MESSAGE_MAX + 1
        })
    );
}

#[test]
fn un_tampon_trop_petit_est_dit() {
    let mut tampons = TamponsReponse::nouveaux();
    let poussee = Poussee::decoder(MESSAGE.as_bytes(), &mut tampons).unwrap();
    let mut court = vec![0_u8; MESSAGE.len() - 1];
    assert_eq!(poussee.encoder(&mut court), Err(Erreur::TamponTropPetit));
}

#[test]
fn une_poussee_a_plusieurs_verdicts_les_separe() {
    let entrees = [
        Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port(80)),
            verdict: Verdict::NonSonde {
                raison: RaisonNonSonde::ProtocoleNonSondable,
            },
        },
        Joignabilite {
            point: PointEcoute::nouveau(Protocole::Udp, port(80)),
            verdict: Verdict::NonSonde {
                raison: RaisonNonSonde::ProtocoleNonSondable,
            },
        },
    ];
    let poussee = Poussee::nouvelle(vu_depuis(), VerdictNat::Non, &entrees).unwrap();
    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = poussee.encoder(&mut sortie).unwrap();
    let rendu = core::str::from_utf8(&sortie[..ecrits]).unwrap();
    assert!(rendu.contains("},{"), "{rendu}");
    assert!(decoder(rendu).is_ok());
}

#[test]
fn les_trois_sous_decodeurs_propagent_leurs_refus() {
    // Chaque `?` du décodeur de poussée a son cas : ce qui n'est pas atteint par
    // un essai est du code qu'on croit éprouvé.
    assert!(matches!(
        decoder(
            r#"{"vu_depuis":{"adresse":"pas-une-adresse","port":1},"derriere_nat":"non","joignabilite":[]}"#
        ),
        Err(Erreur::AdresseInvalide { .. })
    ));
    assert_eq!(
        decoder(
            r#"{"vu_depuis":{"adresse":"10.0.0.1","port":1},"derriere_nat":"peut-etre","joignabilite":[]}"#
        ),
        Err(Erreur::VerdictNatInconnu)
    );
    assert_eq!(
        decoder(
            r#"{"vu_depuis":{"adresse":"10.0.0.1","port":1},"derriere_nat":"non","joignabilite":[{"protocole":"sctp","port":80,"verdict":"en_cours"}]}"#
        ),
        Err(Erreur::ProtocoleInconnu)
    );
}
