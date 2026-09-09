//! Le message de réponse, et **C6 traduite en types**.
//!
//! La contrainte dit que l'annuaire n'affirme jamais ce qu'il n'a pas mesuré.
//! Ces essais fixent les trois endroits où cette règle cesse d'être une consigne
//! de revue pour devenir impossible à enfreindre :
//!
//! - `Joignable` porte sa date et son candidat DANS la variante ;
//! - `derriere_nat` a un troisième état, `indetermine` ;
//! - un point UDP ne peut être ni `joignable` ni `injoignable`.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_id::{Genre, Identifiant};
use asl_proto::{
    Bail, Candidat, Erreur, Horodatage, Joignabilite, KEEPALIVE_MAX, MESSAGE_MAX, Origine,
    POINTS_MAX, PointEcoute, Port, Protocole, RaisonNonSonde, Reponse, TamponsReponse, Verdict,
    VerdictNat, VuDepuis,
};

fn service() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Service, [0x22; 16])
}

fn service_texte() -> String {
    service().texte().as_str().to_owned()
}

fn port(valeur: u16) -> Port {
    Port::depuis_u16(valeur).expect("port d'essai valide")
}

fn bail() -> Bail {
    Bail::nouveau(15, 45).expect("bail d'essai valide")
}

fn vu_depuis() -> VuDepuis {
    VuDepuis {
        adresse: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        port: port(51840),
    }
}

fn decoder(texte: &str) -> Result<(), Erreur> {
    let mut tampons = TamponsReponse::nouveaux();
    Reponse::decoder(texte.as_bytes(), &mut tampons).map(|_| ())
}

// ── Le bail ─────────────────────────────────────────────────────────────────

#[test]
fn un_keepalive_nul_n_est_pas_une_cadence() {
    assert_eq!(Bail::nouveau(0, 100), Err(Erreur::KeepaliveNul));
}

#[test]
fn le_keepalive_est_borne() {
    assert!(Bail::nouveau(KEEPALIVE_MAX, KEEPALIVE_MAX).is_err());
    assert_eq!(
        Bail::nouveau(KEEPALIVE_MAX + 1, 65535),
        Err(Erreur::KeepaliveTropLong {
            obtenu: KEEPALIVE_MAX + 1
        })
    );
}

#[test]
fn l_inactivite_tolere_au_moins_un_keepalive_manque() {
    // À un pour un, la première perte de paquet tue un daemon sain.
    assert_eq!(
        Bail::nouveau(15, 15),
        Err(Erreur::InactiviteTropCourte {
            obtenue: 15,
            minimum: 30
        })
    );
    assert_eq!(
        Bail::nouveau(15, 29),
        Err(Erreur::InactiviteTropCourte {
            obtenue: 29,
            minimum: 30
        })
    );
    // Deux pour un passe, trois pour un est la politique du produit.
    assert!(Bail::nouveau(15, 30).is_ok());
    let arrete = bail();
    assert_eq!(arrete.keepalive_secondes(), 15);
    assert_eq!(arrete.inactivite_secondes(), 45);
}

#[test]
fn le_double_ne_deborde_pas() {
    // `saturating_mul` : un débordement rendrait acceptable ce que la borne
    // refuse. La borne du keepalive l'empêche déjà, et la ceinture reste.
    assert!(Bail::nouveau(KEEPALIVE_MAX, u16::MAX).is_ok());
}

// ── C6 : le verdict de NAT n'est pas un booléen ─────────────────────────────

#[test]
fn le_verdict_de_nat_a_trois_etats() {
    // Un booléen forcerait à répondre « non » quand on n'a rien pu comparer.
    for (verdict, texte) in [
        (VerdictNat::Non, "non"),
        (VerdictNat::Oui, "oui"),
        (VerdictNat::Indetermine, "indetermine"),
    ] {
        assert_eq!(verdict.texte(), texte);
        assert_eq!(VerdictNat::analyser(texte), Ok(verdict));
        assert_eq!(format!("{verdict}"), texte);
    }
    assert_eq!(VerdictNat::analyser("true"), Err(Erreur::VerdictNatInconnu));
    assert_eq!(VerdictNat::analyser("Non"), Err(Erreur::VerdictNatInconnu));
}

// ── C6 : un point UDP ne se mesure pas ──────────────────────────────────────

#[test]
fn un_point_udp_ne_peut_etre_ni_joignable_ni_injoignable() {
    // C'est l'invariant que ce type existe pour tenir : l'annuaire n'a rien
    // mesuré, donc il ne peut rien affirmer.
    let candidat = Candidat {
        protocole: Protocole::Udp,
        adresse: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)),
        port: port(49152),
        origine: Origine::Reflexif,
    };
    let instant = Horodatage::depuis_millisecondes(1_789_217_731_000);

    for verdict in [
        Verdict::Joignable {
            candidat,
            a: instant,
        },
        Verdict::Injoignable { a: instant },
    ] {
        let entrees = [Joignabilite {
            point: PointEcoute::nouveau(Protocole::Udp, port(49152)),
            verdict,
        }];
        assert_eq!(
            Reponse::nouvelle(service(), bail(), vu_depuis(), VerdictNat::Non, &entrees),
            Err(Erreur::VerdictImpossible),
            "{verdict:?}"
        );
    }

    // Les deux verdicts qui n'affirment aucune mesure passent, eux.
    for verdict in [
        Verdict::NonSonde {
            raison: RaisonNonSonde::ProtocoleNonSondable,
        },
        Verdict::EnCours,
    ] {
        let entrees = [Joignabilite {
            point: PointEcoute::nouveau(Protocole::Udp, port(49152)),
            verdict,
        }];
        assert!(
            Reponse::nouvelle(service(), bail(), vu_depuis(), VerdictNat::Non, &entrees).is_ok(),
            "{verdict:?}"
        );
    }
}

#[test]
fn la_mesure_n_existe_que_pour_les_verdicts_qui_en_portent_une() {
    let instant = Horodatage::depuis_millisecondes(7);
    let candidat = Candidat {
        protocole: Protocole::Tcp,
        adresse: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: port(1),
        origine: Origine::Annonce,
    };
    assert_eq!(
        Verdict::Joignable {
            candidat,
            a: instant
        }
        .mesure_a(),
        Some(instant)
    );
    assert_eq!(
        Verdict::Injoignable { a: instant }.mesure_a(),
        Some(instant)
    );
    assert_eq!(
        Verdict::NonSonde {
            raison: RaisonNonSonde::ProtocoleNonSondable
        }
        .mesure_a(),
        None
    );
    assert_eq!(Verdict::EnCours.mesure_a(), None);
}

// ── La validation de la réponse ─────────────────────────────────────────────

#[test]
fn une_reponse_ordinaire_passe() {
    let entrees = [
        Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port(49152)),
            verdict: Verdict::Joignable {
                candidat: Candidat {
                    protocole: Protocole::Tcp,
                    adresse: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    port: port(49152),
                    origine: Origine::Reflexif,
                },
                a: Horodatage::depuis_millisecondes(1_789_217_731_000),
            },
        },
        Joignabilite {
            point: PointEcoute::nouveau(Protocole::Udp, port(49152)),
            verdict: Verdict::NonSonde {
                raison: RaisonNonSonde::ProtocoleNonSondable,
            },
        },
    ];
    let reponse =
        Reponse::nouvelle(service(), bail(), vu_depuis(), VerdictNat::Non, &entrees).unwrap();
    assert!(reponse.un_point_est_joignable());
    assert!(reponse.vu_depuis.est_ipv6());
}

#[test]
fn un_identifiant_qui_n_est_pas_un_service_est_refuse() {
    let entrees = [Joignabilite {
        point: PointEcoute::nouveau(Protocole::Tcp, port(1)),
        verdict: Verdict::EnCours,
    }];
    for genre in [
        Genre::Utilisateur,
        Genre::Appareil,
        Genre::Machine,
        Genre::Autorisation,
        Genre::Annuaire,
    ] {
        let autre = Identifiant::depuis_entropie(genre, [0x22; 16]);
        assert_eq!(
            Reponse::nouvelle(autre, bail(), vu_depuis(), VerdictNat::Non, &entrees),
            Err(Erreur::PasUnService { obtenu: genre })
        );
    }
}

#[test]
fn les_verdicts_sont_bornes_et_sans_doublon() {
    assert_eq!(
        Reponse::nouvelle(service(), bail(), vu_depuis(), VerdictNat::Non, &[]),
        Err(Erreur::AucuneJoignabilite)
    );

    let trop: Vec<Joignabilite> = (1..=u16::try_from(POINTS_MAX + 1).unwrap())
        .map(|n| Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port(n)),
            verdict: Verdict::EnCours,
        })
        .collect();
    assert_eq!(
        Reponse::nouvelle(service(), bail(), vu_depuis(), VerdictNat::Non, &trop),
        Err(Erreur::TropDeJoignabilites {
            obtenu: POINTS_MAX + 1
        })
    );

    // Deux verdicts pour le même point, ce sont deux réponses à une question.
    let doublon = [
        Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port(1)),
            verdict: Verdict::EnCours,
        },
        Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port(1)),
            verdict: Verdict::NonSonde {
                raison: RaisonNonSonde::ProtocoleNonSondable,
            },
        },
    ];
    assert_eq!(
        Reponse::nouvelle(service(), bail(), vu_depuis(), VerdictNat::Non, &doublon),
        Err(Erreur::PointEnDouble)
    );
}

#[test]
fn aucun_point_joignable_se_dit_aussi() {
    let entrees = [Joignabilite {
        point: PointEcoute::nouveau(Protocole::Tcp, port(1)),
        verdict: Verdict::Injoignable {
            a: Horodatage::depuis_millisecondes(1),
        },
    }];
    let reponse =
        Reponse::nouvelle(service(), bail(), vu_depuis(), VerdictNat::Oui, &entrees).unwrap();
    assert!(!reponse.un_point_est_joignable());
}

// ── Le cadrage ──────────────────────────────────────────────────────────────

fn message_valide() -> String {
    format!(
        r#"{{"service":"{}","keepalive_secondes":15,"inactivite_secondes":45,"vu_depuis":{{"adresse":"2001:db8::1","port":51840}},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":49152,"verdict":"joignable","candidat":"[2001:db8::1]:49152","origine":"reflexif","a":1789217731000}},{{"protocole":"udp","port":49152,"verdict":"non_sonde","raison":"protocole_non_sondable"}}]}}"#,
        service_texte()
    )
}

#[test]
fn un_message_ordinaire_se_decode_et_se_reecrit_a_l_identique() {
    let texte = message_valide();
    let mut tampons = TamponsReponse::nouveaux();
    let reponse = Reponse::decoder(texte.as_bytes(), &mut tampons).expect("doit se décoder");

    assert_eq!(reponse.service, service());
    assert_eq!(reponse.bail.keepalive_secondes(), 15);
    assert_eq!(reponse.derriere_nat, VerdictNat::Non);
    assert_eq!(reponse.joignabilite.len(), 2);
    assert!(reponse.un_point_est_joignable());

    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = reponse.encoder(&mut sortie).unwrap();
    assert_eq!(core::str::from_utf8(&sortie[..ecrits]).unwrap(), texte);
}

#[test]
fn les_quatre_verdicts_font_l_aller_retour() {
    for (fragment, attendu) in [
        (
            r#""verdict":"joignable","candidat":"203.0.113.4:80","origine":"annonce","a":1"#,
            "joignable",
        ),
        (r#""verdict":"injoignable","a":2"#, "injoignable"),
        (
            r#""verdict":"non_sonde","raison":"protocole_non_sondable""#,
            "non_sonde",
        ),
        (r#""verdict":"en_cours""#, "en_cours"),
    ] {
        let texte = format!(
            r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"indetermine","joignabilite":[{{"protocole":"tcp","port":80,{fragment}}}]}}"#,
            service_texte()
        );
        let mut tampons = TamponsReponse::nouveaux();
        let reponse = Reponse::decoder(texte.as_bytes(), &mut tampons)
            .unwrap_or_else(|e| panic!("{attendu} : {e}"));
        assert_eq!(reponse.joignabilite[0].verdict.texte(), attendu);

        let mut sortie = [0_u8; MESSAGE_MAX];
        let ecrits = reponse.encoder(&mut sortie).unwrap();
        assert_eq!(
            core::str::from_utf8(&sortie[..ecrits]).unwrap(),
            texte,
            "{attendu}"
        );
    }
}

#[test]
fn un_champ_hors_de_propos_est_refuse() {
    // L'émetteur dirait quelque chose que le verdict ne peut pas porter.
    let cas = [
        r#""verdict":"en_cours","a":1"#,
        r#""verdict":"en_cours","candidat":"10.0.0.1:1","origine":"annonce""#,
        r#""verdict":"en_cours","raison":"protocole_non_sondable""#,
        r#""verdict":"injoignable","a":1,"candidat":"10.0.0.1:1""#,
        r#""verdict":"injoignable","a":1,"origine":"annonce""#,
        r#""verdict":"injoignable","a":1,"raison":"protocole_non_sondable""#,
        r#""verdict":"non_sonde","raison":"protocole_non_sondable","a":1"#,
        r#""verdict":"non_sonde","raison":"protocole_non_sondable","candidat":"10.0.0.1:1""#,
        r#""verdict":"non_sonde","raison":"protocole_non_sondable","origine":"annonce""#,
        r#""verdict":"joignable","candidat":"10.0.0.1:1","origine":"annonce","a":1,"raison":"protocole_non_sondable""#,
    ];
    for fragment in cas {
        let texte = format!(
            r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":80,{fragment}}}]}}"#,
            service_texte()
        );
        assert!(
            matches!(decoder(&texte), Err(Erreur::ChampHorsPropos { .. })),
            "{fragment}"
        );
    }
}

#[test]
fn chaque_verdict_exige_ses_champs() {
    for (fragment, manquant) in [
        (
            r#""verdict":"joignable","origine":"annonce","a":1"#,
            "candidat",
        ),
        (
            r#""verdict":"joignable","candidat":"10.0.0.1:1","a":1"#,
            "origine",
        ),
        (
            r#""verdict":"joignable","candidat":"10.0.0.1:1","origine":"annonce""#,
            "a",
        ),
        (r#""verdict":"injoignable""#, "a"),
        (r#""verdict":"non_sonde""#, "raison"),
    ] {
        let texte = format!(
            r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":80,{fragment}}}]}}"#,
            service_texte()
        );
        assert_eq!(
            decoder(&texte),
            Err(Erreur::ChampManquant { nom: manquant }),
            "{fragment}"
        );
    }
}

#[test]
fn les_verdicts_et_raisons_inconnus_sont_refuses() {
    let base = |fragment: &str| {
        format!(
            r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":80,{fragment}}}]}}"#,
            service_texte()
        )
    };
    assert_eq!(
        decoder(&base(r#""verdict":"peut-etre""#)),
        Err(Erreur::VerdictInconnu)
    );
    assert_eq!(
        decoder(&base(r#""verdict":"non_sonde","raison":"parce_que""#)),
        Err(Erreur::RaisonInconnue)
    );
    assert_eq!(
        decoder(&base(
            r#""verdict":"joignable","candidat":"10.0.0.1:1","origine":"ailleurs","a":1"#
        )),
        Err(Erreur::OrigineInconnue)
    );
    // La VARIANTE est épinglée, pas le décalage : un numéro d'octet exact se
    // casse au premier caractère ajouté au message d'essai, et n'apprend rien
    // de plus sur le comportement.
    assert!(matches!(
        decoder(&base(
            r#""verdict":"joignable","candidat":"pas-une-adresse","origine":"annonce","a":1"#
        )),
        Err(Erreur::CandidatInvalide { .. })
    ));
}

// ── Les fautes de forme du message de réponse ───────────────────────────────

/// Un message de réponse dont on remplace un fragment.
fn message(corps: &str) -> String {
    format!(r#"{{"service":"{}",{corps}}}"#, service_texte())
}

#[test]
fn les_memes_trois_refus_qu_a_l_annonce() {
    // Champ en double au premier niveau.
    assert!(matches!(
        decoder(&message(
            r#""keepalive_secondes":1,"keepalive_secondes":2,"inactivite_secondes":2"#
        )),
        Err(Erreur::ChampEnDouble { .. })
    ));

    // Champ inconnu au premier niveau.
    assert!(matches!(
        decoder(&message(r#""cadence":1"#)),
        Err(Erreur::ChampInconnu { .. })
    ));

    // Séparateur fautif au premier niveau.
    assert!(matches!(
        decoder(&message(
            r#""keepalive_secondes":1 "inactivite_secondes":2"#
        )),
        Err(Erreur::JsonAttendu {
            attendu: "une virgule ou la fin de l'objet",
            ..
        })
    ));
}

#[test]
fn un_message_de_reponse_trop_long_est_refuse() {
    let long = vec![b' '; MESSAGE_MAX + 1];
    let mut tampons = TamponsReponse::nouveaux();
    assert_eq!(
        Reponse::decoder(&long, &mut tampons).map(|_| ()),
        Err(Erreur::MessageTropLong {
            obtenue: MESSAGE_MAX + 1
        })
    );
}

#[test]
fn un_objet_de_reponse_vide_manque_du_premier_champ() {
    assert_eq!(decoder("{}"), Err(Erreur::ChampManquant { nom: "service" }));
}

#[test]
fn chaque_champ_de_la_reponse_manque_a_son_tour() {
    let complet = [
        ("service", format!(r#""service":"{}""#, service_texte())),
        ("keepalive_secondes", r#""keepalive_secondes":1"#.to_owned()),
        (
            "inactivite_secondes",
            r#""inactivite_secondes":2"#.to_owned(),
        ),
        (
            "vu_depuis",
            r#""vu_depuis":{"adresse":"10.0.0.1","port":1}"#.to_owned(),
        ),
        (
            "joignabilite",
            r#""joignabilite":[{"protocole":"tcp","port":80,"verdict":"en_cours"}]"#.to_owned(),
        ),
        ("derriere_nat", r#""derriere_nat":"non""#.to_owned()),
    ];
    for (absent, _) in &complet {
        let corps: Vec<&str> = complet
            .iter()
            .filter(|(nom, _)| nom != absent)
            .map(|(_, texte)| texte.as_str())
            .collect();
        let texte = format!("{{{}}}", corps.join(","));
        assert_eq!(
            decoder(&texte),
            Err(Erreur::ChampManquant { nom: absent }),
            "sans {absent}"
        );
    }
}

#[test]
fn l_objet_vu_depuis_a_ses_propres_refus() {
    let autour = |vu: &str| {
        format!(
            r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{vu},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":80,"verdict":"en_cours"}}]}}"#,
            service_texte()
        )
    };

    assert!(matches!(
        decoder(&autour(
            r#"{"adresse":"10.0.0.1","adresse":"10.0.0.2","port":1}"#
        )),
        Err(Erreur::ChampEnDouble { .. })
    ));
    assert!(matches!(
        decoder(&autour(r#"{"adresse":"10.0.0.1","port":1,"port":2}"#)),
        Err(Erreur::ChampEnDouble { .. })
    ));
    assert!(matches!(
        decoder(&autour(
            r#"{"adresse":"10.0.0.1","port":1,"famille":"ipv4"}"#
        )),
        Err(Erreur::ChampInconnu { .. })
    ));
    assert!(matches!(
        decoder(&autour(r#"{"adresse":"10.0.0.1" "port":1}"#)),
        Err(Erreur::JsonAttendu {
            attendu: "une virgule ou la fin de l'objet",
            ..
        })
    ));
    assert_eq!(
        decoder(&autour(r#"{"port":1}"#)),
        Err(Erreur::ChampManquant { nom: "adresse" })
    );
    assert_eq!(
        decoder(&autour(r#"{"adresse":"10.0.0.1"}"#)),
        Err(Erreur::ChampManquant { nom: "port" })
    );
    assert!(matches!(
        decoder(&autour(r#"{"adresse":"pas-une-adresse","port":1}"#)),
        Err(Erreur::AdresseInvalide { .. })
    ));
    assert_eq!(
        decoder(&autour(r#"{"adresse":"10.0.0.1","port":0}"#)),
        Err(Erreur::PortNul)
    );
    assert!(matches!(
        decoder(&autour(r#"{"adresse":"10.0.0.1","port":70000}"#)),
        Err(Erreur::NombreHorsBornes { .. })
    ));
}

#[test]
fn le_tableau_de_joignabilite_a_ses_propres_refus() {
    let autour = |liste: &str| {
        format!(
            r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":{liste}}}"#,
            service_texte()
        )
    };

    // Un tableau vide est syntaxiquement bon, et refusé par la VALIDATION.
    assert_eq!(decoder(&autour("[]")), Err(Erreur::AucuneJoignabilite));

    // Séparateur fautif entre deux entrées.
    assert!(matches!(
        decoder(&autour(
            r#"[{"protocole":"tcp","port":80,"verdict":"en_cours"} 2]"#
        )),
        Err(Erreur::JsonAttendu {
            attendu: "une virgule ou la fin du tableau",
            ..
        })
    ));

    // Champ inconnu, champ en double, séparateur fautif DANS une entrée.
    assert!(matches!(
        decoder(&autour(
            r#"[{"protocole":"tcp","port":80,"verdict":"en_cours","poids":1}]"#
        )),
        Err(Erreur::ChampInconnu { .. })
    ));
    assert!(matches!(
        decoder(&autour(
            r#"[{"protocole":"tcp","protocole":"udp","port":80,"verdict":"en_cours"}]"#
        )),
        Err(Erreur::ChampEnDouble { .. })
    ));
    assert!(matches!(
        decoder(&autour(
            r#"[{"protocole":"tcp" "port":80,"verdict":"en_cours"}]"#
        )),
        Err(Erreur::JsonAttendu {
            attendu: "une virgule ou la fin de l'objet",
            ..
        })
    ));

    // Les champs obligatoires de l'entrée.
    assert_eq!(
        decoder(&autour(r#"[{"port":80,"verdict":"en_cours"}]"#)),
        Err(Erreur::ChampManquant { nom: "protocole" })
    );
    assert_eq!(
        decoder(&autour(r#"[{"protocole":"tcp","verdict":"en_cours"}]"#)),
        Err(Erreur::ChampManquant { nom: "port" })
    );
    assert_eq!(
        decoder(&autour(r#"[{"protocole":"tcp","port":80}]"#)),
        Err(Erreur::ChampManquant { nom: "verdict" })
    );

    // Et la borne du tableau, vérifiée PENDANT la lecture.
    let trop: Vec<String> = (1..=POINTS_MAX + 1)
        .map(|n| format!(r#"{{"protocole":"tcp","port":{n},"verdict":"en_cours"}}"#))
        .collect();
    assert_eq!(
        decoder(&autour(&format!("[{}]", trop.join(",")))),
        Err(Erreur::TropDeJoignabilites {
            obtenu: POINTS_MAX + 1
        })
    );
}

#[test]
fn une_origine_hors_de_propos_sur_un_injoignable_est_refusee() {
    // Ce cas a sa propre position dans le message d'erreur, et donc sa propre
    // branche : `origine` sur un `injoignable`.
    let texte = format!(
        r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":80,"origine":"annonce","verdict":"injoignable","a":1}}]}}"#,
        service_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::ChampHorsPropos { .. })
    ));
}

#[test]
fn un_bail_invalide_est_refuse_au_cadrage() {
    let texte = format!(
        r#"{{"service":"{}","keepalive_secondes":15,"inactivite_secondes":15,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":80,"verdict":"en_cours"}}]}}"#,
        service_texte()
    );
    assert_eq!(
        decoder(&texte),
        Err(Erreur::InactiviteTropCourte {
            obtenue: 15,
            minimum: 30
        })
    );
}

#[test]
fn des_tampons_de_reponse_par_defaut_valent_des_neufs() {
    let texte = message_valide();
    let mut tampons = TamponsReponse::default();
    assert!(Reponse::decoder(texte.as_bytes(), &mut tampons).is_ok());
}

#[test]
fn l_horodatage_rend_ses_millisecondes() {
    let instant = Horodatage::depuis_millisecondes(1_789_217_731_000);
    assert_eq!(instant.millisecondes(), 1_789_217_731_000);
    assert_eq!(format!("{instant}"), "1789217731000");
}

#[test]
fn les_fautes_de_forme_du_premier_niveau() {
    // Chaque `?` du décodeur de réponse a son cas : ce qui n'est pas atteint
    // par un essai est du code qu'on croit éprouvé.
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
        decoder(r#"{"service"}"#),
        Err(Erreur::JsonAttendu {
            attendu: "deux-points",
            ..
        })
    ));
    assert!(matches!(
        decoder(r#"{"service":1}"#),
        Err(Erreur::JsonAttendu {
            attendu: "une chaîne",
            ..
        })
    ));
    assert!(matches!(
        decoder(r#"{"service":"pas-un-identifiant-de-service"}"#),
        Err(Erreur::IdentifiantInvalide { .. })
    ));
    assert!(matches!(
        decoder(&message(r#""derriere_nat":1"#)),
        Err(Erreur::JsonAttendu {
            attendu: "une chaîne",
            ..
        })
    ));
    assert!(matches!(
        decoder(&message(r#""keepalive_secondes":"quinze""#)),
        Err(Erreur::JsonAttendu {
            attendu: "un entier",
            ..
        })
    ));
    assert!(matches!(
        decoder(&message(r#""keepalive_secondes":70000"#)),
        Err(Erreur::NombreHorsBornes { .. })
    ));
    assert!(matches!(
        decoder(&message(r#""vu_depuis":[]"#)),
        Err(Erreur::JsonAttendu {
            attendu: "un objet",
            ..
        })
    ));
    assert!(matches!(
        decoder(&message(r#""joignabilite":{}"#)),
        Err(Erreur::JsonAttendu {
            attendu: "un tableau",
            ..
        })
    ));
    assert!(matches!(
        decoder(&message(r#""joignabilite":[1]"#)),
        Err(Erreur::JsonAttendu {
            attendu: "un objet",
            ..
        })
    ));
}

#[test]
fn une_origine_seule_sur_un_en_cours_est_refusee() {
    // `candidat` est examiné avant `origine` : sans ce cas-là, la branche de
    // l'origine sur un `en_cours` n'est jamais atteinte.
    let texte = format!(
        r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":[{{"protocole":"tcp","port":80,"verdict":"en_cours","origine":"annonce"}}]}}"#,
        service_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::ChampHorsPropos { .. })
    ));
}

#[test]
fn un_tampon_de_reponse_trop_petit_est_dit() {
    let texte = message_valide();
    let mut tampons = TamponsReponse::nouveaux();
    let reponse = Reponse::decoder(texte.as_bytes(), &mut tampons).unwrap();
    let mut court = vec![0_u8; texte.len() - 1];
    assert_eq!(reponse.encoder(&mut court), Err(Erreur::TamponTropPetit));
}

#[test]
fn chaque_sous_decodeur_a_ses_fautes_de_forme() {
    let autour = |vu: &str, liste: &str, nat: &str| {
        format!(
            r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{vu},"derriere_nat":{nat},"joignabilite":{liste}}}"#,
            service_texte()
        )
    };
    let vu = r#"{"adresse":"10.0.0.1","port":1}"#;
    let liste = r#"[{"protocole":"tcp","port":80,"verdict":"en_cours"}]"#;

    // `inactivite_secondes`, qui n'avait pas ses propres cas.
    assert!(matches!(
        decoder(&message(r#""inactivite_secondes":"deux""#)),
        Err(Erreur::JsonAttendu {
            attendu: "un entier",
            ..
        })
    ));
    assert!(matches!(
        decoder(&message(r#""inactivite_secondes":70000"#)),
        Err(Erreur::NombreHorsBornes { .. })
    ));

    // `derriere_nat` inconnu, vu à travers le cadrage.
    assert_eq!(
        decoder(&autour(vu, liste, r#""peut-etre""#)),
        Err(Erreur::VerdictNatInconnu)
    );

    // Des octets après la fin du message.
    let mut trop = autour(vu, liste, r#""non""#);
    trop.push_str("{}");
    assert!(matches!(decoder(&trop), Err(Erreur::DonneesEnTrop { .. })));

    // Dans `vu_depuis` : clé qui n'est pas une chaîne, deux-points manquant,
    // adresse qui n'est pas une chaîne, port qui n'est pas un nombre.
    for (mauvais, attendu) in [
        (r#"{1:2}"#, "une chaîne"),
        (r#"{"adresse"}"#, "deux-points"),
        (r#"{"adresse":1}"#, "une chaîne"),
        (r#"{"adresse":"10.0.0.1","port":"1"}"#, "un entier"),
    ] {
        match decoder(&autour(mauvais, liste, r#""non""#)) {
            Err(Erreur::JsonAttendu { attendu: dit, .. }) => assert_eq!(dit, attendu, "{mauvais}"),
            autre => panic!("{mauvais} : obtenu {autre:?}"),
        }
    }

    // Dans une entrée de joignabilité : même chose.
    for (mauvais, attendu) in [
        (r#"[{1:2}]"#, "une chaîne"),
        (r#"[{"protocole"}]"#, "deux-points"),
        (r#"[{"protocole":1}]"#, "une chaîne"),
        (r#"[{"protocole":"tcp","port":"80"}]"#, "un entier"),
        (
            r#"[{"protocole":"tcp","port":80,"verdict":1}]"#,
            "une chaîne",
        ),
        (
            r#"[{"protocole":"tcp","port":80,"verdict":"joignable","candidat":1}]"#,
            "une chaîne",
        ),
        (
            r#"[{"protocole":"tcp","port":80,"verdict":"joignable","candidat":"10.0.0.1:1","origine":1}]"#,
            "une chaîne",
        ),
        (
            r#"[{"protocole":"tcp","port":80,"verdict":"injoignable","a":"hier"}]"#,
            "un entier",
        ),
        (
            r#"[{"protocole":"tcp","port":80,"verdict":"non_sonde","raison":1}]"#,
            "une chaîne",
        ),
    ] {
        match decoder(&autour(vu, mauvais, r#""non""#)) {
            Err(Erreur::JsonAttendu { attendu: dit, .. }) => assert_eq!(dit, attendu, "{mauvais}"),
            autre => panic!("{mauvais} : obtenu {autre:?}"),
        }
    }

    // Le port d'une entrée est borné comme partout ailleurs.
    assert!(matches!(
        decoder(&autour(
            vu,
            r#"[{"protocole":"tcp","port":70000,"verdict":"en_cours"}]"#,
            r#""non""#
        )),
        Err(Erreur::NombreHorsBornes { .. })
    ));
    assert_eq!(
        decoder(&autour(
            vu,
            r#"[{"protocole":"tcp","port":0,"verdict":"en_cours"}]"#,
            r#""non""#
        )),
        Err(Erreur::PortNul)
    );

    // Un candidat dont le port est nul : le type le refuse aussi là.
    assert_eq!(
        decoder(&autour(
            vu,
            r#"[{"protocole":"tcp","port":80,"verdict":"joignable","candidat":"10.0.0.1:0","origine":"annonce","a":1}]"#,
            r#""non""#
        )),
        Err(Erreur::PortNul)
    );
}

#[test]
fn un_protocole_inconnu_dans_un_verdict_est_refuse() {
    let texte = format!(
        r#"{{"service":"{}","keepalive_secondes":1,"inactivite_secondes":2,"vu_depuis":{{"adresse":"10.0.0.1","port":1}},"derriere_nat":"non","joignabilite":[{{"protocole":"sctp","port":80,"verdict":"en_cours"}}]}}"#,
        service_texte()
    );
    assert_eq!(decoder(&texte), Err(Erreur::ProtocoleInconnu));
}

#[test]
fn vu_depuis_distingue_les_deux_familles() {
    // La question qui décide de tout dans ce produit : IPv6 ou IPv4.
    assert!(vu_depuis().est_ipv6());
    let en_quatre = VuDepuis {
        adresse: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)),
        port: port(1),
    };
    assert!(!en_quatre.est_ipv6());
}
