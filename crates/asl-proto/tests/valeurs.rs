//! Les valeurs du protocole, éprouvées une à une.
//!
//! **Ce sont des codecs**, donc chaque cas se pose en une ligne : aucun réseau,
//! aucune horloge, aucun fichier. C'est ce que la contrainte C1 achète.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_id::{Genre, Identifiant};
use asl_proto::{
    ADRESSES_MAX, Annonce, Candidat, Erreur, NOM_MAX, NomService, Origine, POINTS_MAX, PointEcoute,
    Port, Protocole, ordonner,
};

/// Une machine, pour les essais qui en veulent une.
fn machine() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, [0x11; 16])
}

/// Un port dont on sait qu'il est valide.
fn port(valeur: u16) -> Port {
    Port::depuis_u16(valeur).expect("port d'essai valide")
}

// ── Le protocole ────────────────────────────────────────────────────────────

#[test]
fn les_deux_protocoles_se_lisent_et_s_ecrivent() {
    for (protocole, texte) in [(Protocole::Tcp, "tcp"), (Protocole::Udp, "udp")] {
        assert_eq!(protocole.texte(), texte);
        assert_eq!(Protocole::analyser(texte), Ok(protocole));
        assert_eq!(format!("{protocole}"), texte);
    }
}

#[test]
fn les_majuscules_du_protocole_sont_refusees_et_non_repliees() {
    // `TCP` et `tcp` seraient deux écritures d'une même valeur.
    for texte in ["TCP", "Tcp", "UDP", "Udp", "", " tcp", "tcp ", "sctp"] {
        assert_eq!(
            Protocole::analyser(texte),
            Err(Erreur::ProtocoleInconnu),
            "{texte:?}"
        );
    }
}

#[test]
fn seul_tcp_se_sonde() {
    // Une sonde UDP ne distingue pas « écoute et ignore » de « rien n'écoute ».
    assert!(Protocole::Tcp.se_sonde());
    assert!(!Protocole::Udp.se_sonde());
}

// ── Le port ─────────────────────────────────────────────────────────────────

#[test]
fn le_port_zero_n_est_pas_un_port() {
    assert_eq!(Port::depuis_u16(0), Err(Erreur::PortNul));
    assert_eq!(Port::analyser("0"), Err(Erreur::PortNul));
}

#[test]
fn les_bornes_du_port_sont_celles_annoncees() {
    assert_eq!(port(1).valeur(), 1);
    assert_eq!(port(65535).valeur(), 65535);
    assert_eq!(Port::analyser("1"), Ok(port(1)));
    assert_eq!(Port::analyser("65535"), Ok(port(65535)));
}

#[test]
fn le_debordement_se_refuse_et_ne_se_tronque_pas() {
    // `65536` tronqué vaudrait `0` : un service annoncé sur un port qui
    // n'existe pas, sans qu'aucune erreur ne soit rendue. C'est C3.
    for texte in [
        "65536",
        "70000",
        "99999",
        "4294967296",
        "18446744073709551616",
    ] {
        assert_eq!(
            Port::analyser(texte),
            Err(Erreur::PortHorsBornes),
            "{texte}"
        );
    }
}

#[test]
fn une_seule_ecriture_par_port() {
    for texte in ["0080", "00", "01", "065535"] {
        assert_eq!(
            Port::analyser(texte),
            Err(Erreur::PortNonCanonique),
            "{texte}"
        );
    }
}

#[test]
fn ce_qui_n_est_pas_un_nombre_decimal_est_refuse() {
    for texte in [
        "", " 80", "80 ", "+80", "-80", "8_0", "0x50", "80.0", "quatre",
    ] {
        assert_eq!(
            Port::analyser(texte),
            Err(Erreur::PortNonNumerique),
            "{texte:?}"
        );
    }
}

#[test]
fn tout_port_valide_se_relit() {
    // L'aller-retour sur toute la plage : il n'existe pas de port qu'on sache
    // écrire et pas relire.
    for valeur in 1_u16..=u16::MAX {
        let origine = port(valeur);
        let ecrit = format!("{origine}");
        assert_eq!(Port::analyser(&ecrit), Ok(origine), "{valeur}");
    }
}

// ── Le nom de service ───────────────────────────────────────────────────────

#[test]
fn un_nom_ordinaire_passe() {
    for texte in [
        "a",
        "0",
        "depot-de-messages",
        "sauvegarde_2",
        "air.mail.smtp",
        "_interne",
    ] {
        let nom = NomService::analyser(texte).unwrap_or_else(|e| panic!("{texte:?} : {e}"));
        assert_eq!(nom.as_str(), texte);
        assert_eq!(format!("{nom}"), texte);
    }
}

#[test]
fn le_nom_vide_et_le_nom_trop_long_sont_refuses() {
    assert_eq!(NomService::analyser(""), Err(Erreur::NomVide));

    let juste = "a".repeat(NOM_MAX);
    assert!(NomService::analyser(&juste).is_ok());

    let trop = "a".repeat(NOM_MAX + 1);
    assert_eq!(
        NomService::analyser(&trop),
        Err(Erreur::NomTropLong {
            obtenue: NOM_MAX + 1
        })
    );
}

#[test]
fn les_majuscules_du_nom_sont_refusees_et_non_repliees() {
    // Un nom qui ne diffère que par la casse produirait deux services que
    // l'annuaire distingue et qu'un humain lit comme un seul.
    assert_eq!(
        NomService::analyser("Sauvegarde"),
        Err(Erreur::NomSymboleInvalide { position: 0 })
    );
    assert_eq!(
        NomService::analyser("sauvegardE"),
        Err(Erreur::NomSymboleInvalide { position: 9 })
    );
}

#[test]
fn tout_octet_hors_alphabet_est_refuse_et_sa_position_dite() {
    for (texte, position) in [
        ("dépôt", 1_usize),
        ("a b", 1),
        ("a/b", 1),
        ("a?b", 1),
        ("a%20b", 1),
        ("a\u{0}b", 1),
        ("a:b", 1),
        ("a+b", 1),
    ] {
        assert_eq!(
            NomService::analyser(texte),
            Err(Erreur::NomSymboleInvalide { position }),
            "{texte:?}"
        );
    }
}

#[test]
fn les_bords_du_nom_sont_contraints() {
    for texte in ["-a", "a-", ".a", "a.", "-", ".", "-a-", ".a."] {
        assert_eq!(
            NomService::analyser(texte),
            Err(Erreur::NomBordInvalide),
            "{texte:?}"
        );
    }
    // Le tiret bas, lui, est permis partout — il ne se cache pas et ne se lit
    // pas mal.
    assert!(NomService::analyser("_").is_ok());
    assert!(NomService::analyser("_a_").is_ok());
}

// ── Le point d'écoute ───────────────────────────────────────────────────────

#[test]
fn un_point_s_ecrit_protocole_puis_port() {
    let point = PointEcoute::nouveau(Protocole::Tcp, port(49152));
    assert_eq!(format!("{point}"), "tcp/49152");
    assert_eq!(point.protocole, Protocole::Tcp);
    assert_eq!(point.port, port(49152));
}

// ── Les candidats ───────────────────────────────────────────────────────────

/// Un candidat, brièvement.
fn candidat(adresse: &str, port_valeur: u16, origine: Origine) -> Candidat {
    Candidat {
        protocole: Protocole::Tcp,
        adresse: adresse.parse().expect("adresse d'essai valide"),
        port: port(port_valeur),
        origine,
    }
}

#[test]
fn une_adresse_ipv6_s_ecrit_entre_crochets() {
    // Sans crochets, `2001:db8::1:49152` ne se relit pas : le dernier `:` est
    // indiscernable d'un séparateur de groupe.
    let six = candidat("2001:db8::1", 49152, Origine::Reflexif);
    assert_eq!(format!("{six}"), "[2001:db8::1]:49152");

    let quatre = candidat("203.0.113.4", 49152, Origine::Reflexif);
    assert_eq!(format!("{quatre}"), "203.0.113.4:49152");
}

#[test]
fn ipv6_passe_avant_ipv4_et_reflexif_avant_annonce() {
    let mut candidats = [
        candidat("192.168.1.20", 49152, Origine::Annonce),
        candidat("203.0.113.4", 49152, Origine::Reflexif),
        candidat("2001:db8::2", 49152, Origine::Annonce),
        candidat("2001:db8::1", 49152, Origine::Reflexif),
    ];
    ordonner(&mut candidats);

    let ordre: Vec<String> = candidats.iter().map(|c| format!("{c}")).collect();
    assert_eq!(
        ordre,
        [
            "[2001:db8::1]:49152",
            "[2001:db8::2]:49152",
            "203.0.113.4:49152",
            "192.168.1.20:49152",
        ]
    );
}

#[test]
fn le_rang_dit_la_famille_puis_l_origine() {
    assert_eq!(candidat("2001:db8::1", 1, Origine::Reflexif).rang(), (0, 0));
    assert_eq!(candidat("2001:db8::1", 1, Origine::Annonce).rang(), (0, 1));
    assert_eq!(candidat("203.0.113.4", 1, Origine::Reflexif).rang(), (1, 0));
    assert_eq!(candidat("203.0.113.4", 1, Origine::Annonce).rang(), (1, 1));
}

#[test]
fn ordonner_est_deterministe_sur_une_liste_vide_ou_unique() {
    let mut rien: [Candidat; 0] = [];
    ordonner(&mut rien);

    let mut seul = [candidat("2001:db8::1", 1, Origine::Annonce)];
    let avant = seul;
    ordonner(&mut seul);
    assert_eq!(seul, avant);
}

// ── L'annonce ───────────────────────────────────────────────────────────────

#[test]
fn une_annonce_ordinaire_passe() {
    let points = [
        PointEcoute::nouveau(Protocole::Tcp, port(49152)),
        PointEcoute::nouveau(Protocole::Udp, port(49152)),
    ];
    let adresses = [
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
    ];
    let nom = NomService::analyser("depot-de-messages").unwrap();

    let annonce = Annonce::nouvelle(machine(), nom, &points, &adresses).unwrap();
    assert_eq!(annonce.machine, machine());
    assert_eq!(annonce.service, nom);
    assert_eq!(annonce.points.len(), 2);
    assert_eq!(annonce.adresses_locales.len(), 2);
    assert!(annonce.a_un_point_sondable());
}

#[test]
fn un_identifiant_qui_n_est_pas_une_machine_est_refuse() {
    // Sinon il passerait pour une machine inconnue, et l'administrateur
    // chercherait une machine qu'il n'a jamais déclarée.
    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let nom = NomService::analyser("x").unwrap();

    for genre in [
        Genre::Utilisateur,
        Genre::Appareil,
        Genre::Service,
        Genre::Autorisation,
        Genre::Annuaire,
    ] {
        let autre = Identifiant::depuis_entropie(genre, [0x11; 16]);
        assert_eq!(
            Annonce::nouvelle(autre, nom, &points, &[]),
            Err(Erreur::PasUneMachine { obtenu: genre }),
            "{genre:?}"
        );
    }
}

#[test]
fn une_annonce_sans_point_ne_dit_rien() {
    let nom = NomService::analyser("x").unwrap();
    assert_eq!(
        Annonce::nouvelle(machine(), nom, &[], &[]),
        Err(Erreur::AucunPoint)
    );
}

#[test]
fn les_comptes_sont_bornes() {
    let nom = NomService::analyser("x").unwrap();

    // Les comptes viennent du réseau : ils sont bornés.
    let trop_de_points: Vec<PointEcoute> = (1..=u16::try_from(POINTS_MAX + 1).unwrap())
        .map(|valeur| PointEcoute::nouveau(Protocole::Tcp, port(valeur)))
        .collect();
    assert_eq!(
        Annonce::nouvelle(machine(), nom, &trop_de_points, &[]),
        Err(Erreur::TropDePoints {
            obtenu: POINTS_MAX + 1
        })
    );
    assert!(Annonce::nouvelle(machine(), nom, &trop_de_points[..POINTS_MAX], &[]).is_ok());

    let points = [PointEcoute::nouveau(Protocole::Tcp, port(1))];
    let trop_d_adresses: Vec<IpAddr> = (0..=u8::try_from(ADRESSES_MAX).unwrap())
        .map(|n| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
        .collect();
    assert_eq!(
        Annonce::nouvelle(machine(), nom, &points, &trop_d_adresses),
        Err(Erreur::TropDAdresses {
            obtenu: ADRESSES_MAX + 1
        })
    );
    assert!(Annonce::nouvelle(machine(), nom, &points, &trop_d_adresses[..ADRESSES_MAX]).is_ok());
}

#[test]
fn deux_points_identiques_sont_refuses() {
    // Deux fois `tcp/49152` ne veut rien dire, et la sonde le paierait deux fois.
    let nom = NomService::analyser("x").unwrap();
    let doublon = [
        PointEcoute::nouveau(Protocole::Tcp, port(49152)),
        PointEcoute::nouveau(Protocole::Udp, port(49152)),
        PointEcoute::nouveau(Protocole::Tcp, port(49152)),
    ];
    assert_eq!(
        Annonce::nouvelle(machine(), nom, &doublon, &[]),
        Err(Erreur::PointEnDouble)
    );

    // Le même port sur deux protocoles n'est PAS un doublon.
    let distincts = [
        PointEcoute::nouveau(Protocole::Tcp, port(49152)),
        PointEcoute::nouveau(Protocole::Udp, port(49152)),
    ];
    assert!(Annonce::nouvelle(machine(), nom, &distincts, &[]).is_ok());
}

#[test]
fn un_daemon_purement_udp_n_a_aucun_point_sondable() {
    let nom = NomService::analyser("x").unwrap();
    let points = [
        PointEcoute::nouveau(Protocole::Udp, port(49152)),
        PointEcoute::nouveau(Protocole::Udp, port(49153)),
    ];
    let annonce = Annonce::nouvelle(machine(), nom, &points, &[]).unwrap();
    assert!(!annonce.a_un_point_sondable());
}

// ── Les erreurs se disent ───────────────────────────────────────────────────

#[test]
fn chaque_erreur_se_dit_a_un_humain() {
    // Un daemon tiers lira ces refus dans son journal.
    let toutes = [
        Erreur::ProtocoleInconnu,
        Erreur::PortNul,
        Erreur::PortNonNumerique,
        Erreur::PortHorsBornes,
        Erreur::PortNonCanonique,
        Erreur::NomVide,
        Erreur::NomTropLong { obtenue: 99 },
        Erreur::NomSymboleInvalide { position: 3 },
        Erreur::NomBordInvalide,
        Erreur::AucunPoint,
        Erreur::TropDePoints { obtenu: 99 },
        Erreur::PointEnDouble,
        Erreur::TropDAdresses { obtenu: 99 },
        Erreur::PasUneMachine {
            obtenu: Genre::Service,
        },
        // Celles du cadrage. Une erreur qu'on ne peut pas afficher n'aide
        // personne, et un daemon tiers ne lira que ce message.
        Erreur::MessageTropLong { obtenue: 9_999 },
        Erreur::IdentifiantInvalide { position: 11 },
        Erreur::JsonAttendu {
            position: 3,
            attendu: "un objet",
        },
        Erreur::JsonInattendu { position: 3 },
        Erreur::ChampInconnu { position: 12 },
        Erreur::ChampEnDouble { position: 12 },
        Erreur::ChampManquant { nom: "machine" },
        Erreur::EchappementRefuse { position: 7 },
        Erreur::CaractereBrutRefuse { position: 7 },
        Erreur::NombreNonCanonique { position: 40 },
        Erreur::NombreNonEntier { position: 40 },
        Erreur::NombreHorsBornes { position: 40 },
        Erreur::AdresseInvalide { position: 60 },
        Erreur::DonneesEnTrop { position: 128 },
        Erreur::TamponTropPetit,
        // Celles du message de réponse.
        Erreur::KeepaliveNul,
        Erreur::KeepaliveTropLong { obtenu: 9_999 },
        Erreur::InactiviteTropCourte {
            obtenue: 15,
            minimum: 30,
        },
        Erreur::VerdictNatInconnu,
        Erreur::RaisonInconnue,
        Erreur::VerdictInconnu,
        Erreur::OrigineInconnue,
        Erreur::PasUnService {
            obtenu: Genre::Machine,
        },
        Erreur::AucuneJoignabilite,
        Erreur::TropDeJoignabilites { obtenu: 99 },
        Erreur::VerdictImpossible,
        Erreur::ChampHorsPropos { position: 42 },
        Erreur::CandidatInvalide { position: 42 },
        // Celles des listes.
        Erreur::ListeMalFormee { position: 42 },
        Erreur::TropDElements { obtenu: 99 },
    ];
    for erreur in toutes {
        let message = format!("{erreur}");
        assert!(!message.is_empty(), "{erreur:?}");
        // Un message qui se contenterait du nom de la variante n'apprendrait
        // rien de plus que le `Debug`.
        assert_ne!(message, format!("{erreur:?}"), "{erreur:?}");
    }
}
