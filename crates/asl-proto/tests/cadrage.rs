//! Le cadrage JSON, éprouvé octet par octet.
//!
//! **Les trois refus de ce décodeur ont chacun leur section** — échappements,
//! champs inconnus, champs en double — parce que ce sont des décisions, et
//! qu'une décision qu'aucun essai ne fixe se défait par inadvertance.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_id::{Genre, Identifiant};
use asl_proto::{
    ADRESSES_MAX, Annonce, Erreur, MESSAGE_MAX, NomService, POINTS_MAX, PointEcoute, Port,
    Protocole, Tampons,
};

/// L'identifiant de machine employé partout ici.
fn machine() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, [0x11; 16])
}

/// Son écriture.
fn machine_texte() -> String {
    machine().texte().as_str().to_owned()
}

/// Décode, avec des tampons neufs.
fn decoder(texte: &str) -> Result<(), Erreur> {
    let mut tampons = Tampons::nouveaux();
    Annonce::decoder(texte.as_bytes(), &mut tampons).map(|_| ())
}

/// Un message d'annonce complet et valide.
fn message_valide() -> String {
    format!(
        r#"{{"machine":"{}","service":"depot-de-messages","points":[{{"protocole":"tcp","port":49152}}],"adresses_locales":["2001:db8::1"]}}"#,
        machine_texte()
    )
}

// ── Le tour complet ─────────────────────────────────────────────────────────

#[test]
fn un_message_ordinaire_se_decode() {
    let texte = message_valide();
    let mut tampons = Tampons::nouveaux();
    let annonce = Annonce::decoder(texte.as_bytes(), &mut tampons).expect("doit se décoder");

    assert_eq!(annonce.machine, machine());
    assert_eq!(annonce.service.as_str(), "depot-de-messages");
    assert_eq!(
        annonce.points,
        [PointEcoute::nouveau(
            Protocole::Tcp,
            Port::depuis_u16(49152).unwrap()
        )]
    );
    assert_eq!(
        annonce.adresses_locales,
        [IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))]
    );
}

#[test]
fn l_ecriture_est_canonique_et_se_relit() {
    // Deux annonces égales s'écrivent de la même façon : c'est ce qui rend un
    // journal comparable à lui-même.
    let texte = message_valide();
    let mut tampons = Tampons::nouveaux();
    let annonce = Annonce::decoder(texte.as_bytes(), &mut tampons).unwrap();

    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = annonce.encoder(&mut sortie).unwrap();
    let reecrit = core::str::from_utf8(&sortie[..ecrits]).unwrap();

    assert_eq!(reecrit, texte, "l'écriture n'est pas canonique");

    let mut encore = Tampons::nouveaux();
    let relu = Annonce::decoder(reecrit.as_bytes(), &mut encore).unwrap();
    assert_eq!(relu.machine, annonce.machine);
    assert_eq!(relu.service, annonce.service);
    assert_eq!(relu.points, annonce.points);
    assert_eq!(relu.adresses_locales, annonce.adresses_locales);
}

#[test]
fn les_champs_peuvent_venir_dans_n_importe_quel_ordre() {
    // Ce message se débogue avec `curl` ; exiger un ordre coûterait plus que
    // ça ne rapporterait.
    let texte = format!(
        r#"{{"adresses_locales":[],"points":[{{"port":80,"protocole":"udp"}}],"service":"x","machine":"{}"}}"#,
        machine_texte()
    );
    let mut tampons = Tampons::nouveaux();
    let annonce = Annonce::decoder(texte.as_bytes(), &mut tampons).unwrap();
    assert_eq!(annonce.points[0].protocole, Protocole::Udp);
    assert_eq!(annonce.points[0].port.valeur(), 80);
    assert!(annonce.adresses_locales.is_empty());
}

#[test]
fn les_adresses_locales_sont_facultatives() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}]}}"#,
        machine_texte()
    );
    let mut tampons = Tampons::nouveaux();
    let annonce = Annonce::decoder(texte.as_bytes(), &mut tampons).unwrap();
    assert!(annonce.adresses_locales.is_empty());
}

#[test]
fn les_blancs_de_json_sont_admis_et_eux_seuls() {
    let texte = format!(
        "{{ \"machine\" : \"{}\" ,\n\t\"service\":\"x\",\r\n\"points\" : [ {{ \"protocole\" : \"tcp\" , \"port\" : 1 }} ] }}",
        machine_texte()
    );
    assert!(decoder(&texte).is_ok());

    // La tabulation verticale n'est pas un blanc au sens de RFC 8259 §2.
    let avec_vt = format!(
        "{{\u{000b}\"machine\":\"{}\",\"service\":\"x\",\"points\":[{{\"protocole\":\"tcp\",\"port\":1}}]}}",
        machine_texte()
    );
    assert!(matches!(decoder(&avec_vt), Err(Erreur::JsonAttendu { .. })));
}

// ── Refus 1 : les échappements ──────────────────────────────────────────────

#[test]
fn tout_echappement_est_refuse() {
    // `\u0078` serait une deuxième écriture de `x`, et `\u002f` ferait passer un
    // `/` que l'alphabet des noms refuse. Les deux se ferment d'un coup.
    //
    // Les motifs sont des chaînes BRUTES délimitées par `r#"…"#` : `r"\""` ne
    // se ferme pas, et cassait la lecture de tout ce qui suivait dans ce
    // fichier.
    for echappement in [r#"\u0078"#, r#"\n"#, r#"\\"#, r#"\""#, r#"\/"#] {
        let texte = format!(
            r#"{{"machine":"{}","service":"{echappement}","points":[{{"protocole":"tcp","port":1}}]}}"#,
            machine_texte()
        );
        assert!(
            matches!(decoder(&texte), Err(Erreur::EchappementRefuse { .. })),
            "{echappement}"
        );
    }
}

#[test]
fn les_octets_de_controle_et_le_non_ascii_sont_refuses() {
    for brut in ["\u{0}", "\u{1f}", "\u{7f}", "é", "→"] {
        let texte = format!(
            r#"{{"machine":"{}","service":"{brut}","points":[{{"protocole":"tcp","port":1}}]}}"#,
            machine_texte()
        );
        assert!(
            matches!(decoder(&texte), Err(Erreur::CaractereBrutRefuse { .. })),
            "{brut:?}"
        );
    }
}

// ── Refus 2 : les champs inconnus ───────────────────────────────────────────

#[test]
fn un_champ_inconnu_est_refuse_et_non_ignore() {
    // Un champ qu'on ignore est un champ que l'émetteur croit avoir transmis.
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}],"priorite":3}}"#,
        machine_texte()
    );
    assert!(matches!(decoder(&texte), Err(Erreur::ChampInconnu { .. })));

    // Y compris dans un point d'écoute.
    let dans_un_point = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1,"poids":2}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&dans_un_point),
        Err(Erreur::ChampInconnu { .. })
    ));
}

// ── Refus 3 : les champs en double ──────────────────────────────────────────

#[test]
fn un_champ_en_double_est_refuse() {
    // Deux analyseurs qui ne choisiraient pas le même gagnant liraient deux
    // messages dans les mêmes octets.
    let texte = format!(
        r#"{{"machine":"{}","service":"x","service":"y","points":[{{"protocole":"tcp","port":1}}]}}"#,
        machine_texte()
    );
    assert!(matches!(decoder(&texte), Err(Erreur::ChampEnDouble { .. })));

    let dans_un_point = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","protocole":"udp","port":1}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&dans_un_point),
        Err(Erreur::ChampEnDouble { .. })
    ));

    let port_double = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"port":1,"port":2,"protocole":"tcp"}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&port_double),
        Err(Erreur::ChampEnDouble { .. })
    ));
}

// ── Les champs manquants ────────────────────────────────────────────────────

#[test]
fn chaque_champ_obligatoire_manque_a_son_tour() {
    for (sans, nom) in [
        (
            r#"{"service":"x","points":[{"protocole":"tcp","port":1}]}"#.to_owned(),
            "machine",
        ),
        (
            format!(
                r#"{{"machine":"{}","points":[{{"protocole":"tcp","port":1}}]}}"#,
                machine_texte()
            ),
            "service",
        ),
        (
            format!(r#"{{"machine":"{}","service":"x"}}"#, machine_texte()),
            "points",
        ),
    ] {
        assert_eq!(decoder(&sans), Err(Erreur::ChampManquant { nom }), "{sans}");
    }

    // Un objet entièrement vide manque du premier champ nommé.
    assert_eq!(decoder("{}"), Err(Erreur::ChampManquant { nom: "machine" }));

    // Et dans un point d'écoute.
    let sans_port = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp"}}]}}"#,
        machine_texte()
    );
    assert_eq!(
        decoder(&sans_port),
        Err(Erreur::ChampManquant { nom: "port" })
    );
    let sans_protocole = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"port":1}}]}}"#,
        machine_texte()
    );
    assert_eq!(
        decoder(&sans_protocole),
        Err(Erreur::ChampManquant { nom: "protocole" })
    );
}

// ── Les nombres ─────────────────────────────────────────────────────────────

#[test]
fn un_nombre_non_entier_est_refuse() {
    // Accepter `49152.0` obligerait à décider d'un arrondi dans un décodeur.
    for brut in ["1.0", "1e3", "1E3"] {
        let texte = format!(
            r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":{brut}}}]}}"#,
            machine_texte()
        );
        assert!(
            matches!(decoder(&texte), Err(Erreur::NombreNonEntier { .. })),
            "{brut}"
        );
    }
}

#[test]
fn un_nombre_avec_un_zero_en_tete_est_refuse() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":080}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::NombreNonCanonique { .. })
    ));
}

#[test]
fn un_port_hors_bornes_est_refuse_et_non_tronque() {
    // Le décodeur lit en `u32` puis borne : un `65536` tronqué en `u16` vaudrait
    // `0`, c'est-à-dire un service annoncé nulle part.
    for brut in ["65536", "4294967296", "99999999999999999999"] {
        let texte = format!(
            r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":{brut}}}]}}"#,
            machine_texte()
        );
        assert!(
            matches!(decoder(&texte), Err(Erreur::NombreHorsBornes { .. })),
            "{brut}"
        );
    }
}

#[test]
fn le_port_zero_est_refuse_par_le_type() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":0}}]}}"#,
        machine_texte()
    );
    assert_eq!(decoder(&texte), Err(Erreur::PortNul));
}

#[test]
fn un_nombre_absent_la_ou_il_est_attendu() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":"1"}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::JsonAttendu {
            attendu: "un entier",
            ..
        })
    ));
}

// ── Les bornes ──────────────────────────────────────────────────────────────

#[test]
fn un_message_trop_long_est_refuse_avant_toute_lecture() {
    let long = vec![b' '; MESSAGE_MAX + 1];
    let mut tampons = Tampons::nouveaux();
    assert_eq!(
        Annonce::decoder(&long, &mut tampons).map(|_| ()),
        Err(Erreur::MessageTropLong {
            obtenue: MESSAGE_MAX + 1
        })
    );
}

#[test]
fn les_tableaux_sont_bornes_pendant_la_lecture() {
    // LA BORNE EST VÉRIFIÉE AVANT D'ÉCRIRE : un tableau de mille éléments ne
    // coûte pas mille écritures.
    let points: Vec<String> = (1..=POINTS_MAX + 1)
        .map(|n| format!(r#"{{"protocole":"tcp","port":{n}}}"#))
        .collect();
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{}]}}"#,
        machine_texte(),
        points.join(",")
    );
    assert_eq!(
        decoder(&texte),
        Err(Erreur::TropDePoints {
            obtenu: POINTS_MAX + 1
        })
    );

    let adresses: Vec<String> = (0..=ADRESSES_MAX)
        .map(|n| format!(r#""10.0.0.{n}""#))
        .collect();
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}],"adresses_locales":[{}]}}"#,
        machine_texte(),
        adresses.join(",")
    );
    assert_eq!(
        decoder(&texte),
        Err(Erreur::TropDAdresses {
            obtenu: ADRESSES_MAX + 1
        })
    );
}

// ── La forme JSON ───────────────────────────────────────────────────────────

#[test]
fn les_fautes_de_forme_designent_leur_position() {
    // LES VECTEURS PORTENT UN VRAI IDENTIFIANT DE MACHINE. Avec un `"x"`, le
    // décodeur échouait sur l'identifiant avant d'atteindre le contrôle qu'on
    // voulait éprouver — l'essai passait pour la mauvaise raison.
    let identifiant = machine_texte();
    let cas: [(String, &str); 6] = [
        (String::new(), "un objet"),
        ("[]".to_owned(), "un objet"),
        ("{".to_owned(), "une chaîne"),
        (r#"{"machine"}"#.to_owned(), "deux-points"),
        (
            format!(r#"{{"machine":"{identifiant}" "service":"y"}}"#),
            "une virgule ou la fin de l'objet",
        ),
        (
            format!(r#"{{"machine":"{identifiant}","service":"y","points":{{}}}}"#),
            "un tableau",
        ),
    ];
    for (texte, attendu) in cas {
        match decoder(&texte) {
            Err(Erreur::JsonAttendu { attendu: dit, .. }) => {
                assert_eq!(dit, attendu, "{texte}");
            }
            autre => panic!("{texte} : attendu JsonAttendu({attendu}), obtenu {autre:?}"),
        }
    }
}

#[test]
fn une_chaine_non_terminee_est_refusee() {
    assert!(matches!(
        decoder(r#"{"machine":"m-000"#),
        Err(Erreur::JsonAttendu {
            attendu: "la fin d'une chaîne",
            ..
        })
    ));
}

#[test]
fn des_octets_apres_le_message_sont_refuses() {
    // Deux messages collés, c'est un lecteur qui en voit un et un autre qui en
    // voit deux.
    let texte = format!("{}{{}}", message_valide());
    assert!(matches!(decoder(&texte), Err(Erreur::DonneesEnTrop { .. })));
}

#[test]
fn un_identifiant_qui_n_est_pas_une_machine_est_refuse_au_cadrage() {
    let service = Identifiant::depuis_entropie(Genre::Service, [0x11; 16]);
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}]}}"#,
        service.texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::IdentifiantInvalide { .. })
    ));
}

#[test]
fn une_adresse_illisible_est_refusee() {
    for brut in ["pas-une-adresse", "999.999.999.999", "2001:db8::g", ""] {
        let texte = format!(
            r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}],"adresses_locales":["{brut}"]}}"#,
            machine_texte()
        );
        assert!(
            matches!(decoder(&texte), Err(Erreur::AdresseInvalide { .. })),
            "{brut:?}"
        );
    }
}

#[test]
fn les_tableaux_vides_passent() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[],"adresses_locales":[]}}"#,
        machine_texte()
    );
    // Un tableau de points vide est syntaxiquement bon, et refusé par la
    // VALIDATION — les deux étages disent chacun leur part.
    assert_eq!(decoder(&texte), Err(Erreur::AucunPoint));
}

#[test]
fn un_tableau_mal_ferme_est_refuse() {
    for texte in [
        format!(
            r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}"#,
            machine_texte()
        ),
        format!(
            r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}} 2]}}"#,
            machine_texte()
        ),
        format!(
            r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}],"adresses_locales":["10.0.0.1" 2]}}"#,
            machine_texte()
        ),
    ] {
        assert!(decoder(&texte).is_err(), "{texte}");
    }
}

// ── L'encodage ──────────────────────────────────────────────────────────────

#[test]
fn un_tampon_trop_petit_est_dit_et_non_tronque() {
    let texte = message_valide();
    let mut tampons = Tampons::nouveaux();
    let annonce = Annonce::decoder(texte.as_bytes(), &mut tampons).unwrap();

    for taille in [0, 1, texte.len() - 1] {
        let mut sortie = vec![0_u8; taille];
        assert_eq!(
            annonce.encoder(&mut sortie),
            Err(Erreur::TamponTropPetit),
            "taille {taille}"
        );
    }
    let mut juste = vec![0_u8; texte.len()];
    assert_eq!(annonce.encoder(&mut juste), Ok(texte.len()));
}

#[test]
fn une_ipv4_et_une_ipv6_s_ecrivent_toutes_deux() {
    let points = [PointEcoute::nouveau(
        Protocole::Udp,
        Port::depuis_u16(53).unwrap(),
    )];
    let adresses = [
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
    ];
    let nom = NomService::analyser("dns").unwrap();
    let annonce = Annonce::nouvelle(machine(), nom, &points, &adresses).unwrap();

    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = annonce.encoder(&mut sortie).unwrap();
    let rendu = core::str::from_utf8(&sortie[..ecrits]).unwrap();

    assert!(
        rendu.contains(r#""adresses_locales":["::1","192.168.1.20"]"#),
        "{rendu}"
    );
    assert!(rendu.contains(r#""protocole":"udp","port":53"#), "{rendu}");
    assert!(decoder(rendu).is_ok());
}

#[test]
fn plusieurs_points_sont_separes_par_une_virgule() {
    // La virgule entre deux points d'écoute n'a pas d'autre essai : avec un seul
    // point, la branche qui l'écrit ne s'exécute jamais.
    let points = [
        PointEcoute::nouveau(Protocole::Tcp, Port::depuis_u16(49152).unwrap()),
        PointEcoute::nouveau(Protocole::Udp, Port::depuis_u16(49152).unwrap()),
    ];
    let nom = NomService::analyser("x").unwrap();
    let annonce = Annonce::nouvelle(machine(), nom, &points, &[]).unwrap();

    let mut sortie = [0_u8; MESSAGE_MAX];
    let ecrits = annonce.encoder(&mut sortie).unwrap();
    let rendu = core::str::from_utf8(&sortie[..ecrits]).unwrap();

    assert!(
        rendu.contains(
            r#""points":[{"protocole":"tcp","port":49152},{"protocole":"udp","port":49152}]"#
        ),
        "{rendu}"
    );
    assert!(decoder(rendu).is_ok());
}

#[test]
fn un_point_mal_separe_est_refuse() {
    // Dans l'objet d'un point, comme dans l'objet du message : ce qui suit une
    // valeur est une virgule ou la fin.
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp" "port":1}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::JsonAttendu {
            attendu: "une virgule ou la fin de l'objet",
            ..
        })
    ));
}

#[test]
fn des_tampons_par_defaut_valent_des_tampons_neufs() {
    let texte = message_valide();
    let mut tampons = Tampons::default();
    assert!(Annonce::decoder(texte.as_bytes(), &mut tampons).is_ok());
}

#[test]
fn un_nom_de_service_invalide_est_refuse_au_cadrage() {
    // Le cadrage délègue au type : c'est `NomService` qui refuse, et son refus
    // remonte tel quel plutôt que d'être traduit en faute de forme.
    let texte = format!(
        r#"{{"machine":"{}","service":"Sauvegarde","points":[{{"protocole":"tcp","port":1}}]}}"#,
        machine_texte()
    );
    assert_eq!(
        decoder(&texte),
        Err(Erreur::NomSymboleInvalide { position: 0 })
    );
}

#[test]
fn un_point_qui_n_est_pas_un_objet_est_refuse() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[1]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::JsonAttendu {
            attendu: "un objet",
            ..
        })
    ));
}

#[test]
fn une_cle_de_point_qui_n_est_pas_une_chaine_est_refusee() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{1:2}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::JsonAttendu {
            attendu: "une chaîne",
            ..
        })
    ));
}

#[test]
fn un_deux_points_manquant_dans_un_point_est_refuse() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole" "tcp"}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::JsonAttendu {
            attendu: "deux-points",
            ..
        })
    ));
}

#[test]
fn une_adresse_qui_n_est_pas_une_chaine_est_refusee() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}],"adresses_locales":[1]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::JsonAttendu {
            attendu: "une chaîne",
            ..
        })
    ));
}

#[test]
fn un_protocole_inconnu_est_refuse_au_cadrage() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"sctp","port":1}}]}}"#,
        machine_texte()
    );
    assert_eq!(decoder(&texte), Err(Erreur::ProtocoleInconnu));
}

#[test]
fn un_protocole_qui_n_est_pas_une_chaine_est_refuse() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":6,"port":1}}]}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::JsonAttendu {
            attendu: "une chaîne",
            ..
        })
    ));
}

#[test]
fn des_adresses_locales_qui_ne_sont_pas_un_tableau_sont_refusees() {
    let texte = format!(
        r#"{{"machine":"{}","service":"x","points":[{{"protocole":"tcp","port":1}}],"adresses_locales":{{}}}}"#,
        machine_texte()
    );
    assert!(matches!(
        decoder(&texte),
        Err(Erreur::JsonAttendu {
            attendu: "un tableau",
            ..
        })
    ));
}
