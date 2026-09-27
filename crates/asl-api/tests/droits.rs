//! Les droits sur le fil (`protocole.md` §2.2, 2026-09-27) : la demande de
//! `POST /v1/droits`, et ce que `GET /v1/droits` rend.

use asl_api::droit::{DemandeDeDroit, DroitRendu, NOMS_DE_DROITS};
use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;

fn un(genre: Genre) -> Identifiant {
    Identifiant::depuis_entropie(genre, [0x44; 16])
}

fn texte(genre: Genre) -> String {
    un(genre).texte().as_str().to_owned()
}

/// Une demande bien formée, avec ces droits écrits tels quels.
fn demande(element: &str, droits: &str) -> String {
    format!(
        r#"{{"groupe":"{}","element":"{element}","droits":{droits},"etiquette":"Famille"}}"#,
        texte(Genre::Ensemble)
    )
}

#[test]
fn une_demande_se_lit_et_se_reecrit_a_l_identique() {
    for genre in [Genre::Domaine, Genre::Machine, Genre::Service] {
        let corps = demande(&texte(genre), r#"["voir","localiser"]"#);
        let lue = DemandeDeDroit::decoder(corps.as_bytes()).unwrap();
        assert_eq!(lue.groupe, un(Genre::Ensemble));
        assert_eq!(lue.element, un(genre));
        assert_eq!(lue.droits, 0b1100);
        assert_eq!(lue.etiquette, "Famille");
        let mut sortie = [0_u8; 512];
        let combien = lue.encoder(&mut sortie).unwrap();
        assert_eq!(&sortie[..combien], corps.as_bytes());
    }
}

#[test]
fn les_droits_viennent_dans_n_importe_quel_ordre_et_s_ecrivent_dans_le_sien() {
    let corps = demande(
        &texte(Genre::Domaine),
        r#"[ "localiser" , "administrer","rattacher" ,"voir" ]"#,
    );
    let lue = DemandeDeDroit::decoder(corps.as_bytes()).unwrap();
    assert_eq!(lue.droits, 0b1111);
    let mut sortie = [0_u8; 512];
    let combien = lue.encoder(&mut sortie).unwrap();
    let reecrit = core::str::from_utf8(&sortie[..combien]).unwrap();
    assert!(reecrit.contains(r#""droits":["administrer","rattacher","voir","localiser"]"#));
    // Un nom par bit, au rang de son bit.
    for (rang, nom) in NOMS_DE_DROITS.iter().enumerate() {
        let seul = demande(&texte(Genre::Domaine), &format!(r#"["{nom}"]"#));
        assert_eq!(
            DemandeDeDroit::decoder(seul.as_bytes()).unwrap().droits,
            1 << rang
        );
    }
}

#[test]
fn les_champs_viennent_dans_n_importe_quel_ordre() {
    let corps = format!(
        r#"{{ "etiquette" : "Bureau", "droits" : ["voir"], "element" : "{}", "groupe" : "{}" }}"#,
        texte(Genre::Machine),
        texte(Genre::Ensemble)
    );
    let lue = DemandeDeDroit::decoder(corps.as_bytes()).unwrap();
    assert_eq!(lue.element, un(Genre::Machine));
    assert_eq!(lue.etiquette, "Bureau");
}

#[test]
fn un_element_ou_un_groupe_d_un_autre_genre_est_refuse() {
    // Pas un compte : l'élément « compte » ne s'accorde plus que par le verbe
    // de compatibilité. Ni rien d'autre.
    for genre in [Genre::Utilisateur, Genre::Appareil, Genre::Ensemble] {
        let corps = demande(&texte(genre), r#"["voir"]"#);
        assert!(
            matches!(
                DemandeDeDroit::decoder(corps.as_bytes()),
                Err(Erreur::IdentifiantInvalide { .. })
            ),
            "{genre:?}"
        );
    }
    let corps = format!(
        r#"{{"groupe":"{}","element":"{}","droits":["voir"],"etiquette":"x"}}"#,
        texte(Genre::Utilisateur),
        texte(Genre::Domaine)
    );
    assert!(matches!(
        DemandeDeDroit::decoder(corps.as_bytes()),
        Err(Erreur::IdentifiantInvalide { .. })
    ));
}

#[test]
fn un_tableau_de_droits_mal_forme_est_refuse() {
    let d = texte(Genre::Domaine);
    // Vide : un droit qui ne permettrait rien.
    assert_eq!(
        DemandeDeDroit::decoder(demande(&d, "[ ]").as_bytes()),
        Err(Erreur::ChampManquant { nom: "droits" })
    );
    // Inconnu, répété.
    assert!(matches!(
        DemandeDeDroit::decoder(demande(&d, r#"["lire"]"#).as_bytes()),
        Err(Erreur::ChampInconnu { .. })
    ));
    assert!(matches!(
        DemandeDeDroit::decoder(demande(&d, r#"["voir","voir"]"#).as_bytes()),
        Err(Erreur::ChampEnDouble { .. })
    ));
    // Pas un tableau, un élément qui n'est pas une chaîne, un séparateur faux.
    for droits in [r#""voir""#, "[1]", r#"["voir";"localiser"]"#, r#"["voir""#] {
        assert!(
            DemandeDeDroit::decoder(demande(&d, droits).as_bytes()).is_err(),
            "{droits}"
        );
    }
}

#[test]
fn l_etiquette_suit_les_regles_d_un_nom() {
    let base = |etiquette: &str| {
        format!(
            r#"{{"groupe":"{}","element":"{}","droits":["voir"],"etiquette":{etiquette}}}"#,
            texte(Genre::Ensemble),
            texte(Genre::Domaine)
        )
    };
    assert_eq!(
        DemandeDeDroit::decoder(base(r#""""#).as_bytes()),
        Err(Erreur::NomVide)
    );
    let longue = format!("\"{}\"", "é".repeat(33));
    assert_eq!(
        DemandeDeDroit::decoder(base(&longue).as_bytes()),
        Err(Erreur::NomTropLong { obtenue: 66 })
    );
    assert!(DemandeDeDroit::decoder(base("7").as_bytes()).is_err());
    assert_eq!(
        DemandeDeDroit::decoder(base(r#""Maison — été""#).as_bytes())
            .unwrap()
            .etiquette,
        "Maison — été"
    );
}

#[test]
fn un_champ_manquant_inconnu_ou_double_est_refuse() {
    let g = texte(Genre::Ensemble);
    let d = texte(Genre::Domaine);
    let complets = [
        format!(r#""groupe":"{g}""#),
        format!(r#""element":"{d}""#),
        r#""droits":["voir"]"#.to_owned(),
        r#""etiquette":"x""#.to_owned(),
    ];
    for (rang, nom) in ["groupe", "element", "droits", "etiquette"]
        .iter()
        .enumerate()
    {
        let restants: Vec<&str> = complets
            .iter()
            .enumerate()
            .filter(|(autre, _)| *autre != rang)
            .map(|(_, champ)| champ.as_str())
            .collect();
        let corps = format!("{{{}}}", restants.join(","));
        assert_eq!(
            DemandeDeDroit::decoder(corps.as_bytes()),
            Err(Erreur::ChampManquant { nom }),
            "{nom}"
        );
    }
    let inconnu = format!("{{{},\"a\":\"x\"}}", complets.join(","));
    assert!(matches!(
        DemandeDeDroit::decoder(inconnu.as_bytes()),
        Err(Erreur::ChampInconnu { .. })
    ));
    let double = format!("{{{},{}}}", complets.join(","), complets[0]);
    assert!(matches!(
        DemandeDeDroit::decoder(double.as_bytes()),
        Err(Erreur::ChampEnDouble { .. })
    ));
}

#[test]
fn un_cadrage_mal_forme_est_refuse() {
    let bonne = demande(&texte(Genre::Domaine), r#"["voir"]"#);
    for corps in [
        "[]".to_owned(),
        "{1:2}".to_owned(),
        r#"{"groupe" "x"}"#.to_owned(),
        bonne.replace(",\"element\"", ";\"element\""),
        format!("{bonne} x"),
        format!(r#"{{"groupe":{}}}"#, 7),
        format!(r#"{{"element":{}}}"#, 7),
    ] {
        assert!(
            DemandeDeDroit::decoder(corps.as_bytes()).is_err(),
            "{corps}"
        );
    }
    let trop = vec![b' '; 513];
    assert_eq!(
        DemandeDeDroit::decoder(&trop),
        Err(Erreur::MessageTropLong { obtenue: 513 })
    );
}

#[test]
fn un_tampon_trop_petit_se_dit() {
    let corps = demande(&texte(Genre::Domaine), r#"["voir"]"#);
    let lue = DemandeDeDroit::decoder(corps.as_bytes()).unwrap();
    let mut sortie = [0_u8; 8];
    assert!(lue.encoder(&mut sortie).is_err());
}

#[test]
fn un_droit_se_rend_avec_ce_qu_il_permet_et_son_retrait() {
    let rendu = |retire: bool| DroitRendu {
        droit: un(Genre::Autorisation),
        groupe: un(Genre::Ensemble),
        element: un(Genre::Domaine),
        droits: 0b1010,
        etiquette: "Famille",
        par: un(Genre::Utilisateur),
        retire,
    };
    for retire in [false, true] {
        let mut sortie = [0_u8; 512];
        let combien = rendu(retire).encoder(&mut sortie).unwrap();
        assert_eq!(
            core::str::from_utf8(&sortie[..combien]).unwrap(),
            format!(
                r#"{{"droit":"{}","groupe":"{}","element":"{}","droits":["rattacher","localiser"],"etiquette":"Famille","par":"{}","retire":{retire}}}"#,
                texte(Genre::Autorisation),
                texte(Genre::Ensemble),
                texte(Genre::Domaine),
                texte(Genre::Utilisateur)
            )
        );
    }
    let mut petite = [0_u8; 8];
    assert!(rendu(false).encoder(&mut petite).is_err());
}
