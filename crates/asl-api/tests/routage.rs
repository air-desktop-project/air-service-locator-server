//! Le routage, chemin par chemin.
//!
//! **Deux propriétés valent plus que les autres**, et elles ont leurs sections :
//! le routage ne juge pas le verbe, et aucun pourcent-encodage n'entre.

use asl_api::{
    ALIAS_MAX, ALIAS_MIN, Alias, CIBLE_MAX, Erreur, Exigence, Methode, Ressource, resoudre,
    separer_requete,
};
use asl_id::{Genre, Identifiant};

/// Un identifiant du genre voulu, écrit.
fn ident(genre: Genre) -> String {
    Identifiant::depuis_entropie(genre, [0x33; 16])
        .texte()
        .as_str()
        .to_owned()
}

fn resoudre_get(cible: &str) -> Result<Ressource<'_>, Erreur> {
    resoudre(Methode::Get, cible.as_bytes()).map(|resolu| resolu.ressource)
}

// ── La table des chemins ────────────────────────────────────────────────────

#[test]
fn chaque_chemin_designe_sa_ressource() {
    let u = ident(Genre::Utilisateur);
    let a = ident(Genre::Appareil);
    let m = ident(Genre::Machine);
    let g = ident(Genre::Autorisation);
    let n = ident(Genre::Annuaire);

    let cas: [(String, Ressource<'_>); 6] = [
        ("/v1/comptes".to_owned(), Ressource::Comptes),
        ("/v1/appareils".to_owned(), Ressource::Appareils),
        ("/v1/machines".to_owned(), Ressource::Machines),
        ("/v1/autorisations".to_owned(), Ressource::Autorisations),
        ("/v1/alias".to_owned(), Ressource::Alias),
        ("/v1/expositions".to_owned(), Ressource::Expositions),
    ];
    for (cible, attendu) in cas {
        assert_eq!(resoudre_get(&cible).unwrap(), attendu, "{cible}");
    }

    // Les chemins qui portent un identifiant, et le GENRE que chacun exige.
    assert!(matches!(
        resoudre_get(&format!("/v1/utilisateurs/{u}")).unwrap(),
        Ressource::Utilisateur { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/appareils/{a}")).unwrap(),
        Ressource::Appareil { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/appareils/{a}/poussee")).unwrap(),
        Ressource::PousseeAppareil { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/machines/{m}")).unwrap(),
        Ressource::Machine { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/machines/{m}/enrolement")).unwrap(),
        Ressource::EnrolementMachine { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/machines/{m}/cle")).unwrap(),
        Ressource::CleMachine { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/machines/{m}/services")).unwrap(),
        Ressource::ServicesMachine { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/autorisations/{g}")).unwrap(),
        Ressource::Autorisation { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/expositions/{n}")).unwrap(),
        Ressource::Exposition { .. }
    ));
    assert!(matches!(
        resoudre_get(&format!("/v1/ou/{m}/depot")).unwrap(),
        Ressource::Ou { .. }
    ));
    assert!(matches!(
        resoudre_get("/v1/ou?service=depot").unwrap(),
        Ressource::OuParNom { .. }
    ));
    assert!(matches!(
        resoudre_get("/v1/alias/thierry").unwrap(),
        Ressource::AliasResolu { .. }
    ));
}

#[test]
fn chaque_segment_exige_le_bon_genre() {
    // Un identifiant de machine là où l'on attend un appareil est REFUSÉ, et non
    // traité comme un appareil inconnu : les deux fautes n'appellent pas la même
    // correction chez qui les lit.
    let m = ident(Genre::Machine);
    for (cible, attendu) in [
        (format!("/v1/utilisateurs/{m}"), Genre::Utilisateur),
        (format!("/v1/appareils/{m}"), Genre::Appareil),
        (format!("/v1/autorisations/{m}"), Genre::Autorisation),
        (format!("/v1/expositions/{m}"), Genre::Annuaire),
    ] {
        assert_eq!(
            resoudre_get(&cible),
            Err(Erreur::IdentifiantInvalide { attendu }),
            "{cible}"
        );
    }

    let u = ident(Genre::Utilisateur);
    assert_eq!(
        resoudre_get(&format!("/v1/machines/{u}/cle")),
        Err(Erreur::IdentifiantInvalide {
            attendu: Genre::Machine
        })
    );
    assert_eq!(
        resoudre_get(&format!("/v1/ou/{u}/depot")),
        Err(Erreur::IdentifiantInvalide {
            attendu: Genre::Machine
        })
    );
}

#[test]
fn un_chemin_inconnu_est_refuse() {
    for cible in [
        "/v1",
        "/v2/comptes",
        "/v1/inconnu",
        "/v1/machines/x/y/z",
        "/v1/a/b/c/d/e/f",
    ] {
        assert_eq!(
            resoudre_get(cible),
            Err(Erreur::RessourceInconnue),
            "{cible}"
        );
    }
}

// ── Le routage ne juge pas le verbe ─────────────────────────────────────────

#[test]
fn le_routage_resout_meme_un_verbe_non_servi() {
    // **PROPRIÉTÉ DE SÉCURITÉ.** Rendre « méthode non permise » depuis ici le
    // rendrait AVANT toute vérification d'autorisation, ce qui distinguerait une
    // ressource qui existe d'un chemin qui n'existe pas.
    let resolu = resoudre(Methode::Delete, b"/v1/comptes").expect("le chemin se résout");
    assert_eq!(resolu.ressource, Ressource::Comptes);
    assert_eq!(resolu.methode, Methode::Delete);
    assert!(!resolu.sert, "`Comptes` ne sert pas DELETE");

    let resolu = resoudre(Methode::Post, b"/v1/comptes").unwrap();
    assert!(resolu.sert);
}

#[test]
fn chaque_ressource_sert_ce_qu_elle_annonce_et_rien_d_autre() {
    let m = ident(Genre::Machine);
    let cibles = [
        "/v1/comptes".to_owned(),
        "/v1/appareils".to_owned(),
        "/v1/machines".to_owned(),
        "/v1/autorisations".to_owned(),
        "/v1/alias".to_owned(),
        "/v1/expositions".to_owned(),
        format!("/v1/machines/{m}"),
        format!("/v1/machines/{m}/cle"),
        format!("/v1/machines/{m}/services"),
        format!("/v1/machines/{m}/enrolement"),
        "/v1/alias/thierry".to_owned(),
        "/v1/ou?service=depot".to_owned(),
    ];
    let verbes = [
        Methode::Get,
        Methode::Post,
        Methode::Put,
        Methode::Patch,
        Methode::Delete,
    ];

    for cible in cibles {
        for methode in verbes {
            let resolu = resoudre(methode, cible.as_bytes()).unwrap_or_else(|e| {
                panic!("{cible} avec {methode:?} : {e:?}");
            });
            assert_eq!(
                resolu.sert,
                resolu.ressource.verbes().contains(&methode),
                "{cible} / {methode:?}"
            );
            assert_eq!(resolu.exigence, resolu.ressource.exigence());
        }
    }
}

#[test]
fn les_verbes_qui_modifient_sont_ceux_qu_on_croit() {
    assert!(!Methode::Get.modifie());
    for methode in [Methode::Post, Methode::Put, Methode::Patch, Methode::Delete] {
        assert!(methode.modifie(), "{methode:?}");
    }
}

// ── Les exigences ───────────────────────────────────────────────────────────

#[test]
fn trois_ressources_seulement_n_exigent_rien() {
    let u = ident(Genre::Utilisateur);
    for cible in [
        "/v1/comptes".to_owned(),
        "/v1/alias/thierry".to_owned(),
        // **`/v1/vu` NE PARLE QUE DE LA CONNEXION QUI DEMANDE**, et ne rend rien
        // qu'un serveur STUN public ne rendrait. Exiger une clé aurait exclu le
        // cas le plus utile : la machine qu'on installe, qui veut savoir si elle
        // atteint l'annuaire avant même d'avoir un code d'enrôlement.
        "/v1/vu".to_owned(),
        format!("/v1/utilisateurs/{u}"),
    ] {
        assert_eq!(
            resoudre_get(&cible).unwrap().exigence(),
            Exigence::Aucune,
            "{cible}"
        );
    }

    let m = ident(Genre::Machine);
    // La résolution exige une machine porteuse de `lecture`.
    for cible in [
        format!("/v1/ou/{m}/depot"),
        "/v1/ou?service=depot".to_owned(),
    ] {
        assert_eq!(
            resoudre_get(&cible).unwrap().exigence(),
            Exigence::MachineLecture,
            "{cible}"
        );
    }

    // Tout le reste exige un appareil enrôlé.
    for cible in [
        "/v1/appareils".to_owned(),
        "/v1/machines".to_owned(),
        "/v1/autorisations".to_owned(),
        "/v1/alias".to_owned(),
        "/v1/expositions".to_owned(),
        format!("/v1/machines/{m}/services"),
    ] {
        assert_eq!(
            resoudre_get(&cible).unwrap().exigence(),
            Exigence::Appareil,
            "{cible}"
        );
    }
}

// ── Aucun pourcent-encodage ─────────────────────────────────────────────────

#[test]
fn tout_pourcent_encodage_est_refuse() {
    // `%75` à la place d'un `u` serait une deuxième écriture de la même cible ;
    // `%2e%2e` serait une traversée. Les deux se ferment d'un coup.
    for cible in [
        "/v1/%63omptes",
        "/v1/comptes%2f",
        "/v1/%2e%2e/comptes",
        "/v1/alias/thier%72y",
        "/%",
    ] {
        assert!(
            matches!(resoudre_get(cible), Err(Erreur::EncodageRefuse { .. })),
            "{cible}"
        );
    }
}

#[test]
fn la_traversee_de_chemin_est_structurellement_impossible() {
    // Il n'y a aucune règle anti-traversée dans ce code : c'est l'alphabet des
    // noms et des identifiants qui la rend inutile. `.` et `..` ne sont ni l'un
    // ni l'autre.
    let m = ident(Genre::Machine);
    for cible in [
        "/v1/../etc/passwd".to_owned(),
        "/v1/machines/../comptes".to_owned(),
        format!("/v1/ou/{m}/.."),
        format!("/v1/ou/{m}/."),
        "/v1/alias/..".to_owned(),
    ] {
        assert!(resoudre_get(&cible).is_err(), "{cible}");
    }
}

#[test]
fn les_octets_hors_ascii_graphique_sont_refuses() {
    for cible in [
        "/v1/comptes\u{0}",
        "/v1/com ptes",
        "/v1/comptés",
        "/v1/\u{7f}",
    ] {
        assert!(
            matches!(
                resoudre_get(cible),
                Err(Erreur::CibleNonAscii { .. } | Erreur::RessourceInconnue)
            ),
            "{cible:?}"
        );
    }
}

// ── La forme de la cible ────────────────────────────────────────────────────

#[test]
fn une_cible_sans_racine_est_refusee() {
    for cible in ["v1/comptes", "", "?service=depot"] {
        assert_eq!(
            resoudre_get(cible),
            Err(Erreur::CibleSansRacine),
            "{cible:?}"
        );
    }
}

#[test]
fn un_segment_vide_est_refuse() {
    // `//` et un `/` final de trop désignent la même ressource dans certaines
    // piles et pas dans d'autres. Ici, ni l'un ni l'autre.
    // `/` seul en fait partie : c'est un chemin dont l'unique segment est vide,
    // et le dire ainsi est plus précis que « ressource inconnue ».
    for (cible, rang) in [
        ("/v1//comptes", 1_usize),
        ("/v1/comptes/", 2),
        ("//", 0),
        ("/", 0),
    ] {
        assert_eq!(
            resoudre_get(cible),
            Err(Erreur::SegmentVide { rang }),
            "{cible}"
        );
    }
}

#[test]
fn une_cible_trop_longue_est_refusee_avant_toute_lecture() {
    let longue = format!("/{}", "a".repeat(CIBLE_MAX));
    assert_eq!(
        resoudre_get(&longue),
        Err(Erreur::CibleTropLongue {
            obtenue: CIBLE_MAX + 1
        })
    );
}

// ── La chaîne de requête ────────────────────────────────────────────────────

#[test]
fn la_requete_se_separe_du_chemin() {
    assert_eq!(separer_requete(b"/v1/ou"), (&b"/v1/ou"[..], &b""[..]));
    assert_eq!(
        separer_requete(b"/v1/ou?service=depot"),
        (&b"/v1/ou"[..], &b"service=depot"[..])
    );
    assert_eq!(separer_requete(b"?x"), (&b""[..], &b"x"[..]));
    // Un second `?` appartient à la requête, pas au chemin.
    assert_eq!(separer_requete(b"/a?b?c"), (&b"/a"[..], &b"b?c"[..]));
}

#[test]
fn seul_le_parametre_service_est_admis() {
    // Ignorer un paramètre inconnu laisserait un client croire qu'il a demandé
    // quelque chose que personne n'a lu.
    for requete in ["", "x=1", "service", "services=depot", "service=depot&x=1"] {
        assert!(
            matches!(
                resoudre_get(&format!("/v1/ou?{requete}")),
                Err(Erreur::RequeteInvalide | Erreur::NomInvalide)
            ),
            "{requete:?}"
        );
    }
    assert!(resoudre_get("/v1/ou?service=depot-de-messages").is_ok());
}

#[test]
fn un_nom_de_service_invalide_est_refuse_dans_les_deux_formes() {
    let m = ident(Genre::Machine);
    assert_eq!(
        resoudre_get(&format!("/v1/ou/{m}/Depot")),
        Err(Erreur::NomInvalide)
    );
    assert_eq!(
        resoudre_get("/v1/ou?service=Depot"),
        Err(Erreur::NomInvalide)
    );
}

// ── L'alias ─────────────────────────────────────────────────────────────────

#[test]
fn un_alias_ordinaire_passe() {
    for texte in [
        "abc",
        "thierry",
        "air.desktop",
        "a_b-c",
        &"a".repeat(ALIAS_MAX),
    ] {
        let alias = Alias::analyser(texte).unwrap_or_else(|e| panic!("{texte} : {e:?}"));
        assert_eq!(alias.as_str(), texte);
    }
}

#[test]
fn un_alias_ne_peut_pas_ressembler_a_un_identifiant() {
    // **La règle qui compte** : dans l'application, un utilisateur tape SOIT un
    // identifiant SOIT un alias, dans le MÊME champ. Si les deux formes
    // pouvaient se confondre, l'application devrait deviner — et se tromperait
    // un jour sur un alias que quelqu'un aurait choisi exprès.
    for texte in ["u-abc", "m-thierry", "x-y", "a-bc"] {
        assert_eq!(
            Alias::analyser(texte),
            Err(Erreur::AliasRessembleAUnIdentifiant),
            "{texte}"
        );
    }
    // Un tiret ailleurs qu'en deuxième position ne gêne pas.
    assert!(Alias::analyser("ab-cd").is_ok());
}

#[test]
fn les_bornes_et_l_alphabet_de_l_alias() {
    for texte in ["", "ab", &"a".repeat(ALIAS_MAX + 1)] {
        assert_eq!(
            Alias::analyser(texte),
            Err(Erreur::AliasLongueur {
                obtenue: texte.len()
            }),
            "{texte:?}"
        );
    }
    assert_eq!(ALIAS_MIN, 3);

    assert_eq!(
        Alias::analyser("Thierry"),
        Err(Erreur::AliasSymboleInvalide { position: 0 })
    );
    assert_eq!(
        Alias::analyser("thi erry"),
        Err(Erreur::AliasSymboleInvalide { position: 3 })
    );

    for texte in ["-abc", "abc-", ".abc", "abc."] {
        assert_eq!(
            Alias::analyser(texte),
            Err(Erreur::AliasBordInvalide),
            "{texte}"
        );
    }
}

#[test]
fn un_alias_invalide_dans_un_chemin_remonte_tel_quel() {
    assert_eq!(
        resoudre_get("/v1/alias/ab"),
        Err(Erreur::AliasLongueur { obtenue: 2 })
    );
    assert_eq!(
        resoudre_get("/v1/alias/u-abc"),
        Err(Erreur::AliasRessembleAUnIdentifiant)
    );
}

#[test]
fn chaque_route_qui_porte_un_identifiant_verifie_son_genre() {
    // Une route par ligne : ce qui n'est pas éprouvé est du code qu'on croit
    // éprouvé.
    let mauvais = ident(Genre::Utilisateur);
    let m = ident(Genre::Machine);

    let cas: [(String, Genre); 8] = [
        (format!("/v1/appareils/{mauvais}/poussee"), Genre::Appareil),
        (format!("/v1/machines/{mauvais}"), Genre::Machine),
        (format!("/v1/machines/{mauvais}/enrolement"), Genre::Machine),
        (format!("/v1/machines/{mauvais}/cle"), Genre::Machine),
        (format!("/v1/machines/{mauvais}/services"), Genre::Machine),
        (format!("/v1/autorisations/{mauvais}"), Genre::Autorisation),
        (format!("/v1/expositions/{mauvais}"), Genre::Annuaire),
        (format!("/v1/ou/{mauvais}/depot"), Genre::Machine),
    ];
    for (cible, attendu) in cas {
        assert_eq!(
            resoudre_get(&cible),
            Err(Erreur::IdentifiantInvalide { attendu }),
            "{cible}"
        );
    }

    // Et un identifiant simplement mal formé est refusé de la même façon : le
    // genre attendu est ce qu'on dit, pas ce qui a été lu.
    assert_eq!(
        resoudre_get("/v1/machines/pas-un-identifiant/cle"),
        Err(Erreur::IdentifiantInvalide {
            attendu: Genre::Machine
        })
    );
    // La route à deux identifiants valides passe, elle.
    assert!(resoudre_get(&format!("/v1/ou/{m}/depot")).is_ok());
}

#[test]
fn une_requete_qui_n_est_pas_de_l_utf8_est_refusee() {
    // La chaîne de requête n'est PAS soumise au contrôle ASCII du chemin : elle
    // arrive telle quelle, et c'est ici qu'elle est refusée.
    let mut cible = b"/v1/ou?service=".to_vec();
    cible.push(0xFF);
    assert_eq!(
        resoudre(Methode::Get, &cible).map(|_| ()),
        Err(Erreur::RequeteInvalide)
    );
}

// ── Le défi ─────────────────────────────────────────────────────────────────

#[test]
fn le_defi_se_route_et_sert_les_deux_verbes() {
    // `GET` tire un défi, `POST` rapporte la signature. Rien d'autre.
    for (methode, sert) in [
        (Methode::Get, true),
        (Methode::Post, true),
        (Methode::Put, false),
        (Methode::Patch, false),
        (Methode::Delete, false),
    ] {
        let resolu = resoudre(methode, b"/v1/defi").expect("la cible se route");
        assert_eq!(resolu.ressource, Ressource::Defi);
        assert_eq!(resolu.sert, sert, "{methode:?}");
    }
}

#[test]
fn le_defi_n_exige_aucune_preuve_et_c_est_le_point() {
    // **C'EST ELLE QUI PRODUIT LA PREUVE.** Si elle en exigeait une, aucune
    // connexion ne pourrait jamais s'authentifier.
    let resolu = resoudre(Methode::Get, b"/v1/defi").expect("la cible se route");
    assert_eq!(resolu.exigence, Exigence::Aucune);
}

// ── L'annonce ───────────────────────────────────────────────────────────────

#[test]
fn l_annonce_n_a_qu_un_verbe() {
    // **PAS DE `DELETE`** : fermer la connexion suffit, et un verbe de retrait
    // ferait deux façons de dire la même chose. Pas de `PUT` non plus : la
    // connexion EST le bail.
    for (methode, sert) in [
        (Methode::Post, true),
        (Methode::Get, false),
        (Methode::Put, false),
        (Methode::Patch, false),
        (Methode::Delete, false),
    ] {
        let resolu = resoudre(methode, b"/v1/annonce").expect("la cible se route");
        assert_eq!(resolu.ressource, Ressource::Annonce);
        assert_eq!(resolu.sert, sert, "{methode:?}");
    }
}

#[test]
fn l_annonce_exige_la_capacite_d_annoncer_et_non_celle_de_lire() {
    // **LES DEUX CAPACITÉS NE SE CONFONDENT PAS** : un daemon qui annonce n'a
    // aucune raison de pouvoir interroger l'annuaire, et réciproquement.
    let annonce = resoudre(Methode::Post, b"/v1/annonce").expect("la cible se route");
    assert_eq!(annonce.exigence, Exigence::MachineAnnonce);

    let lecture = resoudre(Methode::Get, b"/v1/ou?service=imap").expect("la cible se route");
    assert_eq!(lecture.exigence, Exigence::MachineLecture);
}

// ── La route qui manquait ───────────────────────────────────────────────────

#[test]
fn l_enrolement_d_une_machine_se_route_et_n_exige_rien() {
    // **ELLE EST PARLÉE PAR LA MACHINE**, à qui l'annuaire ne connaît encore
    // rien : c'est le code d'enrôlement qui fait justificatif, et lui seul.
    let resolu = resoudre(Methode::Post, b"/v1/enrolement").expect("elle se route");
    assert_eq!(resolu.ressource, Ressource::Enrolement);
    assert!(resolu.sert);
    assert_eq!(resolu.exigence, Exigence::Aucune);
}

#[test]
fn l_enrolement_ne_sert_que_le_post() {
    for methode in [Methode::Get, Methode::Put, Methode::Patch, Methode::Delete] {
        let resolu = resoudre(methode, b"/v1/enrolement").expect("elle se route");
        assert!(!resolu.sert, "{methode:?}");
    }
}

#[test]
fn l_enrolement_d_une_machine_ne_se_confond_pas_avec_l_emission_d_un_code() {
    // Les deux verbes sont aux deux bouts du même geste, et n'ont ni le même
    // public ni la même exigence : celui-ci nomme la machine et exige un
    // appareil, celui-là ne nomme personne et n'exige rien.
    let machine = Identifiant::depuis_entropie(Genre::Machine, [3; 16]);
    let cible = format!("/v1/machines/{}/enrolement", machine.texte());
    let resolu = resoudre(Methode::Post, cible.as_bytes()).expect("elle se route");
    assert_eq!(resolu.ressource, Ressource::EnrolementMachine { machine });
    assert_eq!(resolu.exigence, Exigence::Appareil);
}

// ── Les deux verbes des listes ──────────────────────────────────────────────

#[test]
fn machines_et_appareils_servent_lecture_et_creation() {
    // **`GET` LISTE, `POST` CRÉE.** Les écrans « Machines » et « Compte »
    // (`protocole.md` §2.2) n'avaient aucun verbe pour se remplir tant que ces
    // ressources ne servaient que la création.
    for cible in [&b"/v1/machines"[..], &b"/v1/appareils"[..]] {
        for (methode, sert) in [
            (Methode::Get, true),
            (Methode::Post, true),
            (Methode::Put, false),
            (Methode::Patch, false),
            (Methode::Delete, false),
        ] {
            let resolu = resoudre(methode, cible).expect("la cible se route");
            assert_eq!(
                resolu.sert,
                sert,
                "{} {methode:?}",
                core::str::from_utf8(cible).unwrap()
            );
        }
    }
}

#[test]
fn lister_ses_machines_ou_appareils_exige_un_appareil() {
    // La lecture n'ouvre pas plus que la création : c'est le compte de l'appareil
    // qui demande, et lui seul. Nommer un autre compte n'y donne pas droit.
    for cible in [&b"/v1/machines"[..], &b"/v1/appareils"[..]] {
        let resolu = resoudre(Methode::Get, cible).expect("la cible se route");
        assert_eq!(resolu.exigence, Exigence::Appareil);
    }
}
