//! Les corps de l'API mobile : ce qu'ils acceptent, et ce qu'ils refusent.

use asl_api::corps::{
    CORPS_MAX, Capacites, DeclarationMachine, DemandeAlias, DemandeAutorisation, DepotJeton,
    JETON_MAX, ModificationMachine, NOM_MACHINE_MAX, Plateforme, Portee,
};
use asl_id::{Genre, Identifiant};
use asl_proto::Erreur;

/// Un identifiant de ce genre, reproductible.
fn un(genre: Genre) -> Identifiant {
    Identifiant::depuis_entropie(genre, [0x2B; 16])
}

// ── Déclarer une machine ────────────────────────────────────────────────────

#[test]
fn une_declaration_se_lit_et_se_reecrit_a_l_identique() {
    let octets = br#"{"nom":"grenier","capacites":["annonce","lecture"]}"#;
    let lue = DeclarationMachine::decoder(octets).expect("elle se lit");
    assert_eq!(lue.nom, "grenier");
    assert!(lue.capacites.annonce && lue.capacites.lecture);

    let mut sortie = [0_u8; CORPS_MAX];
    let combien = lue.encoder(&mut sortie).expect("elle se réécrit");
    assert_eq!(&sortie[..combien], &octets[..]);
}

#[test]
fn les_champs_viennent_dans_n_importe_quel_ordre() {
    let lue = DeclarationMachine::decoder(br#"{"capacites":[],"nom":"portable"}"#)
        .expect("l'ordre est libre");
    assert_eq!(lue.nom, "portable");
    assert_eq!(lue.capacites, Capacites::default());
}

#[test]
fn une_machine_sans_aucune_capacite_est_legitime() {
    // Déclarée, et qui ne peut rien : c'est un état qu'on a le droit de vouloir,
    // et c'est même le défaut que l'application propose.
    let lue = DeclarationMachine::decoder(br#"{"nom":"n","capacites":[]}"#).expect("elle se lit");
    assert!(!lue.capacites.annonce && !lue.capacites.lecture);

    let mut sortie = [0_u8; CORPS_MAX];
    let combien = lue.encoder(&mut sortie).expect("elle se réécrit");
    assert_eq!(&sortie[..combien], br#"{"nom":"n","capacites":[]}"#);
}

#[test]
fn un_nom_porte_les_accents_et_les_ideogrammes() {
    // **C'EST LA DÉCISION DE LA TRANCHE** : un nom d'affichage n'est comparé à
    // rien, donc l'argument d'équivalence Unicode qui interdit le non-ASCII
    // ailleurs ne vaut pas ici.
    for nom in [
        "Mac de Thérèse",
        "屋根裏",
        "grenier 🏠",
        "Ordinateur d'André",
    ] {
        let corps = alloc_corps(nom);
        let lue = DeclarationMachine::decoder(corps.as_bytes())
            .unwrap_or_else(|faute| panic!("{nom} devrait passer : {faute:?}"));
        assert_eq!(lue.nom, nom);
    }
}

/// Le corps d'une déclaration portant ce nom.
fn alloc_corps(nom: &str) -> String {
    format!(r#"{{"nom":"{nom}","capacites":["annonce"]}}"#)
}

#[test]
fn un_nom_qui_ment_sur_ce_qui_l_entoure_est_refuse() {
    // Les forceurs de sens d'écriture ne s'affichent pas eux-mêmes : ils
    // retournent leurs voisins. Un nom de machine se lit dans une liste.
    for (nom, quoi) in [
        ("gre\u{202E}nier", "forceur de sens"),
        ("gre\u{2066}nier", "isolat"),
        ("\u{FEFF}grenier", "marque d'ordre des octets"),
        ("gre\u{0085}nier", "contrôle C1"),
    ] {
        let corps = alloc_corps(nom);
        assert!(
            matches!(
                DeclarationMachine::decoder(corps.as_bytes()),
                Err(Erreur::CaractereInvisibleRefuse { .. })
            ),
            "{quoi} devrait être refusé"
        );
    }
}

#[test]
fn un_nom_avec_un_controle_ou_un_echappement_est_refuse() {
    assert!(matches!(
        DeclarationMachine::decoder(b"{\"nom\":\"gre\x1bnier\",\"capacites\":[]}"),
        Err(Erreur::CaractereBrutRefuse { .. })
    ));
    assert!(matches!(
        DeclarationMachine::decoder(br#"{"nom":"gre\nier","capacites":[]}"#),
        Err(Erreur::EchappementRefuse { .. })
    ));
}

#[test]
fn un_nom_mal_encode_est_refuse() {
    // Une suite d'octets qui n'est pas de l'UTF-8 : elle passerait le filtre des
    // contrôles et ne serait pourtant pas du texte.
    let mut corps = b"{\"nom\":\"".to_vec();
    corps.extend_from_slice(&[0xC3, 0x28]);
    corps.extend_from_slice(b"\",\"capacites\":[]}");
    assert!(matches!(
        DeclarationMachine::decoder(&corps),
        Err(Erreur::TexteMalEncode { .. })
    ));
}

#[test]
fn un_nom_vide_ou_trop_long_est_refuse() {
    assert_eq!(
        DeclarationMachine::decoder(br#"{"nom":"","capacites":[]}"#).map(|_| ()),
        Err(Erreur::NomVide)
    );
    let trop = "a".repeat(NOM_MACHINE_MAX + 1);
    let corps = alloc_corps(&trop);
    assert_eq!(
        DeclarationMachine::decoder(corps.as_bytes()).map(|_| ()),
        Err(Erreur::NomTropLong {
            obtenue: NOM_MACHINE_MAX + 1
        })
    );

    // Et la borne elle-même passe : elle compte des OCTETS.
    let juste = "a".repeat(NOM_MACHINE_MAX);
    let corps = alloc_corps(&juste);
    assert!(DeclarationMachine::decoder(corps.as_bytes()).is_ok());
}

#[test]
fn un_champ_manquant_inconnu_ou_double_est_refuse() {
    assert_eq!(
        DeclarationMachine::decoder(br#"{"nom":"n"}"#).map(|_| ()),
        Err(Erreur::ChampManquant { nom: "capacites" })
    );
    assert_eq!(
        DeclarationMachine::decoder(br#"{"capacites":[]}"#).map(|_| ()),
        Err(Erreur::ChampManquant { nom: "nom" })
    );
    assert!(matches!(
        DeclarationMachine::decoder(br#"{"nom":"n","couleur":"bleu","capacites":[]}"#),
        Err(Erreur::ChampInconnu { .. })
    ));
    assert!(matches!(
        DeclarationMachine::decoder(br#"{"nom":"n","nom":"m","capacites":[]}"#),
        Err(Erreur::ChampEnDouble { .. })
    ));
}

#[test]
fn une_capacite_inconnue_ou_repetee_est_refusee() {
    assert!(matches!(
        DeclarationMachine::decoder(br#"{"nom":"n","capacites":["administrer"]}"#),
        Err(Erreur::ChampInconnu { .. })
    ));
    // **UNE CAPACITÉ EN DOUBLE EST UN CHAMP EN DOUBLE**, et pour la même raison :
    // deux lecteurs qui ne trancheraient pas pareil liraient deux demandes.
    assert!(matches!(
        DeclarationMachine::decoder(br#"{"nom":"n","capacites":["annonce","annonce"]}"#),
        Err(Erreur::ChampInconnu { .. })
    ));
}

#[test]
fn un_cadrage_mal_forme_est_refuse() {
    for octets in [
        &b""[..],
        &b"["[..],
        &br#"{"nom" "n","capacites":[]}"#[..],
        &br#"{"nom":"n","capacites":["annonce"}"#[..],
        &br#"{"nom":"n","capacites":[] "#[..],
        &br#"{"nom":"n","capacites":[]}x"#[..],
        &br#"{"nom":"n","capacites":"annonce"}"#[..],
    ] {
        assert!(
            DeclarationMachine::decoder(octets).is_err(),
            "{:?} devrait être refusé",
            String::from_utf8_lossy(octets)
        );
    }
}

#[test]
fn un_corps_trop_long_est_refuse_avant_toute_analyse() {
    let trop = vec![b'{'; CORPS_MAX + 1];
    assert_eq!(
        DeclarationMachine::decoder(&trop).map(|_| ()),
        Err(Erreur::MessageTropLong {
            obtenue: CORPS_MAX + 1
        })
    );
    assert_eq!(
        DemandeAutorisation::decoder(&trop).map(|_| ()),
        Err(Erreur::MessageTropLong {
            obtenue: CORPS_MAX + 1
        })
    );
}

#[test]
fn un_tampon_trop_petit_se_dit() {
    let lue = DeclarationMachine::decoder(br#"{"nom":"n","capacites":[]}"#).expect("elle se lit");
    let mut sortie = [0_u8; 4];
    assert_eq!(lue.encoder(&mut sortie), Err(Erreur::TamponTropPetit));

    let demande = DemandeAutorisation::decoder(
        format!(
            r#"{{"a":"{}","portee":"tout"}}"#,
            un(Genre::Utilisateur).texte()
        )
        .as_bytes(),
    )
    .expect("elle se lit");
    assert_eq!(demande.encoder(&mut sortie), Err(Erreur::TamponTropPetit));
}

// ── Modifier une machine ────────────────────────────────────────────────────

#[test]
fn une_modification_se_lit_et_se_reecrit_a_l_identique() {
    for octets in [
        &br#"{"nom":"grenier"}"#[..],
        &br#"{"capacites":["annonce"]}"#[..],
        // **LA LECTURE SEULE**, et non l'annonce : c'est le seul cas où le
        // tableau commence par son second membre, et où la virgule ne doit pas
        // s'écrire.
        &br#"{"capacites":["lecture"]}"#[..],
        &br#"{"capacites":[]}"#[..],
        &br#"{"nom":"grenier","capacites":["annonce","lecture"]}"#[..],
    ] {
        let lue = ModificationMachine::decoder(octets).expect("elle se lit");
        let mut tampon = [0_u8; 128];
        let ecrit = lue.encoder(&mut tampon).expect("elle se réécrit");
        assert_eq!(
            &tampon[..ecrit],
            octets,
            "{}",
            String::from_utf8_lossy(octets)
        );
    }
}

#[test]
fn ce_qui_est_absent_ne_change_pas() {
    // **ET LE TABLEAU VIDE, LUI, RETIRE.** `None` dit « laisse », `Some(rien)`
    // dit « aucune » : sans cette distinction, une machine ne pourrait jamais
    // perdre toutes ses capacités par ce verbe.
    let nom_seul = ModificationMachine::decoder(br#"{"nom":"grenier"}"#).expect("elle se lit");
    assert_eq!(nom_seul.nom, Some("grenier"));
    assert_eq!(nom_seul.capacites, None);

    let vides = ModificationMachine::decoder(br#"{"capacites":[]}"#).expect("elle se lit");
    assert_eq!(vides.nom, None);
    assert_eq!(vides.capacites, Some(Capacites::default()));
}

#[test]
fn une_modification_qui_ne_change_rien_est_refusee() {
    // **`{}` EST DU JSON VALIDE, ET IL EST REFUSÉ QUAND MÊME.** Personne ne
    // l'envoie exprès : ce qui le produit est un champ mal orthographié, ou une
    // variable vide. Rendre `200` laisserait l'humain chercher sa faute partout
    // sauf là où elle est.
    assert_eq!(
        ModificationMachine::decoder(b"{}").map(|_| ()),
        Err(Erreur::RienAChanger)
    );
    assert_eq!(
        ModificationMachine::decoder(b"{ }").map(|_| ()),
        Err(Erreur::RienAChanger)
    );
    // Une déclaration, elle, NOMME celui des deux champs qui manque : elle les
    // veut tous les deux, et le dire aide plus que « rien à changer ».
    assert_eq!(
        DeclarationMachine::decoder(b"{}").map(|_| ()),
        Err(Erreur::ChampManquant { nom: "nom" })
    );
}

#[test]
fn une_modification_refuse_tout_ce_qu_une_declaration_refuse() {
    // La boucle est PARTAGÉE, et cet essai est là pour que ça reste vrai : si
    // quelqu'un réécrivait l'une des deux, ces refus-là seraient les premiers à
    // se perdre.
    for octets in [
        &br#"{"nom":""}"#[..],
        &br#"{"nom":"n","nom":"m"}"#[..],
        &br#"{"couleur":"bleu"}"#[..],
        &br#"{"capacites":["administrer"]}"#[..],
        &br#"{"capacites":["annonce","annonce"]}"#[..],
        &br#"{"nom":"gre
ier"}"#[..],
        &br#"{"nom":"n" "capacites":[]}"#[..],
        &br#"{"nom":"n"}x"#[..],
        // Un objet vide SUIVI de quelque chose : la faute est ce qui suit, et
        // non l'absence de champ — le décodeur doit le dire dans cet ordre.
        &br#"{}x"#[..],
        &b""[..],
    ] {
        assert!(
            ModificationMachine::decoder(octets).is_err(),
            "{:?} devrait être refusé",
            String::from_utf8_lossy(octets)
        );
    }

    let trop = "a".repeat(NOM_MACHINE_MAX + 1);
    let corps = format!(r#"{{"nom":"{trop}"}}"#);
    assert_eq!(
        ModificationMachine::decoder(corps.as_bytes()).map(|_| ()),
        Err(Erreur::NomTropLong {
            obtenue: NOM_MACHINE_MAX + 1
        })
    );

    let long = vec![b'{'; CORPS_MAX + 1];
    assert_eq!(
        ModificationMachine::decoder(&long).map(|_| ()),
        Err(Erreur::MessageTropLong {
            obtenue: CORPS_MAX + 1
        })
    );
}

#[test]
fn une_modification_ne_tient_pas_dans_un_tampon_trop_court() {
    let lue = ModificationMachine::decoder(br#"{"nom":"grenier"}"#).expect("elle se lit");
    let mut tampon = [0_u8; 4];
    assert!(lue.encoder(&mut tampon).is_err());
}

// ── Accorder une autorisation ───────────────────────────────────────────────

#[test]
fn les_trois_portees_se_lisent_et_se_reecrivent() {
    let compte = un(Genre::Utilisateur);
    let machine = un(Genre::Machine);
    let service = un(Genre::Service);

    for (texte, attendue) in [
        ("tout".to_owned(), Portee::ToutLeCompte),
        (
            machine.texte().as_str().to_owned(),
            Portee::UneMachine(machine),
        ),
        (
            service.texte().as_str().to_owned(),
            Portee::UnService(service),
        ),
    ] {
        let corps = format!(r#"{{"a":"{}","portee":"{texte}"}}"#, compte.texte());
        let lue = DemandeAutorisation::decoder(corps.as_bytes()).expect("elle se lit");
        assert_eq!(lue.a, compte);
        assert_eq!(lue.portee, attendue, "{texte}");

        let mut sortie = [0_u8; CORPS_MAX];
        let combien = lue.encoder(&mut sortie).expect("elle se réécrit");
        assert_eq!(&sortie[..combien], corps.as_bytes(), "{texte}");
    }
}

#[test]
fn une_portee_qui_ne_delimite_rien_est_refusee() {
    // Un compte, un appareil, une autorisation, un annuaire : aucun de ceux-là
    // ne dit jusqu'où une autorisation porte.
    let compte = un(Genre::Utilisateur);
    for genre in [
        Genre::Utilisateur,
        Genre::Appareil,
        Genre::Autorisation,
        Genre::Annuaire,
    ] {
        let corps = format!(
            r#"{{"a":"{}","portee":"{}"}}"#,
            compte.texte(),
            un(genre).texte()
        );
        assert!(
            matches!(
                DemandeAutorisation::decoder(corps.as_bytes()),
                Err(Erreur::IdentifiantInvalide { .. })
            ),
            "{genre:?} ne délimite rien"
        );
    }
    // Ni un mot quelconque.
    let corps = format!(r#"{{"a":"{}","portee":"presque-tout"}}"#, compte.texte());
    assert!(matches!(
        DemandeAutorisation::decoder(corps.as_bytes()),
        Err(Erreur::IdentifiantInvalide { .. })
    ));
}

#[test]
fn un_beneficiaire_qui_n_est_pas_un_compte_est_refuse() {
    let corps = format!(
        r#"{{"a":"{}","portee":"tout"}}"#,
        un(Genre::Machine).texte()
    );
    assert!(matches!(
        DemandeAutorisation::decoder(corps.as_bytes()),
        Err(Erreur::IdentifiantInvalide { .. })
    ));
}

#[test]
fn une_demande_mal_formee_est_refusee() {
    let compte = un(Genre::Utilisateur);
    let juste = format!(r#"{{"a":"{}","portee":"tout"}}"#, compte.texte());

    assert_eq!(
        DemandeAutorisation::decoder(format!(r#"{{"a":"{}"}}"#, compte.texte()).as_bytes())
            .map(|_| ()),
        Err(Erreur::ChampManquant { nom: "portee" })
    );
    assert_eq!(
        DemandeAutorisation::decoder(br#"{"portee":"tout"}"#).map(|_| ()),
        Err(Erreur::ChampManquant { nom: "a" })
    );
    assert!(matches!(
        DemandeAutorisation::decoder(
            format!(r#"{{"a":"{}","a":"{}"}}"#, compte.texte(), compte.texte()).as_bytes()
        ),
        Err(Erreur::ChampEnDouble { .. })
    ));
    assert!(matches!(
        DemandeAutorisation::decoder(
            format!(r#"{{"a":"{}","quand":"demain"}}"#, compte.texte()).as_bytes()
        ),
        Err(Erreur::ChampInconnu { .. })
    ));
    assert!(DemandeAutorisation::decoder(format!("{juste} ").as_bytes()).is_ok());
    assert!(DemandeAutorisation::decoder(format!("{juste}x").as_bytes()).is_err());
    assert!(DemandeAutorisation::decoder(b"{").is_err());
    assert!(
        DemandeAutorisation::decoder(
            format!(r#"{{"a":"{}" "portee":"tout"}}"#, compte.texte()).as_bytes()
        )
        .is_err()
    );
    assert!(
        DemandeAutorisation::decoder(format!(r#"{{"a" "{}"}}"#, compte.texte()).as_bytes())
            .is_err()
    );
}

#[test]
fn une_chaine_libre_jamais_close_est_refusee() {
    // Le tampon se termine avant le guillemet fermant : il n'y a plus d'octet à
    // regarder, et ce n'est pas une chaîne.
    assert!(matches!(
        DeclarationMachine::decoder(br#"{"nom":"grenier"#),
        Err(Erreur::JsonAttendu { .. })
    ));
}

#[test]
fn chaque_faute_de_texte_libre_se_dit_a_un_humain() {
    // Les fautes se recopient dans un journal : elles doivent nommer ce qui
    // cloche et où.
    let mut corps = b"{\"nom\":\"".to_vec();
    corps.extend_from_slice(&[0xC3, 0x28]);
    corps.extend_from_slice(b"\",\"capacites\":[]}");
    let mal_encode = DeclarationMachine::decoder(&corps).expect_err("mal encodé");
    assert!(
        mal_encode.to_string().contains("mal encodé"),
        "{mal_encode}"
    );

    let invisible = DeclarationMachine::decoder(alloc_corps("gre\u{202E}nier").as_bytes())
        .expect_err("invisible");
    assert!(invisible.to_string().contains("invisible"), "{invisible}");
}

#[test]
fn une_cle_de_champ_qui_n_est_pas_une_chaine_est_refusee() {
    // JSON permet d'écrire `{1:2}` ; ce dialecte, non — une clé est une chaîne.
    assert!(matches!(
        DeclarationMachine::decoder(b"{1:2}"),
        Err(Erreur::JsonAttendu { .. })
    ));
    assert!(matches!(
        DemandeAutorisation::decoder(b"{1:2}"),
        Err(Erreur::JsonAttendu { .. })
    ));
}

#[test]
fn une_capacite_qui_n_est_pas_une_chaine_est_refusee() {
    assert!(matches!(
        DeclarationMachine::decoder(br#"{"nom":"n","capacites":[1]}"#),
        Err(Erreur::JsonAttendu { .. })
    ));
}

#[test]
fn une_demande_qui_ne_commence_pas_par_un_objet_est_refusee() {
    assert!(matches!(
        DemandeAutorisation::decoder(b"[]"),
        Err(Erreur::JsonAttendu { .. })
    ));
}

#[test]
fn une_valeur_d_autorisation_qui_n_est_pas_une_chaine_est_refusee() {
    assert!(matches!(
        DemandeAutorisation::decoder(br#"{"a":1}"#),
        Err(Erreur::JsonAttendu { .. })
    ));
}

#[test]
fn un_nom_qui_n_est_pas_une_chaine_est_refuse() {
    // C'est `texte_libre` qui refuse ici, et non le lecteur de chaînes : le
    // guillemet ouvrant manque.
    assert!(matches!(
        DeclarationMachine::decoder(br#"{"nom":42,"capacites":[]}"#),
        Err(Erreur::JsonAttendu { .. })
    ));
}

#[test]
fn une_machine_de_lecture_seule_se_reecrit_sans_virgule_orpheline() {
    let lue = DeclarationMachine::decoder(br#"{"nom":"n","capacites":["lecture"]}"#)
        .expect("elle se lit");
    let mut sortie = [0_u8; CORPS_MAX];
    let combien = lue.encoder(&mut sortie).expect("elle se réécrit");
    assert_eq!(
        &sortie[..combien],
        br#"{"nom":"n","capacites":["lecture"]}"#
    );
}

// ── Poser un alias ──────────────────────────────────────────────────────────

#[test]
fn un_alias_se_lit_et_se_reecrit_a_l_identique() {
    let octets = br#"{"alias":"thierry"}"#;
    let lue = DemandeAlias::decoder(octets).expect("il se lit");
    assert_eq!(lue.alias.as_str(), "thierry");

    let mut sortie = [0_u8; CORPS_MAX];
    let combien = lue.encoder(&mut sortie).expect("il se réécrit");
    assert_eq!(&sortie[..combien], &octets[..]);
}

#[test]
fn un_alias_reste_une_cle_et_refuse_ce_qu_un_nom_accepte() {
    // **LA DIFFÉRENCE AVEC LE NOM D'UNE MACHINE EST TOUT LE PROPOS.** Un alias
    // se CHERCHE : deux écritures d'une même valeur feraient croire à deux
    // comptes qu'ils la possèdent chacun. Le non-ASCII y est donc refusé, là où
    // un nom d'affichage l'accepte.
    for texte in [
        "Thérèse",
        "屋根裏",
        "THIERRY",
        "ab",
        "a".repeat(33).as_str(),
    ] {
        let corps = format!(r#"{{"alias":"{texte}"}}"#);
        assert!(
            DemandeAlias::decoder(corps.as_bytes()).is_err(),
            "{texte:?} devrait être refusé"
        );
    }
}

#[test]
fn un_alias_qui_ressemble_a_un_identifiant_est_refuse() {
    // Sinon `GET /v1/alias/{alias}` et `GET /v1/utilisateurs/{u}` se
    // confondraient à l'œil, et l'alias servirait à imiter un identifiant.
    let corps = format!(
        r#"{{"alias":"{}"}}"#,
        un(Genre::Utilisateur).texte().as_str().to_lowercase()
    );
    assert!(matches!(
        DemandeAlias::decoder(corps.as_bytes()),
        Err(Erreur::IdentifiantInvalide { .. })
    ));
}

#[test]
fn une_demande_d_alias_mal_formee_est_refusee() {
    for octets in [
        &b""[..],
        &b"["[..],
        &br#"{"alias":"thierry""#[..],
        &br#"{"alias":"thierry"}x"#[..],
        &br#"{"pseudo":"thierry"}"#[..],
        &br#"{"alias":1}"#[..],
        &br#"{"alias" "thierry"}"#[..],
        &br#"{"alias":"thierry","alias":"autre"}"#[..],
        &b"{1:2}"[..],
    ] {
        assert!(
            DemandeAlias::decoder(octets).is_err(),
            "{:?} devrait être refusé",
            String::from_utf8_lossy(octets)
        );
    }
    let trop = vec![b'{'; CORPS_MAX + 1];
    assert_eq!(
        DemandeAlias::decoder(&trop).map(|_| ()),
        Err(Erreur::MessageTropLong {
            obtenue: CORPS_MAX + 1
        })
    );
    let lue = DemandeAlias::decoder(br#"{"alias":"thierry"}"#).expect("il se lit");
    let mut sortie = [0_u8; 4];
    assert_eq!(lue.encoder(&mut sortie), Err(Erreur::TamponTropPetit));
}

// ── Ce qu'une autorisation rend ─────────────────────────────────────────────

use asl_api::corps::AutorisationRendue;

/// Encode, et rend les octets.
fn encoder_rendue(quoi: &AutorisationRendue) -> Vec<u8> {
    let mut sortie = vec![0_u8; CORPS_MAX];
    let combien = quoi.encoder(&mut sortie).expect("elle s'encode");
    sortie.truncate(combien);
    sortie
}

fn une_rendue(portee: Portee, revoquee: bool) -> AutorisationRendue {
    AutorisationRendue {
        autorisation: Identifiant::depuis_entropie(Genre::Autorisation, [0x11; 16]),
        par: Identifiant::depuis_entropie(Genre::Utilisateur, [0x22; 16]),
        a: Identifiant::depuis_entropie(Genre::Utilisateur, [0x33; 16]),
        portee,
        revoquee,
    }
}

#[test]
fn une_autorisation_rendue_fait_l_aller_et_le_retour() {
    // **L'ENCODEUR A UN DÉCODEUR, ET C'EST POUR CELA.** Un encodeur seul ne se
    // vérifie que par comparaison de chaînes, et une comparaison de chaînes ne
    // dit pas qu'un lecteur saura relire.
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x44; 16]);
    let service = Identifiant::depuis_entropie(Genre::Service, [0x55; 16]);

    for portee in [
        Portee::ToutLeCompte,
        Portee::UneMachine(machine),
        Portee::UnService(service),
    ] {
        for revoquee in [false, true] {
            let avant = une_rendue(portee, revoquee);
            let octets = encoder_rendue(&avant);
            let apres = AutorisationRendue::decoder(&octets).expect("elle se relit");
            assert_eq!(apres, avant, "{portee:?} révoquée={revoquee}");
        }
    }
}

#[test]
fn elle_porte_son_propre_identifiant() {
    // **C'EST LUI QU'ON PASSE À `DELETE /v1/autorisations/{g}`.** Une liste dont
    // les éléments ne se désignent pas est une liste qu'on ne peut que regarder.
    let rendue = une_rendue(Portee::ToutLeCompte, false);
    let octets = encoder_rendue(&rendue);
    let texte = core::str::from_utf8(&octets).expect("de l'ASCII");
    assert!(
        texte.contains(rendue.autorisation.texte().as_str()),
        "{texte}"
    );
    assert!(texte.starts_with(r#"{"autorisation":"#), "{texte}");
}

#[test]
fn une_revocation_se_lit_dans_la_liste() {
    // **L'ÉCRAN QU'ON REGARDE APRÈS AVOIR RETIRÉ UN ACCÈS DOIT MONTRER CE QU'ON
    // A RETIRÉ.** Taire les révoquées ferait douter d'avoir cliqué.
    let vive = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
    let morte = encoder_rendue(&une_rendue(Portee::ToutLeCompte, true));
    assert!(
        core::str::from_utf8(&vive)
            .unwrap()
            .contains(r#""revoquee":false"#)
    );
    assert!(
        core::str::from_utf8(&morte)
            .unwrap()
            .contains(r#""revoquee":true"#)
    );
    assert_ne!(vive, morte);
}

#[test]
fn les_deux_sens_se_distinguent_par_par_et_a() {
    // `protocole.md` §2.2 : « les deux sens ». Deux tableaux séparés auraient
    // obligé l'application à savoir dans lequel chercher.
    let rendue = une_rendue(Portee::ToutLeCompte, false);
    let relue = AutorisationRendue::decoder(&encoder_rendue(&rendue)).unwrap();
    assert_ne!(relue.par, relue.a, "un compte ne s'autorise pas lui-même");
}

#[test]
fn un_genre_qui_ne_convient_pas_est_refuse() {
    // Un appareil n'accorde rien, et une machine ne bénéficie de rien : ce sont
    // des COMPTES qui s'autorisent.
    let bon = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
    let texte = core::str::from_utf8(&bon).unwrap();
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x66; 16]);

    let faux = texte.replacen(
        &format!(
            r#""par":"{}""#,
            une_rendue(Portee::ToutLeCompte, false).par.texte().as_str()
        ),
        &format!(r#""par":"{}""#, machine.texte().as_str()),
        1,
    );
    assert!(matches!(
        AutorisationRendue::decoder(faux.as_bytes()),
        Err(Erreur::IdentifiantInvalide { .. })
    ));
}

#[test]
fn un_champ_manquant_est_nomme() {
    for (retire, nom) in [
        (r#""revoquee":false"#, "revoquee"),
        (r#""portee":"tout""#, "portee"),
    ] {
        let bon = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
        let texte = core::str::from_utf8(&bon).unwrap();
        let ampute = texte.replacen(&format!(",{retire}"), "", 1);
        assert_eq!(
            AutorisationRendue::decoder(ampute.as_bytes()),
            Err(Erreur::ChampManquant { nom }),
            "{ampute}"
        );
    }
}

#[test]
fn un_champ_en_double_est_refuse_quel_qu_il_soit() {
    // **ET NON UN DERNIER-GAGNE** : deux lecteurs qui choisiraient différemment
    // liraient deux messages dans un seul. La règle vaut pour LES CINQ champs,
    // et l'éprouver sur un seul laisserait quatre refus que personne n'a lus.
    let modele = une_rendue(Portee::ToutLeCompte, false);
    let bon = encoder_rendue(&modele);
    let texte = core::str::from_utf8(&bon).unwrap().to_owned();

    let morceaux = [
        format!(
            r#""autorisation":"{}""#,
            modele.autorisation.texte().as_str()
        ),
        format!(r#""par":"{}""#, modele.par.texte().as_str()),
        format!(r#""a":"{}""#, modele.a.texte().as_str()),
        r#""portee":"tout""#.to_owned(),
        r#""revoquee":false"#.to_owned(),
    ];

    for morceau in morceaux {
        let double = texte.replacen(&morceau, &format!("{morceau},{morceau}"), 1);
        assert!(
            matches!(
                AutorisationRendue::decoder(double.as_bytes()),
                Err(Erreur::ChampEnDouble { .. })
            ),
            "{double}"
        );
    }
}

#[test]
fn ce_qui_n_est_ni_true_ni_false_est_refuse() {
    let bon = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
    let texte = core::str::from_utf8(&bon).unwrap();
    for quoi in [
        r#""revoquee":1"#,
        r#""revoquee":"false""#,
        r#""revoquee":null"#,
    ] {
        let faux = texte.replacen(r#""revoquee":false"#, quoi, 1);
        assert!(
            AutorisationRendue::decoder(faux.as_bytes()).is_err(),
            "{faux}"
        );
    }
}

#[test]
fn un_champ_inconnu_est_refuse() {
    let bon = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
    let texte = core::str::from_utf8(&bon).unwrap();
    let ajoute = texte.replacen(
        r#""revoquee":false"#,
        r#""etiquette":"x","revoquee":false"#,
        1,
    );
    assert!(matches!(
        AutorisationRendue::decoder(ajoute.as_bytes()),
        Err(Erreur::ChampInconnu { .. })
    ));
}

#[test]
fn ce_qui_n_est_pas_un_objet_est_refuse() {
    for brut in [b"".as_slice(), b"[]", b"{", br#"{"autorisation":}"#] {
        assert!(AutorisationRendue::decoder(brut).is_err(), "{brut:?}");
    }
}

#[test]
fn ce_qui_suit_l_objet_est_refuse() {
    let bon = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
    let mut trop = bon.clone();
    trop.extend_from_slice(b" et la suite");
    assert!(AutorisationRendue::decoder(&trop).is_err());
}

#[test]
fn un_tampon_trop_petit_se_dit_pour_une_autorisation_rendue() {
    let mut sortie = [0_u8; 8];
    assert_eq!(
        une_rendue(Portee::ToutLeCompte, false).encoder(&mut sortie),
        Err(Erreur::TamponTropPetit)
    );
}

#[test]
fn chaque_champ_exige_son_genre_et_sa_forme() {
    // **CHAQUE `?` DE CE DÉCODEUR EST UN REFUS QUE QUELQU'UN DÉCLENCHERA.** Les
    // laisser inatteints reviendrait à croire éprouvé ce que personne n'a lu.
    let bon = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
    let texte = core::str::from_utf8(&bon).unwrap().to_owned();
    let modele = une_rendue(Portee::ToutLeCompte, false);
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x66; 16]);

    // Un genre qui ne convient pas, champ par champ.
    for (champ, attendu) in [
        ("autorisation", modele.autorisation),
        ("par", modele.par),
        ("a", modele.a),
    ] {
        let faux = texte.replacen(
            &format!(r#""{champ}":"{}""#, attendu.texte().as_str()),
            &format!(r#""{champ}":"{}""#, machine.texte().as_str()),
            1,
        );
        assert!(
            matches!(
                AutorisationRendue::decoder(faux.as_bytes()),
                Err(Erreur::IdentifiantInvalide { .. })
            ),
            "{champ} : {faux}"
        );
    }

    // Chaque champ, retiré, se nomme.
    for (champ, morceau) in [
        (
            "autorisation",
            format!(
                r#""autorisation":"{}","#,
                modele.autorisation.texte().as_str()
            ),
        ),
        (
            "par",
            format!(r#""par":"{}","#, modele.par.texte().as_str()),
        ),
        ("a", format!(r#""a":"{}","#, modele.a.texte().as_str())),
    ] {
        let ampute = texte.replacen(&morceau, "", 1);
        assert_eq!(
            AutorisationRendue::decoder(ampute.as_bytes()),
            Err(Erreur::ChampManquant { nom: champ }),
            "{ampute}"
        );
    }
}

#[test]
fn une_ponctuation_manquante_est_refusee() {
    let bon = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
    let texte = core::str::from_utf8(&bon).unwrap().to_owned();

    // Les deux-points après une clé.
    let sans = texte.replacen(r#""revoquee":"#, r#""revoquee""#, 1);
    assert!(
        AutorisationRendue::decoder(sans.as_bytes()).is_err(),
        "{sans}"
    );

    // L'accolade fermante.
    let ouvert = texte.trim_end_matches('}').to_owned();
    assert!(
        AutorisationRendue::decoder(ouvert.as_bytes()).is_err(),
        "{ouvert}"
    );
}

#[test]
fn une_portee_illisible_est_refusee() {
    let bon = encoder_rendue(&une_rendue(Portee::ToutLeCompte, false));
    let texte = core::str::from_utf8(&bon).unwrap().to_owned();

    // Pas une chaîne.
    let nombre = texte.replacen(r#""portee":"tout""#, r#""portee":7"#, 1);
    assert!(
        AutorisationRendue::decoder(nombre.as_bytes()).is_err(),
        "{nombre}"
    );

    // Un genre qui ne délimite rien : un compte n'est pas une portée.
    let compte = Identifiant::depuis_entropie(Genre::Utilisateur, [0x77; 16]);
    let faux = texte.replacen(
        r#""portee":"tout""#,
        &format!(r#""portee":"{}""#, compte.texte().as_str()),
        1,
    );
    assert!(
        matches!(
            AutorisationRendue::decoder(faux.as_bytes()),
            Err(Erreur::IdentifiantInvalide { .. })
        ),
        "{faux}"
    );
}

// ── Déposer un jeton de poussée ─────────────────────────────────────────────

#[test]
fn un_depot_se_lit_et_se_reecrit_a_l_identique() {
    for octets in [
        &br#"{"plateforme":"apns","jeton":"c0ffee"}"#[..],
        &br#"{"plateforme":"fcm","jeton":"e:Z-_9"}"#[..],
    ] {
        let lu = DepotJeton::decoder(octets).expect("il se lit");
        let mut tampon = [0_u8; 128];
        let ecrit = lu.encoder(&mut tampon).expect("il se réécrit");
        assert_eq!(
            &tampon[..ecrit],
            octets,
            "{}",
            String::from_utf8_lossy(octets)
        );
    }
}

#[test]
fn l_ordre_des_champs_ne_compte_pas() {
    let lu = DepotJeton::decoder(br#"{"jeton":"c0ffee","plateforme":"fcm"}"#).expect("il se lit");
    assert_eq!(lu.plateforme, Plateforme::Fcm);
    assert_eq!(lu.jeton, "c0ffee");
}

#[test]
fn les_deux_plateformes_et_elles_seules() {
    // **LA LISTE EST FERMÉE.** Un jeton ne veut rien dire hors du service qui
    // l'a émis, et l'annuaire doit savoir à qui le présenter.
    assert_eq!(Plateforme::depuis_le_mot("apns"), Some(Plateforme::Apns));
    assert_eq!(Plateforme::depuis_le_mot("fcm"), Some(Plateforme::Fcm));
    for mot in ["APNS", "windows", "", "apns "] {
        assert_eq!(Plateforme::depuis_le_mot(mot), None, "{mot}");
    }
    for plateforme in [Plateforme::Apns, Plateforme::Fcm] {
        assert_eq!(
            Plateforme::depuis_le_mot(plateforme.mot()),
            Some(plateforme)
        );
    }
    assert!(matches!(
        DepotJeton::decoder(br#"{"plateforme":"windows","jeton":"x"}"#),
        Err(Erreur::ChampInconnu { .. })
    ));
}

#[test]
fn un_jeton_vide_ou_trop_long_est_refuse() {
    // **UN JETON VIDE N'EST PAS UN RETRAIT DÉGUISÉ.** C'est un champ qu'on a
    // oublié de remplir, et le prendre pour un dépôt ferait présenter la chaîne
    // vide à Apple.
    assert_eq!(
        DepotJeton::decoder(br#"{"plateforme":"apns","jeton":""}"#).map(|_| ()),
        Err(Erreur::NomVide)
    );

    let juste = "a".repeat(JETON_MAX);
    let corps = format!(r#"{{"plateforme":"apns","jeton":"{juste}"}}"#);
    assert!(
        DepotJeton::decoder(corps.as_bytes()).is_ok(),
        "la borne passe"
    );

    let trop = "a".repeat(JETON_MAX + 1);
    let corps = format!(r#"{{"plateforme":"apns","jeton":"{trop}"}}"#);
    assert_eq!(
        DepotJeton::decoder(corps.as_bytes()).map(|_| ()),
        Err(Erreur::NomTropLong {
            obtenue: JETON_MAX + 1
        })
    );
}

#[test]
fn un_depot_incomplet_inconnu_ou_double_est_refuse() {
    assert_eq!(
        DepotJeton::decoder(br#"{"jeton":"c0ffee"}"#).map(|_| ()),
        Err(Erreur::ChampManquant { nom: "plateforme" })
    );
    assert_eq!(
        DepotJeton::decoder(br#"{"plateforme":"apns"}"#).map(|_| ()),
        Err(Erreur::ChampManquant { nom: "jeton" })
    );
    assert!(matches!(
        DepotJeton::decoder(br#"{"plateforme":"apns","couleur":"bleu","jeton":"x"}"#),
        Err(Erreur::ChampInconnu { .. })
    ));
    assert!(matches!(
        DepotJeton::decoder(br#"{"plateforme":"apns","plateforme":"fcm","jeton":"x"}"#),
        Err(Erreur::ChampEnDouble { .. })
    ));
}

#[test]
fn un_depot_mal_cadre_est_refuse() {
    for octets in [
        &b""[..],
        &b"["[..],
        &br#"{}"#[..],
        &br#"{"plateforme" "apns","jeton":"x"}"#[..],
        &br#"{"plateforme":"apns" "jeton":"x"}"#[..],
        &br#"{"plateforme":"apns","jeton":"x""#[..],
        &br#"{"plateforme":"apns","jeton":"x"}y"#[..],
        // **UN JETON N'EST PAS UN NOMBRE**, et le lecteur de chaînes le dit.
        &br#"{"plateforme":"apns","jeton":42}"#[..],
        // Un échappement est refusé : aucune valeur de ce protocole n'en emploie.
        &br#"{"plateforme":"apns","jeton":"a\nb"}"#[..],
    ] {
        assert!(
            DepotJeton::decoder(octets).is_err(),
            "{:?} devrait être refusé",
            String::from_utf8_lossy(octets)
        );
    }

    let trop = vec![b'{'; CORPS_MAX + 1];
    assert_eq!(
        DepotJeton::decoder(&trop).map(|_| ()),
        Err(Erreur::MessageTropLong {
            obtenue: CORPS_MAX + 1
        })
    );
}

#[test]
fn un_depot_ne_tient_pas_dans_un_tampon_trop_court() {
    let lu = DepotJeton::decoder(br#"{"plateforme":"apns","jeton":"c0ffee"}"#).expect("il se lit");
    let mut tampon = [0_u8; 8];
    assert!(lu.encoder(&mut tampon).is_err());
}

// ── Créer un compte, avec preuve et attestation ─────────────────────────────

mod compte {
    use asl_api::corps::{
        ATTESTATION_MAX, CLE_APPAREIL_OCTETS, COMPTE_CORPS_MAX, COMPTE_PREFIXE_OCTETS,
        CreationDeCompte, PREUVE_APPAREIL_OCTETS, PlateformeAttestation,
    };
    use asl_proto::Erreur;

    /// Un corps : plate-forme, clé, preuve, puis l'attestation.
    fn corps(plateforme: u8, attestation: &[u8]) -> Vec<u8> {
        let mut octets = vec![plateforme];
        octets.extend_from_slice(&[0xC1; CLE_APPAREIL_OCTETS]);
        octets.extend_from_slice(&[0x52; PREUVE_APPAREIL_OCTETS]);
        octets.extend_from_slice(attestation);
        octets
    }

    #[test]
    fn un_corps_avec_attestation_se_lit_et_isole_ses_tranches() {
        let octets = corps(1, &[0xA5, 0x01, 0x02]);
        let lu = CreationDeCompte::decoder(&octets).expect("il se lit");
        assert_eq!(lu.plateforme, PlateformeAttestation::Apple);
        assert_eq!(lu.cle, &[0xC1; CLE_APPAREIL_OCTETS]);
        assert_eq!(lu.preuve, &[0x52; PREUVE_APPAREIL_OCTETS]);
        assert_eq!(lu.attestation, &[0xA5, 0x01, 0x02]);
    }

    #[test]
    fn les_trois_plateformes_se_lisent() {
        assert_eq!(
            CreationDeCompte::decoder(&corps(0, &[]))
                .unwrap()
                .plateforme,
            PlateformeAttestation::Aucune
        );
        assert_eq!(
            CreationDeCompte::decoder(&corps(1, &[9]))
                .unwrap()
                .plateforme,
            PlateformeAttestation::Apple
        );
        assert_eq!(
            CreationDeCompte::decoder(&corps(2, &[9]))
                .unwrap()
                .plateforme,
            PlateformeAttestation::Google
        );
    }

    #[test]
    fn le_codec_fait_l_aller_retour() {
        for (plateforme, attestation) in [
            (PlateformeAttestation::Aucune, &[][..]),
            (PlateformeAttestation::Apple, &[0xA5, 1, 2, 3][..]),
            (PlateformeAttestation::Google, &[0xFF; 500][..]),
        ] {
            let objet = CreationDeCompte {
                plateforme,
                cle: &[0x07; CLE_APPAREIL_OCTETS],
                preuve: &[0x08; PREUVE_APPAREIL_OCTETS],
                attestation,
            };
            let mut tampon = [0_u8; COMPTE_CORPS_MAX];
            let n = objet.encoder(&mut tampon).expect("il s'écrit");
            assert_eq!(CreationDeCompte::decoder(&tampon[..n]), Ok(objet));
        }
    }

    #[test]
    fn un_corps_plus_court_que_le_prefixe_est_refuse() {
        let court = corps(0, &[]);
        assert_eq!(court.len(), COMPTE_PREFIXE_OCTETS);
        assert_eq!(
            CreationDeCompte::decoder(&court[..COMPTE_PREFIXE_OCTETS - 1]),
            Err(Erreur::CorpsTropCourt {
                obtenue: COMPTE_PREFIXE_OCTETS - 1,
                attendue: COMPTE_PREFIXE_OCTETS
            })
        );
        assert_eq!(
            CreationDeCompte::decoder(&[]),
            Err(Erreur::CorpsTropCourt {
                obtenue: 0,
                attendue: COMPTE_PREFIXE_OCTETS
            })
        );
    }

    #[test]
    fn un_corps_juste_au_prefixe_est_un_compte_sans_attestation() {
        // Exactement le préfixe, plate-forme 0 : c'est un corps valide, et
        // l'attestation est vide.
        let octets = corps(0, &[]);
        let lu = CreationDeCompte::decoder(&octets).expect("valide");
        assert!(lu.attestation.is_empty());
        assert_eq!(lu.plateforme, PlateformeAttestation::Aucune);
    }

    #[test]
    fn un_corps_trop_long_est_refuse_sans_etre_lu() {
        let trop = corps(1, &vec![0xEE; ATTESTATION_MAX + 1]);
        assert_eq!(trop.len(), COMPTE_CORPS_MAX + 1);
        assert_eq!(
            CreationDeCompte::decoder(&trop),
            Err(Erreur::CorpsTropLong {
                obtenue: COMPTE_CORPS_MAX + 1,
                maximum: COMPTE_CORPS_MAX
            })
        );
        // Juste à la borne, il passe.
        let borne = corps(1, &vec![0xEE; ATTESTATION_MAX]);
        assert!(CreationDeCompte::decoder(&borne).is_ok());
    }

    #[test]
    fn une_plateforme_inconnue_est_refusee() {
        for octet in [3_u8, 4, 200, 255] {
            assert_eq!(
                CreationDeCompte::decoder(&corps(octet, &[9])),
                Err(Erreur::PlateformeInconnue { octet })
            );
        }
    }

    #[test]
    fn une_attestation_derriere_aucune_est_refusee() {
        // La place exacte où l'on glisse des octets que personne ne lit.
        assert_eq!(
            CreationDeCompte::decoder(&corps(0, &[0x01])),
            Err(Erreur::AttestationInattendue { obtenue: 1 })
        );
        assert_eq!(
            CreationDeCompte::decoder(&corps(0, &[0xAA; 42])),
            Err(Erreur::AttestationInattendue { obtenue: 42 })
        );
    }

    #[test]
    fn une_plateforme_declaree_sans_attestation_est_refusee() {
        assert_eq!(
            CreationDeCompte::decoder(&corps(1, &[])),
            Err(Erreur::AttestationManquante)
        );
        assert_eq!(
            CreationDeCompte::decoder(&corps(2, &[])),
            Err(Erreur::AttestationManquante)
        );
    }

    #[test]
    fn l_encodeur_refuse_ce_que_le_decodeur_refuserait() {
        // Une clé de mauvaise taille.
        let mauvais = CreationDeCompte {
            plateforme: PlateformeAttestation::Aucune,
            cle: &[0; CLE_APPAREIL_OCTETS - 1],
            preuve: &[0; PREUVE_APPAREIL_OCTETS],
            attestation: &[],
        };
        let mut tampon = [0_u8; COMPTE_CORPS_MAX];
        assert!(matches!(
            mauvais.encoder(&mut tampon),
            Err(Erreur::CorpsTropCourt { .. })
        ));
        // Aucune, mais une attestation quand même.
        let incoherent = CreationDeCompte {
            plateforme: PlateformeAttestation::Aucune,
            cle: &[0; CLE_APPAREIL_OCTETS],
            preuve: &[0; PREUVE_APPAREIL_OCTETS],
            attestation: &[1],
        };
        assert!(matches!(
            incoherent.encoder(&mut tampon),
            Err(Erreur::AttestationInattendue { obtenue: 1 })
        ));
        // Apple, mais rien.
        let vide = CreationDeCompte {
            plateforme: PlateformeAttestation::Apple,
            cle: &[0; CLE_APPAREIL_OCTETS],
            preuve: &[0; PREUVE_APPAREIL_OCTETS],
            attestation: &[],
        };
        assert_eq!(vide.encoder(&mut tampon), Err(Erreur::AttestationManquante));
    }

    #[test]
    fn l_encodeur_refuse_une_attestation_demesuree() {
        // Un objet construit à la main peut porter une attestation plus grande
        // que ce que le fil admet : l'encodeur la refuse avant d'écrire, même
        // dans un tampon assez grand.
        let enorme = vec![0xEE; ATTESTATION_MAX + 1];
        let objet = CreationDeCompte {
            plateforme: PlateformeAttestation::Apple,
            cle: &[0x07; CLE_APPAREIL_OCTETS],
            preuve: &[0x08; PREUVE_APPAREIL_OCTETS],
            attestation: &enorme,
        };
        let mut tampon = vec![0_u8; COMPTE_CORPS_MAX + 64];
        assert_eq!(
            objet.encoder(&mut tampon),
            Err(Erreur::CorpsTropLong {
                obtenue: COMPTE_CORPS_MAX + 1,
                maximum: COMPTE_CORPS_MAX
            })
        );
    }

    #[test]
    fn l_encodeur_refuse_un_tampon_trop_petit() {
        let objet = CreationDeCompte {
            plateforme: PlateformeAttestation::Apple,
            cle: &[0x07; CLE_APPAREIL_OCTETS],
            preuve: &[0x08; PREUVE_APPAREIL_OCTETS],
            attestation: &[0xA5, 1, 2],
        };
        let mut minuscule = [0_u8; 10];
        assert_eq!(objet.encoder(&mut minuscule), Err(Erreur::TamponTropPetit));
    }

    #[test]
    fn chaque_faute_a_sa_phrase() {
        let fautes = [
            Erreur::CorpsTropCourt {
                obtenue: 5,
                attendue: 98,
            },
            Erreur::CorpsTropLong {
                obtenue: 9000,
                maximum: COMPTE_CORPS_MAX,
            },
            Erreur::PlateformeInconnue { octet: 7 },
            Erreur::AttestationInattendue { obtenue: 3 },
            Erreur::AttestationManquante,
        ];
        for faute in fautes {
            assert!(!faute.to_string().is_empty());
        }
    }
}
