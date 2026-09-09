//! Les corps de l'API mobile : ce qu'ils acceptent, et ce qu'ils refusent.

use asl_api::corps::{
    CORPS_MAX, Capacites, DeclarationMachine, DemandeAutorisation, NOM_MACHINE_MAX, Portee,
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
