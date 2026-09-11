//! Ce que l'objet d'attestation porte, et ce qui l'empêche d'être un objet.

mod forge;

use asl_attest::{
    AAGUID_OCTETS, AUTH_MINIMUM, Champ, DRAPEAU_ATTESTE, DRAPEAU_EXTENSIONS, DRAPEAU_PRESENCE,
    DRAPEAU_VERIFIE, EMPREINTE_OCTETS, Erreur, FORMAT, Lecteur, ObjetAttestation, X5C_MAX,
};
use forge::{Attestation, carte, donnees_auth, entier, octets, suite, tableau, texte};

#[test]
fn un_objet_complet_se_lit_entierement() {
    let brut = Attestation::default().ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("un objet bien formé");

    assert_eq!(objet.chaine().len(), 2);
    assert_eq!(objet.chaine()[0], &[0xaa; 4]);
    assert_eq!(objet.chaine()[1], &[0xbb; 4]);
    assert_eq!(objet.recu, Some(&[0xcc; 3][..]));
    assert_eq!(objet.auth.empreinte_app, &[0x11; EMPREINTE_OCTETS]);
    assert_eq!(objet.auth.compteur, 0);
    assert!(objet.auth.atteste());

    let cle = objet.auth.cle.expect("le drapeau la promet");
    assert_eq!(cle.aaguid, &[0x22; AAGUID_OCTETS]);
    assert_eq!(cle.identifiant, &[0x33; 32]);
    assert_eq!(cle.cle_cose, &[0xa5]);
}

#[test]
fn les_octets_bruts_d_auth_data_sont_gardes_tels_quels() {
    // LE NONCE SE CALCULE DESSUS. S'ils étaient reconstruits depuis la
    // structure, ce seraient d'autres octets, et donc un autre nonce.
    let attestation = Attestation::default();
    let attendus = attestation.auth.clone().expect("des données");
    let brut = attestation.ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("un objet bien formé");
    assert_eq!(objet.donnees_auth, attendus.as_slice());
}

#[test]
fn un_champ_inconnu_de_la_carte_du_dessus_est_sauté() {
    let attestation = Attestation {
        en_plus: vec![suite(&[
            texte("inattendu"),
            carte(1),
            texte("a"),
            entier(1),
        ])],
        ..Attestation::default()
    };
    let brut = attestation.ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("un champ de plus ne gêne pas");
    assert_eq!(objet.chaine().len(), 2);
}

#[test]
fn un_champ_inconnu_de_la_declaration_est_saute() {
    // Écrit à la main : la carte `attStmt` porte trois couples, dont un
    // qu'aucune version de ce lecteur ne connaît.
    let auth = donnees_auth(&[0x11; 32], 0, 0, None);
    let brut = suite(&[
        carte(3),
        texte("fmt"),
        texte(FORMAT),
        texte("attStmt"),
        carte(2),
        texte("plus tard"),
        entier(7),
        texte("x5c"),
        tableau(1),
        octets(&[0xaa]),
        texte("authData"),
        octets(&auth),
    ]);
    let objet = ObjetAttestation::lire(&brut).expect("un champ de plus ne gêne pas");
    assert_eq!(objet.chaine().len(), 1);
    assert_eq!(objet.recu, None);
}

#[test]
fn chacun_des_trois_champs_du_dessus_manque_par_son_nom() {
    let sans_format = Attestation {
        format: None,
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&sans_format.ecrire()),
        Err(Erreur::ChampManquant {
            champ: Champ::Format
        })
    );

    let sans_auth = Attestation {
        auth: None,
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&sans_auth.ecrire()),
        Err(Erreur::ChampManquant {
            champ: Champ::DonneesAuth
        })
    );

    let sans_chaine = Attestation {
        chaine: None,
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&sans_chaine.ecrire()),
        Err(Erreur::ChampManquant {
            champ: Champ::Chaine
        })
    );
}

#[test]
fn une_declaration_absente_manque_par_son_nom() {
    let auth = donnees_auth(&[0x11; 32], 0, 0, None);
    let brut = suite(&[
        carte(2),
        texte("fmt"),
        texte(FORMAT),
        texte("authData"),
        octets(&auth),
    ]);
    assert_eq!(
        ObjetAttestation::lire(&brut),
        Err(Erreur::ChampManquant {
            champ: Champ::Declaration
        })
    );
}

#[test]
fn un_champ_en_double_est_refuse_et_non_le_dernier_pris() {
    // DEUX `authData` : celui que ce lecteur prendrait, et celui qu'un autre
    // prendrait. Les départager serait déjà avoir perdu.
    let second = donnees_auth(&[0x99; 32], 0, 0, None);
    let attestation = Attestation {
        en_plus: vec![suite(&[texte("authData"), octets(&second)])],
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&attestation.ecrire()),
        Err(Erreur::ChampEnDouble {
            champ: Champ::DonneesAuth
        })
    );

    let attestation = Attestation {
        en_plus: vec![suite(&[texte("fmt"), texte(FORMAT)])],
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&attestation.ecrire()),
        Err(Erreur::ChampEnDouble {
            champ: Champ::Format
        })
    );

    let attestation = Attestation {
        en_plus: vec![suite(&[
            texte("attStmt"),
            carte(1),
            texte("x5c"),
            tableau(0),
        ])],
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&attestation.ecrire()),
        Err(Erreur::ChampEnDouble {
            champ: Champ::Declaration
        })
    );
}

#[test]
fn un_champ_de_la_declaration_en_double_est_refuse() {
    let brut = suite(&[
        carte(2),
        texte("fmt"),
        texte(FORMAT),
        texte("attStmt"),
        carte(2),
        texte("x5c"),
        tableau(0),
        texte("x5c"),
        tableau(0),
    ]);
    assert_eq!(
        ObjetAttestation::lire(&brut),
        Err(Erreur::ChampEnDouble {
            champ: Champ::Chaine
        })
    );

    let brut = suite(&[
        carte(1),
        texte("attStmt"),
        carte(2),
        texte("receipt"),
        octets(&[1]),
        texte("receipt"),
        octets(&[2]),
    ]);
    assert_eq!(
        ObjetAttestation::lire(&brut),
        Err(Erreur::ChampEnDouble { champ: Champ::Recu })
    );
}

#[test]
fn un_autre_format_est_refuse() {
    let attestation = Attestation {
        format: Some("android-key".to_owned()),
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&attestation.ecrire()),
        Err(Erreur::FormatInconnu)
    );
}

#[test]
fn une_chaine_trop_longue_est_refusee() {
    let attestation = Attestation {
        chaine: Some(vec![vec![0x01]; X5C_MAX + 1]),
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&attestation.ecrire()),
        Err(Erreur::TropDeCertificats {
            annonces: X5C_MAX + 1
        })
    );
}

#[test]
fn une_chaine_juste_a_la_borne_passe() {
    let attestation = Attestation {
        chaine: Some(vec![vec![0x01]; X5C_MAX]),
        ..Attestation::default()
    };
    let brut = attestation.ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("la borne est incluse");
    assert_eq!(objet.chaine().len(), X5C_MAX);
}

#[test]
fn une_chaine_vide_se_lit_et_ne_prouve_rien() {
    // C'est à la VÉRIFICATION de dire qu'une chaîne vide ne mène nulle part ;
    // la grammaire, elle, n'a rien à y redire.
    let attestation = Attestation {
        chaine: Some(Vec::new()),
        ..Attestation::default()
    };
    let brut = attestation.ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("vide, mais bien formée");
    assert!(objet.chaine().is_empty());
}

#[test]
fn des_donnees_auth_sans_le_drapeau_n_ont_pas_de_cle() {
    let attestation = Attestation {
        auth: Some(donnees_auth(&[0x11; 32], 0, 7, None)),
        ..Attestation::default()
    };
    let brut = attestation.ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("bien formées");
    assert_eq!(objet.auth.cle, None);
    assert_eq!(objet.auth.compteur, 7);
    assert!(!objet.auth.atteste());
}

#[test]
fn les_quatre_drapeaux_se_lisent() {
    let tous = DRAPEAU_PRESENCE | DRAPEAU_VERIFIE | DRAPEAU_EXTENSIONS;
    let attestation = Attestation {
        auth: Some(donnees_auth(&[0x11; 32], tous, 0, None)),
        ..Attestation::default()
    };
    let brut = attestation.ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("bien formées");
    assert!(objet.auth.presence());
    assert!(objet.auth.verifie());
    assert!(objet.auth.extensions());
    assert!(!objet.auth.atteste());
}

#[test]
fn des_donnees_auth_trop_courtes_sont_refusees_a_chaque_borne() {
    // On coupe une à une : l'empreinte, les drapeaux, le compteur, l'aaguid,
    // la longueur, l'identifiant. Chaque borne doit mordre.
    let complet = donnees_auth(
        &[0x11; 32],
        DRAPEAU_ATTESTE,
        0,
        Some((&[0x22; 16], &[0x33; 32], &[0xa5])),
    );
    let bornes = [
        0,
        EMPREINTE_OCTETS - 1,
        EMPREINTE_OCTETS,
        AUTH_MINIMUM - 1,
        AUTH_MINIMUM,
        AUTH_MINIMUM + AAGUID_OCTETS - 1,
        AUTH_MINIMUM + AAGUID_OCTETS,
        AUTH_MINIMUM + AAGUID_OCTETS + 1,
        AUTH_MINIMUM + AAGUID_OCTETS + 2,
        complet.len() - 2,
    ];
    for borne in bornes {
        let attestation = Attestation {
            auth: Some(complet[..borne].to_vec()),
            ..Attestation::default()
        };
        assert_eq!(
            ObjetAttestation::lire(&attestation.ecrire()),
            Err(Erreur::AuthDataTronque { octets: borne }),
            "coupé à {borne} octets"
        );
    }
}

#[test]
fn des_donnees_auth_juste_completes_passent() {
    let attestation = Attestation {
        auth: Some(donnees_auth(&[0x11; 32], 0, u32::MAX, None)),
        ..Attestation::default()
    };
    let brut = attestation.ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("AUTH_MINIMUM suffit sans drapeau");
    assert_eq!(objet.donnees_auth.len(), AUTH_MINIMUM);
    assert_eq!(objet.auth.compteur, u32::MAX);
}

#[test]
fn une_cle_cose_vide_se_lit() {
    let attestation = Attestation {
        auth: Some(donnees_auth(
            &[0x11; 32],
            DRAPEAU_ATTESTE,
            0,
            Some((&[0x22; 16], &[0x33; 4], &[])),
        )),
        ..Attestation::default()
    };
    let brut = attestation.ecrire();
    let objet = ObjetAttestation::lire(&brut).expect("bien formées");
    let cle = objet.auth.cle.expect("le drapeau la promet");
    assert!(cle.cle_cose.is_empty());
}

#[test]
fn des_octets_derriere_l_objet_sont_un_refus() {
    let mut brut = Attestation::default().ecrire();
    let dedans = brut.len();
    brut.extend_from_slice(&entier(0));
    assert_eq!(
        ObjetAttestation::lire(&brut),
        Err(Erreur::DonneesEnTrop { position: dedans })
    );
}

#[test]
fn un_objet_se_lit_aussi_depuis_un_curseur_deja_pose() {
    // `depuis` ne réclame pas la fin des octets : c'est ce qui permettra de
    // lire un objet imbriqué dans autre chose.
    let brut = suite(&[Attestation::default().ecrire(), entier(5)]);
    let mut lecteur = Lecteur::nouveau(&brut);
    let objet = ObjetAttestation::depuis(&mut lecteur).expect("un objet bien formé");
    assert_eq!(objet.chaine().len(), 2);
    assert_eq!(lecteur.entier(), Ok(5));
}

#[test]
fn une_cle_de_carte_qui_n_est_pas_du_texte_est_refusee() {
    let brut = suite(&[carte(1), entier(1), entier(2)]);
    assert_eq!(
        ObjetAttestation::lire(&brut),
        Err(Erreur::PasLeBonType { position: 1 })
    );

    let brut = suite(&[carte(1), texte("attStmt"), carte(1), entier(1), entier(2)]);
    assert_eq!(
        ObjetAttestation::lire(&brut),
        Err(Erreur::PasLeBonType { position: 10 })
    );
}

#[test]
fn ce_qui_n_est_pas_une_carte_n_est_pas_un_objet() {
    let brut = tableau(0);
    assert_eq!(
        ObjetAttestation::lire(&brut),
        Err(Erreur::PasLeBonType { position: 0 })
    );
}

#[test]
fn chaque_champ_se_nomme_comme_sur_le_fil() {
    assert_eq!(Champ::Format.nom(), "fmt");
    assert_eq!(Champ::Declaration.nom(), "attStmt");
    assert_eq!(Champ::DonneesAuth.nom(), "authData");
    assert_eq!(Champ::Chaine.nom(), "x5c");
    assert_eq!(Champ::Recu.nom(), "receipt");
}

#[test]
fn une_valeur_illisible_remonte_sa_faute_de_grammaire() {
    // À CHAQUE PLACE de l'objet, une valeur qu'on ne peut pas lire doit
    // remonter la faute de GRAMMAIRE, et non se transformer en champ manquant :
    // un objet illisible et un objet mal rempli ne se corrigent pas pareil.
    //
    // `0x1f` est une longueur indéfinie, refusée partout.
    let illisible = vec![0x1f_u8];
    let auth = donnees_auth(&[0x11; 32], 0, 0, None);

    let places: Vec<(&str, Vec<u8>)> = vec![
        (
            "la valeur de fmt",
            suite(&[carte(1), texte("fmt"), illisible.clone()]),
        ),
        (
            "la valeur d'authData",
            suite(&[carte(1), texte("authData"), illisible.clone()]),
        ),
        (
            "la valeur d'un champ inconnu",
            suite(&[carte(1), texte("inconnu"), illisible.clone()]),
        ),
        (
            "la valeur d'attStmt",
            suite(&[carte(1), texte("attStmt"), illisible.clone()]),
        ),
        (
            "la valeur de receipt",
            suite(&[
                carte(1),
                texte("attStmt"),
                carte(1),
                texte("receipt"),
                illisible.clone(),
            ]),
        ),
        (
            "la valeur d'un champ inconnu d'attStmt",
            suite(&[
                carte(1),
                texte("attStmt"),
                carte(1),
                texte("inconnu"),
                illisible.clone(),
            ]),
        ),
        (
            "la valeur de x5c",
            suite(&[
                carte(1),
                texte("attStmt"),
                carte(1),
                texte("x5c"),
                illisible.clone(),
            ]),
        ),
        (
            "un élément de x5c",
            suite(&[
                carte(1),
                texte("attStmt"),
                carte(1),
                texte("x5c"),
                tableau(1),
                illisible.clone(),
            ]),
        ),
    ];

    for (ou, brut) in places {
        let faute = ObjetAttestation::lire(&brut);
        assert!(
            matches!(faute, Err(Erreur::LongueurIndefinie { .. })),
            "pour {ou} : attendu LongueurIndefinie, obtenu {faute:?}"
        );
    }

    // Et une fois de plus avec un objet par ailleurs complet, pour qu'on ne
    // puisse pas dire que c'est la carte à un seul couple qui décidait.
    let brut = suite(&[
        carte(3),
        texte("fmt"),
        texte(FORMAT),
        texte("authData"),
        octets(&auth),
        texte("attStmt"),
        illisible,
    ]);
    assert_eq!(
        ObjetAttestation::lire(&brut),
        Err(Erreur::LongueurIndefinie {
            position: brut.len() - 1
        })
    );
}

#[test]
fn des_octets_derriere_un_auth_data_sans_cle_sont_un_refus() {
    // Sans le drapeau ATTESTE, rien ne suit le compteur. Ce qui suivrait
    // quand même ne serait lu par personne — et c'est là qu'on met ce qu'un
    // second lecteur lirait.
    let mut auth = donnees_auth(&[0x11; 32], 0, 0, None);
    auth.push(0x99);
    let attestation = Attestation {
        auth: Some(auth),
        ..Attestation::default()
    };
    assert_eq!(
        ObjetAttestation::lire(&attestation.ecrire()),
        Err(Erreur::DonneesEnTrop {
            position: AUTH_MINIMUM
        })
    );
}
