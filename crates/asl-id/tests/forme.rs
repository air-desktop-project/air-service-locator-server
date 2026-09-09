//! La forme des identifiants, éprouvée symbole par symbole.
//!
//! **Ces essais pilotent un CODEC, et c'est ce qui les rend possibles.**
//! `asl-id` ne lit rien, ne tire aucun aléa, ne regarde pas l'heure : chaque cas
//! se pose en une ligne et se vérifie en une autre. C'est ce que la contrainte
//! C1 achète, et c'est ce qui rend le 100 % de C2 atteignable ici.

use asl_id::{Erreur, Genre, Identifiant, LONGUEUR, SYMBOLES};

/// Les six genres, avec leur lettre.
const GENRES: [(Genre, char); 6] = [
    (Genre::Utilisateur, 'u'),
    (Genre::Appareil, 'a'),
    (Genre::Machine, 'm'),
    (Genre::Service, 's'),
    (Genre::Autorisation, 'g'),
    (Genre::Annuaire, 'n'),
];

// ── La forme ────────────────────────────────────────────────────────────────

#[test]
fn la_longueur_est_de_vingt_huit() {
    assert_eq!(SYMBOLES, 26);
    assert_eq!(LONGUEUR, 28);
}

#[test]
fn chaque_genre_a_sa_lettre_et_se_relit() {
    for (genre, lettre) in GENRES {
        let identifiant = Identifiant::depuis_entropie(genre, [0x42; 16]);
        let texte = identifiant.texte();
        let rendu = texte.as_str();

        assert_eq!(rendu.len(), LONGUEUR, "{genre:?}");
        assert!(rendu.starts_with(&format!("{lettre}-")), "{rendu}");
        assert_eq!(genre.prefixe(), lettre as u8);
        assert_eq!(Genre::depuis_prefixe(lettre as u8), Some(genre));
        // La casse du préfixe est indifférente, comme celle du corps.
        assert_eq!(
            Genre::depuis_prefixe(lettre.to_ascii_uppercase() as u8),
            Some(genre)
        );
    }
}

#[test]
fn aucune_lettre_hors_des_six_ne_designe_un_genre() {
    for octet in 0_u8..=255 {
        let attendu = GENRES.iter().any(|(_, lettre)| {
            octet == *lettre as u8 || octet == lettre.to_ascii_uppercase() as u8
        });
        assert_eq!(
            Genre::depuis_prefixe(octet).is_some(),
            attendu,
            "octet {octet}"
        );
    }
}

// ── L'aller-retour ──────────────────────────────────────────────────────────

#[test]
fn tout_identifiant_se_relit_a_l_identique() {
    // Des motifs choisis pour couvrir les extrêmes de la plage utile : le zéro,
    // le maximum, et de quoi faire varier chaque symbole.
    let motifs: [[u8; 16]; 5] = [
        [0x00; 16],
        [0xFF; 16],
        [0x01; 16],
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ],
        [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ],
    ];

    for (genre, _) in GENRES {
        for motif in motifs {
            let origine = Identifiant::depuis_entropie(genre, motif);
            let relu = Identifiant::analyser(origine.texte().as_str()).expect("doit se relire");
            assert_eq!(origine, relu);
            assert_eq!(relu.genre(), genre);
            assert_eq!(relu.octets(), &motif);
        }
    }
}

#[test]
fn le_zero_et_le_maximum_ont_la_forme_attendue() {
    let zero = Identifiant::depuis_entropie(Genre::Machine, [0x00; 16]);
    assert_eq!(zero.texte().as_str(), "m-00000000000000000000000000");

    // 2^128 - 1. Le premier symbole vaut 7 : les 128 bits tiennent dans les 130
    // du corps, et les deux bits de rabiot bornent ce symbole sous 8.
    let maximum = Identifiant::depuis_entropie(Genre::Machine, [0xFF; 16]);
    let rendu = maximum.texte();
    assert_eq!(rendu.as_str(), "m-7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
}

// ── Le rattrapage de Crockford ──────────────────────────────────────────────

#[test]
fn la_casse_est_indifferente() {
    let origine = Identifiant::depuis_entropie(Genre::Service, [0x9A; 16]);
    let canonique = origine.texte();
    let minuscules = canonique.as_str().to_ascii_lowercase();
    let majuscules = canonique.as_str().to_ascii_uppercase();

    assert_eq!(Identifiant::analyser(&minuscules).unwrap(), origine);
    assert_eq!(Identifiant::analyser(&majuscules).unwrap(), origine);
}

#[test]
fn i_et_l_valent_un_et_o_vaut_zero() {
    // C'est LA raison d'être de l'alphabet de Crockford : une faute de
    // transcription ne coûte pas une machine perdue.
    let reference = Identifiant::analyser("m-01000000000000000000000001").unwrap();

    for variante in [
        "m-0I000000000000000000000001",
        "m-0L000000000000000000000001",
        "m-0i000000000000000000000001",
        "m-0l000000000000000000000001",
    ] {
        assert_eq!(
            Identifiant::analyser(variante).unwrap(),
            reference,
            "{variante}"
        );
    }

    let avec_zero = Identifiant::analyser("m-00000000000000000000000001").unwrap();
    let avec_o = Identifiant::analyser("m-OOOOOOOOOOOOOOOOOOOOOOOOO1").unwrap();
    assert_eq!(avec_o, avec_zero);
}

#[test]
fn le_texte_rendu_est_toujours_canonique() {
    // Quelle que soit la forme lue, ce qu'on réécrit est la forme unique.
    let lu = Identifiant::analyser("m-0i000000000000000000000001").unwrap();
    assert_eq!(lu.texte().as_str(), "m-01000000000000000000000001");
}

#[test]
fn le_u_est_refuse_et_non_rattrape() {
    // Crockford le retire de l'alphabet, et rien ne dit vers quoi le corriger.
    for texte in [
        "m-U0000000000000000000000000",
        "m-u0000000000000000000000000",
    ] {
        assert_eq!(
            Identifiant::analyser(texte),
            Err(Erreur::SymboleInvalide { position: 0 }),
            "{texte}"
        );
    }
}

// ── Les refus ───────────────────────────────────────────────────────────────

#[test]
fn une_longueur_fausse_est_refusee_avec_sa_mesure() {
    for texte in ["", "m-", "m-0", "m-000000000000000000000000000"] {
        assert_eq!(
            Identifiant::analyser(texte),
            Err(Erreur::Longueur {
                attendue: LONGUEUR,
                obtenue: texte.len(),
            }),
            "{texte}"
        );
    }
}

#[test]
fn un_prefixe_inconnu_est_refuse() {
    assert_eq!(
        Identifiant::analyser("z-0000000000000000000000000"),
        Err(Erreur::Longueur {
            attendue: LONGUEUR,
            obtenue: 27
        })
    );
    assert_eq!(
        Identifiant::analyser("z-00000000000000000000000000"),
        Err(Erreur::PrefixeInconnu)
    );
}

#[test]
fn le_tiret_est_exige() {
    assert_eq!(
        Identifiant::analyser("m_00000000000000000000000000"),
        Err(Erreur::SeparateurAbsent)
    );
}

/// Compose un texte valide de bout en bout, sauf UN caractère à la position
/// voulue du corps.
///
/// Écrit à la main, ces chaînes de vingt-huit caractères se comptent mal — le
/// premier essai posait un corps de vingt-sept et échouait sur la longueur au
/// lieu du symbole, ce qui n'éprouvait pas ce qu'il annonçait.
fn corps_avec(position: usize, caractere: char) -> String {
    let mut corps: Vec<char> = core::iter::repeat_n('0', SYMBOLES).collect();
    corps[position] = caractere;
    let corps: String = corps.into_iter().collect();
    assert_eq!(corps.len(), SYMBOLES, "le corps doit faire {SYMBOLES}");
    format!("m-{corps}")
}

#[test]
fn un_symbole_invalide_designe_sa_position() {
    // La position est celle du CORPS, pour la désigner à qui a recopié.
    for (position, caractere) in [(0_usize, '!'), (10, '!'), (24, ' '), (25, 'U')] {
        let texte = corps_avec(position, caractere);
        assert_eq!(texte.len(), LONGUEUR);
        assert_eq!(
            Identifiant::analyser(&texte),
            Err(Erreur::SymboleInvalide { position }),
            "{texte}"
        );
    }
}

#[test]
fn un_premier_symbole_au_dela_de_sept_deborde() {
    // 130 bits de corps pour 128 utiles : le premier symbole reste sous 8.
    assert_eq!(
        Identifiant::analyser("m-80000000000000000000000000"),
        Err(Erreur::Debordement)
    );
    assert_eq!(
        Identifiant::analyser("m-ZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
        Err(Erreur::Debordement)
    );
    // Sept passe, huit ne passe pas : la frontière est bien là.
    assert!(Identifiant::analyser("m-70000000000000000000000000").is_ok());
}

#[test]
fn un_tiret_dans_le_corps_est_refuse() {
    // Crockford autorise des tirets de lisibilité ; nous non. Le seul tiret est
    // celui du préfixe, et une deuxième forme d'écriture n'apporterait qu'une
    // ambiguïté de plus.
    let texte = corps_avec(4, '-');
    assert_eq!(
        Identifiant::analyser(&texte),
        Err(Erreur::SymboleInvalide { position: 4 })
    );
}

// ── Le genre exigé ──────────────────────────────────────────────────────────

#[test]
fn analyser_genre_accepte_le_bon_et_refuse_l_autre() {
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x07; 16]);
    let texte = machine.texte();

    assert_eq!(
        Identifiant::analyser_genre(Genre::Machine, texte.as_str()).unwrap(),
        machine
    );
    assert_eq!(
        Identifiant::analyser_genre(Genre::Service, texte.as_str()),
        Err(Erreur::GenreInattendu {
            attendu: Genre::Service,
            obtenu: Genre::Machine,
        })
    );
}

#[test]
fn analyser_genre_propage_les_erreurs_de_forme() {
    assert_eq!(
        Identifiant::analyser_genre(Genre::Machine, "m-8000000000000000000000000O"),
        Err(Erreur::Debordement)
    );
}

// ── Les traits ──────────────────────────────────────────────────────────────

#[test]
fn deux_textes_differents_du_meme_identifiant_sont_egaux() {
    // La propriété qui justifie que cette crate rende des OCTETS et non un
    // texte : `==` sur les chaînes aurait conclu à deux machines.
    let a = Identifiant::analyser("m-0i000000000000000000000001").unwrap();
    let b = Identifiant::analyser("m-01000000000000000000000001").unwrap();
    assert_eq!(a, b);
    assert_ne!(
        "m-0i000000000000000000000001",
        "m-01000000000000000000000001"
    );
}

#[test]
fn le_genre_participe_a_l_egalite() {
    let octets = [0x11; 16];
    let machine = Identifiant::depuis_entropie(Genre::Machine, octets);
    let service = Identifiant::depuis_entropie(Genre::Service, octets);
    assert_ne!(machine, service);
    assert!(machine.octets() == service.octets());
}

#[test]
fn l_ordre_est_total_et_stable() {
    let petit = Identifiant::depuis_entropie(Genre::Machine, [0x00; 16]);
    let grand = Identifiant::depuis_entropie(Genre::Machine, [0x01; 16]);
    assert!(petit < grand);
    assert_eq!(petit.cmp(&petit), core::cmp::Ordering::Equal);
}

#[test]
fn debug_rend_le_texte_et_non_les_octets() {
    let identifiant = Identifiant::depuis_entropie(Genre::Machine, [0x00; 16]);
    assert_eq!(
        format!("{identifiant:?}"),
        "Identifiant(m-00000000000000000000000000)"
    );
    assert_eq!(format!("{identifiant}"), "m-00000000000000000000000000");
}

#[test]
fn le_texte_s_affiche_aussi() {
    let identifiant = Identifiant::depuis_entropie(Genre::Annuaire, [0x00; 16]);
    let texte = identifiant.texte();
    assert_eq!(format!("{texte}"), "n-00000000000000000000000000");
    assert!(format!("{texte:?}").starts_with("Texte("));
}

#[test]
fn chaque_erreur_se_dit_a_un_humain() {
    // Une erreur qu'on ne peut pas afficher n'aide personne à trouver le
    // caractère qu'il a mal recopié.
    let messages = [
        format!(
            "{}",
            Erreur::Longueur {
                attendue: 28,
                obtenue: 3
            }
        ),
        format!("{}", Erreur::PrefixeInconnu),
        format!("{}", Erreur::SeparateurAbsent),
        format!(
            "{}",
            Erreur::GenreInattendu {
                attendu: Genre::Machine,
                obtenu: Genre::Service
            }
        ),
        format!("{}", Erreur::SymboleInvalide { position: 4 }),
        format!("{}", Erreur::Debordement),
    ];
    for message in messages {
        assert!(!message.is_empty());
    }
}

// ── L'alphabet, en entier ───────────────────────────────────────────────────

/// L'alphabet de Crockford, tel que la spécification le fixe.
///
/// **Écrit ICI À LA MAIN, et non importé de la crate.** Un essai qui réutiliserait
/// la table qu'il éprouve ne vérifierait que sa propre cohérence : une lettre
/// oubliée le serait des deux côtés, et l'essai passerait.
const ALPHABET_ATTENDU: [char; 32] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J',
    'K', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z',
];

/// La valeur d'un identifiant dont seul le dernier symbole est renseigné.
fn valeur_du_dernier_symbole(caractere: char) -> Result<u128, Erreur> {
    let texte = corps_avec(SYMBOLES - 1, caractere);
    Identifiant::analyser(&texte).map(|identifiant| u128::from_be_bytes(*identifiant.octets()))
}

#[test]
fn chaque_symbole_de_l_alphabet_porte_sa_valeur() {
    for (valeur, symbole) in ALPHABET_ATTENDU.iter().enumerate() {
        let attendue = u128::try_from(valeur).unwrap();

        assert_eq!(
            valeur_du_dernier_symbole(*symbole),
            Ok(attendue),
            "majuscule {symbole}"
        );
        assert_eq!(
            valeur_du_dernier_symbole(symbole.to_ascii_lowercase()),
            Ok(attendue),
            "minuscule {symbole}"
        );
    }
}

#[test]
fn l_encodage_emploie_exactement_cet_alphabet() {
    // Pour chaque valeur de 0 à 31, l'identifiant qui la porte doit s'écrire
    // avec le symbole attendu en dernière position.
    for (valeur, symbole) in ALPHABET_ATTENDU.iter().enumerate() {
        let mut octets = [0_u8; 16];
        octets[15] = u8::try_from(valeur).unwrap();
        let identifiant = Identifiant::depuis_entropie(Genre::Machine, octets);
        let rendu = identifiant.texte();
        let dernier = rendu.as_str().chars().next_back().unwrap();
        assert_eq!(dernier, *symbole, "valeur {valeur}");
    }
}

#[test]
fn tout_octet_est_soit_accepte_soit_refuse_selon_la_regle() {
    // La règle, énoncée indépendamment de l'implémentation :
    //   — les 32 symboles de l'alphabet, dans les deux casses ;
    //   — `I`, `L` rattrapés en `1` et `O` en `0`, dans les deux casses ;
    //   — TOUT le reste refusé, `U` compris.
    //
    // LE BALAYAGE S'ARRÊTE À 127, ET C'EST LA BONNE BORNE. Au-delà, `char::from`
    // rend un caractère qui s'écrit sur DEUX octets en UTF-8 : le corps ferait
    // vingt-sept octets et l'analyseur répondrait sur la longueur, pas sur le
    // symbole. Ce n'est pas ce que cet essai éprouve — c'est le suivant.
    for octet in 0_u8..=127 {
        let caractere = char::from(octet);

        let attendu: Option<u128> = if let Some(position) =
            ALPHABET_ATTENDU.iter().position(|symbole| {
                *symbole == caractere.to_ascii_uppercase() && caractere.is_ascii_alphanumeric()
            }) {
            Some(u128::try_from(position).unwrap())
        } else {
            match caractere.to_ascii_uppercase() {
                'I' | 'L' => Some(1),
                'O' => Some(0),
                _ => None,
            }
        };

        let obtenu = valeur_du_dernier_symbole(caractere);

        match attendu {
            Some(valeur) => assert_eq!(
                obtenu,
                Ok(valeur),
                "octet {octet} ({caractere:?}) devait valoir {valeur}"
            ),
            None => assert_eq!(
                obtenu,
                Err(Erreur::SymboleInvalide {
                    position: SYMBOLES - 1
                }),
                "octet {octet} ({caractere:?}) devait être refusé"
            ),
        }
    }
}

#[test]
fn un_caractere_non_ascii_est_toujours_refuse() {
    // L'analyseur travaille sur des OCTETS. Un caractère hors ASCII en occupe
    // plusieurs, et LAQUELLE des deux erreurs répond dépend alors du compte
    // d'octets qui en résulte — ce n'est pas un détail qu'on peut choisir.
    //
    // Ce comportement est épinglé ici parce qu'il n'est pas évident : quelqu'un
    // qui colle un identifiant depuis un traitement de texte peut y avoir gagné
    // un tiret long ou une espace insécable, et le message doit rester juste.
    //
    // La première version de cet essai affirmait « toujours une erreur de
    // longueur ». C'était FAUX, et c'est le code qui avait raison.

    // Vingt-huit octets pile — le `é` en occupe deux, donc vingt-quatre zéros
    // suffisent. La longueur passe, le premier octet du `é` ne passe pas.
    let juste_la_longueur = format!("m-é{}", "0".repeat(24));
    assert_eq!(juste_la_longueur.len(), LONGUEUR);
    assert_eq!(
        Identifiant::analyser(&juste_la_longueur),
        Err(Erreur::SymboleInvalide { position: 0 })
    );

    // Vingt-neuf octets : la longueur répond avant qu'on regarde un symbole.
    let trop_long = format!("m-é{}", "0".repeat(25));
    assert_eq!(
        Identifiant::analyser(&trop_long),
        Err(Erreur::Longueur {
            attendue: LONGUEUR,
            obtenue: 29,
        })
    );

    // Dans tous les cas : REFUSÉ. C'est la seule propriété qui compte pour qui
    // appelle ; le reste est du diagnostic.
    for texte in [
        "m-—0000000000000000000000000",
        "m-0000000000000000000000000é",
        "m-\u{00a0}000000000000000000000000",
    ] {
        assert!(Identifiant::analyser(texte).is_err(), "{texte}");
    }
}
