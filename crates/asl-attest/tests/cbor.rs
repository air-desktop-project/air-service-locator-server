//! Ce que le lecteur CBOR lit, et surtout ce qu'il refuse.

mod forge;

use asl_attest::{Erreur, LONGUEUR_MAX, Lecteur, PROFONDEUR_MAX, Valeur};
use forge::{carte, entier, octets, suite, tableau, tete, tete_large, texte};

#[test]
fn un_entier_court_tient_dans_sa_tete() {
    let mut lecteur = Lecteur::nouveau(&[0x17]);
    assert_eq!(lecteur.valeur(), Ok(Valeur::Entier(23)));
    assert_eq!(lecteur.position(), 1);
    assert_eq!(lecteur.rien_de_plus(), Ok(()));
}

#[test]
fn les_quatre_largeurs_de_tete_se_lisent() {
    for valeur in [24_u64, 0x100, 0x1_0000, 0x1_0000_0000] {
        let octets = entier(valeur);
        let mut lecteur = Lecteur::nouveau(&octets);
        assert_eq!(
            lecteur.valeur(),
            Ok(Valeur::Entier(valeur)),
            "largeur de {valeur}"
        );
    }
}

#[test]
fn les_quatre_largeurs_refusent_une_forme_trop_longue() {
    // La MÊME valeur, écrite sur une tête plus large que nécessaire. Une seule
    // écriture doit être acceptée, sinon deux objets différents portent les
    // mêmes octets.
    for largeur in [1_usize, 2, 4, 8] {
        let octets = tete_large(0, 1, largeur);
        let mut lecteur = Lecteur::nouveau(&octets);
        assert_eq!(
            lecteur.valeur(),
            Err(Erreur::EncodageNonMinimal { position: 0 }),
            "sur {largeur} octet(s)"
        );
    }
}

#[test]
fn rien_a_lire_est_tronque() {
    let mut lecteur = Lecteur::nouveau(&[]);
    assert_eq!(lecteur.valeur(), Err(Erreur::Tronque { position: 0 }));
    assert_eq!(lecteur.restants(), 0);
}

#[test]
fn une_tete_amputee_de_sa_valeur_est_tronquee() {
    // 0x19 annonce deux octets, un seul suit.
    let mut lecteur = Lecteur::nouveau(&[0x19, 0x01]);
    assert_eq!(lecteur.valeur(), Err(Erreur::Tronque { position: 0 }));
}

#[test]
fn une_longueur_indefinie_est_refusee() {
    // 0x5f : chaîne d'octets de longueur indéfinie.
    let mut lecteur = Lecteur::nouveau(&[0x5f]);
    assert_eq!(
        lecteur.valeur(),
        Err(Erreur::LongueurIndefinie { position: 0 })
    );
}

#[test]
fn les_informations_reservees_sont_refusees() {
    for info in [28_u8, 29, 30] {
        let mut lecteur = Lecteur::nouveau(core::slice::from_ref(&info));
        assert_eq!(
            lecteur.valeur(),
            Err(Erreur::EnteteReserve { position: 0 }),
            "information {info}"
        );
    }
}

#[test]
fn les_trois_types_majeurs_non_servis_sont_refuses() {
    // 1 = entier négatif, 6 = étiquette, 7 = flottant et valeurs simples.
    for majeur in [1_u8, 6, 7] {
        let octets = tete(majeur, 0);
        let mut lecteur = Lecteur::nouveau(&octets);
        assert_eq!(
            lecteur.valeur(),
            Err(Erreur::TypeRefuse {
                majeur,
                position: 0
            })
        );
    }
}

#[test]
fn une_longueur_demesuree_est_refusee_sans_lire_la_suite() {
    let annoncee = LONGUEUR_MAX + 1;
    let octets = tete(2, annoncee);
    let mut lecteur = Lecteur::nouveau(&octets);
    assert_eq!(
        lecteur.valeur(),
        Err(Erreur::LongueurDemesuree {
            annoncee,
            position: 0
        })
    );
}

#[test]
fn un_tableau_qui_annonce_plus_qu_il_ne_reste_est_tronque() {
    // Trois éléments annoncés, aucun octet derrière.
    let octets = tableau(3);
    let mut lecteur = Lecteur::nouveau(&octets);
    assert_eq!(lecteur.valeur(), Err(Erreur::Tronque { position: 0 }));
}

#[test]
fn une_chaine_d_octets_se_lit_telle_quelle() {
    let brut = octets(&[1, 2, 3]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.valeur(), Ok(Valeur::Octets(&[1, 2, 3])));
}

#[test]
fn un_texte_valide_se_lit() {
    let brut = texte("clé");
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.valeur(), Ok(Valeur::Texte("clé")));
}

#[test]
fn un_texte_qui_n_est_pas_utf8_est_refuse() {
    let brut = [0x62, 0xff, 0xfe];
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.valeur(), Err(Erreur::TexteInvalide { position: 0 }));
}

#[test]
fn un_tableau_et_une_carte_rendent_leur_compte() {
    let brut = suite(&[tableau(2), entier(1), entier(2)]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.valeur(), Ok(Valeur::Tableau(2)));

    let brut = suite(&[carte(1), texte("a"), entier(1)]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.valeur(), Ok(Valeur::Carte(1)));
}

#[test]
fn chaque_lecture_typee_rend_ce_qu_elle_promet() {
    let brut = suite(&[entier(7), octets(&[9]), texte("x"), tableau(0), carte(0)]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.entier(), Ok(7));
    assert_eq!(lecteur.octets(), Ok(&[9_u8][..]));
    assert_eq!(lecteur.texte(), Ok("x"));
    assert_eq!(lecteur.tableau(), Ok(0));
    assert_eq!(lecteur.carte(), Ok(0));
    assert_eq!(lecteur.rien_de_plus(), Ok(()));
}

#[test]
fn chaque_lecture_typee_refuse_un_autre_type() {
    // Un entier là où chacune des cinq attend autre chose.
    let brut = entier(0);
    assert_eq!(
        Lecteur::nouveau(&brut).octets(),
        Err(Erreur::PasLeBonType { position: 0 })
    );
    assert_eq!(
        Lecteur::nouveau(&brut).texte(),
        Err(Erreur::PasLeBonType { position: 0 })
    );
    assert_eq!(
        Lecteur::nouveau(&brut).tableau(),
        Err(Erreur::PasLeBonType { position: 0 })
    );
    assert_eq!(
        Lecteur::nouveau(&brut).carte(),
        Err(Erreur::PasLeBonType { position: 0 })
    );
    let brut = texte("x");
    assert_eq!(
        Lecteur::nouveau(&brut).entier(),
        Err(Erreur::PasLeBonType { position: 0 })
    );
}

#[test]
fn des_octets_en_trop_derriere_un_objet_bien_forme_sont_un_refus() {
    let brut = suite(&[entier(1), entier(2)]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.entier(), Ok(1));
    assert_eq!(
        lecteur.rien_de_plus(),
        Err(Erreur::DonneesEnTrop { position: 1 })
    );
}

#[test]
fn sauter_passe_par_dessus_un_scalaire() {
    let brut = suite(&[texte("bavard"), entier(4)]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.sauter(), Ok(()));
    assert_eq!(lecteur.entier(), Ok(4));
}

#[test]
fn sauter_passe_par_dessus_un_tableau_et_une_carte() {
    let brut = suite(&[
        tableau(2),
        entier(1),
        octets(&[2]),
        carte(1),
        texte("k"),
        entier(9),
        entier(42),
    ]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(lecteur.sauter(), Ok(()));
    assert_eq!(lecteur.sauter(), Ok(()));
    assert_eq!(lecteur.entier(), Ok(42));
    assert_eq!(lecteur.rien_de_plus(), Ok(()));
}

#[test]
fn une_imbrication_trop_profonde_est_refusee_avant_la_pile() {
    // PROFONDEUR_MAX tableaux d'un élément, puis un de plus : le dernier est
    // celui de trop. Sans la borne, c'est la pile qui répondrait.
    let mut brut = Vec::new();
    for _ in 0..=PROFONDEUR_MAX {
        brut.extend_from_slice(&tableau(1));
    }
    brut.extend_from_slice(&entier(0));
    let mut lecteur = Lecteur::nouveau(&brut);
    let faute = lecteur.sauter();
    assert!(
        matches!(faute, Err(Erreur::TropProfond { .. })),
        "attendu TropProfond, obtenu {faute:?}"
    );
}

#[test]
fn sauter_remonte_la_faute_de_ce_qu_il_saute() {
    // Un tableau qui annonce un élément, et un élément malformé derrière.
    let brut = suite(&[tableau(1), vec![0x1f]]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(
        lecteur.sauter(),
        Err(Erreur::LongueurIndefinie { position: 1 })
    );

    let brut = suite(&[carte(1), vec![0x1f]]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(
        lecteur.sauter(),
        Err(Erreur::LongueurIndefinie { position: 1 })
    );
}

#[test]
fn sauter_remonte_la_faute_de_la_valeur_d_une_carte() {
    let brut = suite(&[carte(1), texte("k"), vec![0x1f]]);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(
        lecteur.sauter(),
        Err(Erreur::LongueurIndefinie { position: 3 })
    );
}

#[test]
fn un_conteneur_qui_annonce_une_longueur_demesuree_est_refuse() {
    // La borne mord sur le COMPTE, avant qu'on cherche à lire les éléments.
    for majeur in [4_u8, 5] {
        let brut = tete(majeur, LONGUEUR_MAX + 1);
        let mut lecteur = Lecteur::nouveau(&brut);
        assert_eq!(
            lecteur.valeur(),
            Err(Erreur::LongueurDemesuree {
                annoncee: LONGUEUR_MAX + 1,
                position: 0
            }),
            "type majeur {majeur}"
        );
    }
}

#[test]
fn une_chaine_qui_annonce_plus_d_octets_qu_il_n_en_reste_est_tronquee() {
    for majeur in [2_u8, 3] {
        let brut = suite(&[tete(majeur, 3), vec![0x41]]);
        let mut lecteur = Lecteur::nouveau(&brut);
        assert_eq!(
            lecteur.valeur(),
            Err(Erreur::Tronque { position: 0 }),
            "type majeur {majeur}"
        );
    }
}

#[test]
fn un_texte_qui_annonce_une_longueur_demesuree_est_refuse() {
    let brut = tete(3, LONGUEUR_MAX + 1);
    let mut lecteur = Lecteur::nouveau(&brut);
    assert_eq!(
        lecteur.valeur(),
        Err(Erreur::LongueurDemesuree {
            annoncee: LONGUEUR_MAX + 1,
            position: 0
        })
    );
}

#[test]
fn chaque_lecture_typee_remonte_la_faute_de_grammaire() {
    // Pas « ce n'est pas le bon type » : la valeur n'a PAS PU ÊTRE LUE, et
    // confondre les deux ferait passer un objet illisible pour un objet mal
    // rempli.
    let brut = [0x1f];
    let attendue = Erreur::LongueurIndefinie { position: 0 };
    assert_eq!(Lecteur::nouveau(&brut).entier(), Err(attendue));
    assert_eq!(Lecteur::nouveau(&brut).octets(), Err(attendue));
    assert_eq!(Lecteur::nouveau(&brut).texte(), Err(attendue));
    assert_eq!(Lecteur::nouveau(&brut).tableau(), Err(attendue));
    assert_eq!(Lecteur::nouveau(&brut).carte(), Err(attendue));
}

#[test]
fn un_flottant_est_refuse_pour_son_type_et_non_pour_son_encodage() {
    // RÉGRESSION. `0xfb` est un double : son information additionnelle 27 ne
    // veut PAS dire « huit octets d'entier », et la règle de forme minimale ne
    // s'y applique pas. Le lecteur lisait pourtant l'argument avant le type, et
    // un double à zéro se faisait refuser pour « encodage non minimal ».
    //
    // Les deux sont des refus, donc rien ne cassait — et c'est bien le
    // problème : le jour où une capture réelle serait refusée, la phrase
    // aurait envoyé chercher du côté d'une règle qui n'a rien à voir.
    //
    // **Ce sont les graines de fuzz qui l'ont attrapé**, parce qu'un essai les
    // relit et vérifie que chacune rend le refus de son nom.
    for premier in [0xf9_u8, 0xfa, 0xfb] {
        let brut = suite(&[vec![premier], vec![0; 8]]);
        let mut lecteur = Lecteur::nouveau(&brut);
        assert_eq!(
            lecteur.valeur(),
            Err(Erreur::TypeRefuse {
                majeur: 7,
                position: 0
            }),
            "pour {premier:#04x}"
        );
    }

    // Et l'inverse tient toujours : sur un type servi, la forme minimale mord.
    let mut lecteur = Lecteur::nouveau(&[0x18, 0x01]);
    assert_eq!(
        lecteur.valeur(),
        Err(Erreur::EncodageNonMinimal { position: 0 })
    );
}
