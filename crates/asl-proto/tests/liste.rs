//! Les listes : composer un tableau, et le redécouper.
//!
//! # CE QUE CE CODEC EXISTE POUR ÉVITER
//!
//! `GET /v1/ou?service=` et `GET /v1/machines/{m}/services` rendent des
//! [`Reponse`] — les mêmes objets que la forme par machine. **Une forme propre
//! aux listes aurait demandé un second décodeur, écrit cinq fois** dans les cinq
//! liaisons.
//!
//! Le prix est ce fichier : un découpage qui doit être juste, parce qu'il coupe
//! des octets sans les comprendre.

use asl_proto::cadrage::{Liste, elements};
use asl_proto::{Erreur, LISTE_MAX};

/// Compose une liste et rend ce qu'elle a écrit.
fn composer(elements_bruts: &[&[u8]]) -> Result<Vec<u8>, Erreur> {
    let mut sortie = vec![0_u8; asl_proto::cadrage::MESSAGE_MAX];
    let combien = {
        let mut liste = Liste::nouvelle(&mut sortie);
        for element in elements_bruts {
            liste.ajouter(element);
        }
        liste.achever()?
    };
    sortie.truncate(combien);
    Ok(sortie)
}

/// Redécoupe, et rend les tranches.
fn decouper(octets: &[u8]) -> Result<Vec<Vec<u8>>, Erreur> {
    Ok(elements(octets)?.map(<[u8]>::to_vec).collect())
}

// ── L'aller et le retour ────────────────────────────────────────────────────

#[test]
fn une_liste_vide_est_un_tableau_vide() {
    // **ET NON UNE ABSENCE DE CORPS.** « Je n'ai rien à te montrer » et « je ne
    // t'ai rien répondu » ne se lisent pas pareil chez un client.
    let compose = composer(&[]).expect("elle se compose");
    assert_eq!(compose, b"[]");
    assert_eq!(
        decouper(&compose).expect("elle se relit"),
        Vec::<Vec<u8>>::new()
    );
}

#[test]
fn ce_qui_entre_ressort_a_l_identique() {
    let objets: [&[u8]; 3] = [br#"{"a":1}"#, br#"{"b":[2,3]}"#, br#"{"c":"d"}"#];
    let compose = composer(&objets).expect("elle se compose");
    assert_eq!(compose, br#"[{"a":1},{"b":[2,3]},{"c":"d"}]"#);

    let relu = decouper(&compose).expect("elle se relit");
    assert_eq!(relu.len(), 3);
    for (obtenu, attendu) in relu.iter().zip(objets.iter()) {
        assert_eq!(obtenu.as_slice(), *attendu);
    }
}

#[test]
fn une_accolade_dans_une_chaine_ne_ferme_rien() {
    // **C'EST TOUT L'ENJEU DU DÉCOUPAGE.** Un compteur naïf d'accolades
    // couperait cet élément en deux, et rendrait deux moitiés qui ne se décodent
    // pas — ou pire, qui se décodent en autre chose.
    let piege: [&[u8]; 2] = [br#"{"nom":"}{,]["}"#, br#"{"nom":"fin"}"#];
    let compose = composer(&piege).expect("elle se compose");
    let relu = decouper(&compose).expect("elle se relit");
    assert_eq!(relu.len(), 2, "l'accolade de la chaîne a coupé l'élément");
    assert_eq!(relu[0].as_slice(), piege[0]);
}

#[test]
fn un_guillemet_echappe_ne_ferme_pas_la_chaine() {
    // `\"` reste dans la chaîne ; `\\` juste avant, non. C'est la seule
    // subtilité de ce parcours.
    let piege: [&[u8]; 2] = [br#"{"a":"il dit \"}\" et continue"}"#, br#"{"b":2}"#];
    let compose = composer(&piege).expect("elle se compose");
    let relu = decouper(&compose).expect("elle se relit");
    assert_eq!(relu.len(), 2);
    assert_eq!(relu[0].as_slice(), piege[0]);

    // Une barre oblique échappée, suivie d'un guillemet qui FERME bien.
    let autre: [&[u8]; 2] = [br#"{"a":"fin\\"}"#, br#"{"b":2}"#];
    let compose = composer(&autre).expect("elle se compose");
    assert_eq!(decouper(&compose).expect("relue").len(), 2);
}

#[test]
fn les_tableaux_imbriques_se_comptent() {
    let dedans: [&[u8]; 2] = [b"[1,2]", b"[[3],[4]]"];
    let compose = composer(&dedans).expect("elle se compose");
    let relu = decouper(&compose).expect("elle se relit");
    assert_eq!(relu.len(), 2);
    assert_eq!(relu[1].as_slice(), b"[[3],[4]]");
}

#[test]
fn les_valeurs_nues_se_decoupent_aussi() {
    // Le codec ne regarde pas DANS les éléments : un nombre est un élément.
    let compose = composer(&[b"1", b"23", b"true"]).expect("elle se compose");
    assert_eq!(compose, b"[1,23,true]");
    let relu = decouper(&compose).expect("elle se relit");
    assert_eq!(relu.len(), 3);
    assert_eq!(relu[2].as_slice(), b"true");
}

#[test]
fn les_blancs_autour_des_elements_sont_tolerés() {
    let relu = decouper(b"[ {\"a\":1} , {\"b\":2} ]").expect("elle se relit");
    assert_eq!(relu.len(), 2);
    assert_eq!(relu[0].as_slice(), br#"{"a":1}"#);
    assert_eq!(relu[1].as_slice(), br#"{"b":2}"#);
    assert_eq!(decouper(b"[ ]").expect("vide").len(), 0);
}

// ── La borne ────────────────────────────────────────────────────────────────

#[test]
fn au_dela_de_la_borne_elle_refuse_au_lieu_de_tronquer() {
    // **UNE LISTE TRONQUÉE MENTIRAIT PAR OMISSION**, et le demandeur croirait
    // avoir tout vu. Le refus est ce qui rend la borne honnête.
    let un = br#"{"a":1}"#;
    let juste: Vec<&[u8]> = core::iter::repeat_n(un.as_slice(), LISTE_MAX).collect();
    assert!(composer(&juste).is_ok(), "{LISTE_MAX} passent");

    let trop: Vec<&[u8]> = core::iter::repeat_n(un.as_slice(), LISTE_MAX + 1).collect();
    assert_eq!(
        composer(&trop),
        Err(Erreur::TropDElements {
            obtenu: LISTE_MAX + 1
        })
    );
}

#[test]
fn la_liste_compte_meme_ce_qu_elle_refuse() {
    // C'est ce qui permet à l'étage 3 de DIRE combien il y en avait.
    let mut sortie = vec![0_u8; asl_proto::cadrage::MESSAGE_MAX];
    let mut liste = Liste::nouvelle(&mut sortie);
    for _ in 0..(LISTE_MAX + 5) {
        liste.ajouter(b"1");
    }
    assert_eq!(liste.combien(), LISTE_MAX + 5);
    assert!(liste.achever().is_err());
}

#[test]
fn un_tableau_qui_porte_trop_d_elements_est_refuse_a_la_lecture() {
    let mut brut = Vec::from(b"[".as_slice());
    for rang in 0..=LISTE_MAX {
        if rang > 0 {
            brut.push(b',');
        }
        brut.push(b'1');
    }
    brut.push(b']');
    assert_eq!(
        decouper(&brut),
        Err(Erreur::TropDElements {
            obtenu: LISTE_MAX + 1
        })
    );
}

#[test]
fn un_tampon_trop_petit_se_dit() {
    let mut sortie = [0_u8; 4];
    let mut liste = Liste::nouvelle(&mut sortie);
    liste.ajouter(br#"{"beaucoup":"trop"}"#);
    assert_eq!(liste.achever(), Err(Erreur::TamponTropPetit));
}

#[test]
fn un_message_trop_long_est_refuse_avant_d_etre_parcouru() {
    let brut = vec![b'x'; asl_proto::cadrage::MESSAGE_MAX + 1];
    assert_eq!(
        decouper(&brut),
        Err(Erreur::MessageTropLong {
            obtenue: asl_proto::cadrage::MESSAGE_MAX + 1
        })
    );
}

// ── Ce qui ne se lit pas ────────────────────────────────────────────────────

#[test]
fn ce_qui_n_est_pas_un_tableau_est_refuse() {
    for brut in [b"".as_slice(), b"{}", b"1", br#""texte""#, b"]"] {
        assert!(
            matches!(decouper(brut), Err(Erreur::ListeMalFormee { .. })),
            "{:?} devrait être refusé",
            core::str::from_utf8(brut)
        );
    }
}

#[test]
fn un_tableau_mal_ferme_est_refuse() {
    for brut in [
        b"[".as_slice(),
        b"[1",
        b"[1,",
        b"[1,]",
        b"[,1]",
        b"[{]",
        b"[{\"a\":1}",
        b"[\"sans fin",
        b"[\"echappement a la fin\\",
    ] {
        assert!(
            decouper(brut).is_err(),
            "{:?} devrait être refusé",
            core::str::from_utf8(brut)
        );
    }
}

#[test]
fn ce_qui_suit_le_tableau_est_refuse() {
    // **`DonneesEnTrop`, ET NON UN SILENCE.** Deux messages collés seraient lus
    // comme un seul, et le second passerait pour la fin du premier.
    assert!(decouper(b"[]x").is_err());
    assert!(decouper(br#"[{"a":1}] {"b":2}"#).is_err());
}

#[test]
fn deux_elements_sans_virgule_sont_refuses() {
    assert!(matches!(
        decouper(br#"[{"a":1} {"b":2}]"#),
        Err(Erreur::ListeMalFormee { .. })
    ));
}

// ── La liste est le même objet, répété ──────────────────────────────────────

#[test]
fn chaque_element_se_decode_comme_une_reponse_seule() {
    // **C'EST LA PROPRIÉTÉ QUI JUSTIFIE TOUT CE FICHIER.** Les cinq liaisons
    // n'ont qu'un lecteur : celui d'une `Reponse`. Une forme propre aux listes
    // en aurait demandé un second, écrit cinq fois.
    use asl_id::{Genre, Identifiant};
    use asl_proto::cadrage::TamponsReponse;
    use asl_proto::{
        Bail, Horodatage, Joignabilite, PointEcoute, Port, Protocole, Reponse, Verdict, VerdictNat,
        VuDepuis,
    };
    use core::net::{IpAddr, Ipv4Addr};

    let composer_une = |marque: u8| {
        let service = Identifiant::depuis_entropie(Genre::Service, [marque; 16]);
        let point = PointEcoute::nouveau(Protocole::Tcp, Port::depuis_u16(8080).unwrap());
        let verdicts = [Joignabilite {
            point,
            verdict: Verdict::Injoignable {
                a: Horodatage::depuis_millisecondes(u64::from(marque)),
            },
        }];
        let reponse = Reponse::nouvelle(
            service,
            Bail::nouveau(15, 45).unwrap(),
            VuDepuis {
                adresse: IpAddr::V4(Ipv4Addr::new(203, 0, 113, marque)),
                port: Port::depuis_u16(41_234).unwrap(),
            },
            VerdictNat::Oui,
            &verdicts,
        )
        .unwrap();
        let mut place = vec![0_u8; asl_proto::cadrage::MESSAGE_MAX];
        let combien = reponse.encoder(&mut place).unwrap();
        place.truncate(combien);
        (service, place)
    };

    let (une, corps_une) = composer_une(1);
    let (autre, corps_autre) = composer_une(2);

    let compose = composer(&[&corps_une, &corps_autre]).expect("elle se compose");
    let tranches = decouper(&compose).expect("elle se relit");
    assert_eq!(tranches.len(), 2);

    // **UN SEUL JEU DE TAMPONS, RÉEMPLOYÉ.** C'est ce que le découpage achète :
    // décoder les soixante-quatre d'un coup demanderait soixante-quatre
    // `TamponsReponse` sur une pile.
    let mut tampons = TamponsReponse::nouveaux();
    let premiere = Reponse::decoder(&tranches[0], &mut tampons).expect("elle se décode");
    assert_eq!(premiere.service, une);

    let mut tampons = TamponsReponse::nouveaux();
    let seconde = Reponse::decoder(&tranches[1], &mut tampons).expect("elle se décode");
    assert_eq!(seconde.service, autre);
    assert_eq!(seconde.joignabilite.len(), 1);
}

// ── Le flux : des objets collés, et un dernier à moitié là ──────────────────

use asl_proto::cadrage::objets;

/// Découpe, et rend les tranches avec le nombre d'octets consommés.
fn au_fil(octets: &[u8]) -> Result<(Vec<Vec<u8>>, usize), Erreur> {
    let (trouves, consommes) = objets(octets)?;
    Ok((trouves.map(<[u8]>::to_vec).collect(), consommes))
}

#[test]
fn des_objets_colles_se_decoupent_un_par_un() {
    // **PAS D'ENVELOPPE** : un tableau attendrait un crochet fermant qui ne
    // viendra jamais, et un lecteur qui l'attendrait n'afficherait rien.
    let flux = br#"{"a":1}{"b":2}{"c":3}"#;
    let (trouves, consommes) = au_fil(flux).expect("ils se lisent");
    assert_eq!(trouves.len(), 3);
    assert_eq!(trouves[0].as_slice(), br#"{"a":1}"#);
    assert_eq!(trouves[2].as_slice(), br#"{"c":3}"#);
    assert_eq!(consommes, flux.len(), "tout a été consommé");
}

#[test]
fn un_dernier_objet_incomplet_n_est_pas_une_faute() {
    // **C'EST LE CAS ORDINAIRE D'UN FLUX** : un datagramme coupe où il veut.
    // Le refuser ferait rejeter une poussée parfaitement valide parce que la
    // suite n'est pas encore arrivée.
    let flux = br#"{"a":1}{"b":2"#;
    let (trouves, consommes) = au_fil(flux).expect("le premier se lit");
    assert_eq!(trouves.len(), 1);
    assert_eq!(trouves[0].as_slice(), br#"{"a":1}"#);
    assert_eq!(consommes, 7, "le reste doit être gardé par l'appelant");

    // Et l'appelant qui garde le reste, puis reçoit la suite, obtient l'objet.
    let mut tampon = flux[consommes..].to_vec();
    tampon.extend_from_slice(b"}");
    let (trouves, consommes) = au_fil(&tampon).expect("il se lit maintenant");
    assert_eq!(trouves.len(), 1);
    assert_eq!(trouves[0].as_slice(), br#"{"b":2}"#);
    assert_eq!(consommes, tampon.len());
}

#[test]
fn un_tampon_sans_objet_complet_rend_le_vide_et_zero() {
    // Ce n'est pas une faute, c'est « pas encore ».
    for partiel in [b"".as_slice(), b"{", br#"{"a""#, br#"{"a":"tex"#] {
        let (trouves, consommes) = au_fil(partiel).expect("pas de faute");
        assert!(trouves.is_empty(), "{partiel:?}");
        assert_eq!(consommes, 0, "{partiel:?}");
    }
}

#[test]
fn les_blancs_qui_suivent_sont_consommes_avec_le_dernier() {
    // Les garder ferait grandir le tampon d'un octet par poussée, pour rien.
    let flux = b"{\"a\":1}\n {\"b\":2}\n";
    let (trouves, consommes) = au_fil(flux).expect("ils se lisent");
    assert_eq!(trouves.len(), 2);
    assert_eq!(consommes, flux.len());
}

#[test]
fn une_accolade_dans_une_chaine_ne_coupe_pas_un_objet_du_flux() {
    // Même piège que pour un tableau, et il compte davantage ici : un flux se
    // relit indéfiniment, et une coupure au mauvais endroit décale tout ce qui
    // suit.
    let flux = br#"{"nom":"}{"}{"apres":1}"#;
    let (trouves, consommes) = au_fil(flux).expect("ils se lisent");
    assert_eq!(trouves.len(), 2, "l'accolade de la chaîne a coupé");
    assert_eq!(trouves[0].as_slice(), br#"{"nom":"}{"}"#);
    assert_eq!(consommes, flux.len());
}

#[test]
fn une_chaine_jamais_close_attend_au_lieu_de_refuser() {
    let (trouves, consommes) = au_fil(br#"{"a":"sans fin"#).expect("pas de faute");
    assert!(trouves.is_empty());
    assert_eq!(consommes, 0);

    // Un échappement en dernière position, aussi : `\` attend son caractère.
    let (trouves, consommes) = au_fil(br#"{"a":"x\"#).expect("pas de faute");
    assert!(trouves.is_empty());
    assert_eq!(consommes, 0);
}

#[test]
fn ce_qui_ne_commence_pas_une_valeur_est_refuse() {
    // **ICI, C'EST BIEN UNE FAUTE** : un flux qui commence par une virgule ne
    // deviendra pas valide en attendant.
    assert!(matches!(au_fil(b","), Err(Erreur::ListeMalFormee { .. })));
    assert!(matches!(
        au_fil(br#"{"a":1},{"b":2}"#),
        Err(Erreur::ListeMalFormee { .. })
    ));
}

#[test]
fn au_dela_de_la_borne_il_s_arrete_et_l_appelant_revient() {
    // **ON S'ARRÊTE AU LIEU DE TRONQUER** : celui qui draine ce qu'on lui rend
    // reviendra chercher la suite, et rien n'est perdu.
    let un = br#"{"a":1}"#;
    let mut flux = Vec::new();
    for _ in 0..(LISTE_MAX + 5) {
        flux.extend_from_slice(un);
    }
    let (trouves, consommes) = au_fil(&flux).expect("il s'arrête sans se plaindre");
    assert_eq!(trouves.len(), LISTE_MAX);
    assert_eq!(consommes, LISTE_MAX * un.len());

    let (suite, _) = au_fil(&flux[consommes..]).expect("et la suite vient");
    assert_eq!(suite.len(), 5);
}

#[test]
fn un_flux_plus_long_que_le_message_maximal_est_refuse() {
    let brut = vec![b'x'; asl_proto::cadrage::MESSAGE_MAX + 1];
    assert!(matches!(au_fil(&brut), Err(Erreur::MessageTropLong { .. })));
}

#[test]
fn un_tableau_tronque_reste_une_faute() {
    // La tolérance est celle du FLUX, et elle ne déteint pas sur `elements` :
    // dans un tableau, un élément est arrivé entier ou il ne vaut rien.
    assert!(matches!(
        decouper(br#"[{"a":1},{"b":2"#),
        Err(Erreur::ListeMalFormee { .. })
    ));
    assert!(matches!(
        decouper(br#"[{"a":"sans fin"#),
        Err(Erreur::ListeMalFormee { .. })
    ));
}
