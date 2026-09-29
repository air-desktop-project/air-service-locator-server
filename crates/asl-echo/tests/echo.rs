//! Ce que l'écho refuse, ce qu'il accepte, et ce que le sondeur conclut.
//!
//! Le plan de `asl-cle` : ce qui compte n'est pas qu'une sonde juste passe,
//! c'est qu'un champ changé la fasse tomber — et que la raison rendue soit la
//! bonne. **Tout refus de l'écho est un silence** ; la raison sert au journal,
//! et un journal qui désigne la mauvaise cause est pire qu'un journal muet.

use core::net::SocketAddr;

use asl_cle::{ClePublique, CleSecrete, DomaineEcho, identifiant_de_racine};
use asl_echo::{
    ADRESSE_OCTETS, Adresse, DUREE_JETON_MS, DefiEcho, FENETRE_HORLOGE_MS, GENRE_REPONSE,
    GENRE_SONDE_ANNUAIRE, GENRE_SONDE_JETON, JETON_HEX_OCTETS, JETON_OCTETS, Jeton, MauvaisGenre,
    REPONSE_OCTETS, REQUETE_OCTETS, Refus, RefusJeton, RefusReponse, RefusRequete, RefusSonde,
    Reponse, SondeAnnuaire, SondeJeton, VERSION, VERSION_JETON, accepter, est_de_l_echo,
};
use asl_id::{Genre, Identifiant};

// ── Le décor ────────────────────────────────────────────────────────────────

const MAINTENANT: u64 = 1_789_217_751_000;

fn cle(graine: u8) -> CleSecrete {
    CleSecrete::depuis_entropie([graine; 32])
}

fn racine() -> CleSecrete {
    cle(0x11)
}

fn racine_id() -> Identifiant {
    identifiant_de_racine(&racine().publique())
}

/// L'écho : la machine sondée.
fn machine() -> CleSecrete {
    cle(0x33)
}

/// Le sondeur d'`asl ping`.
fn sondeur() -> CleSecrete {
    cle(0x44)
}

fn id(genre: Genre, marque: u8) -> Identifiant {
    Identifiant::depuis_entropie(genre, [marque; 16])
}

fn moi() -> Identifiant {
    id(Genre::Machine, 0x70)
}

fn lui() -> Identifiant {
    id(Genre::Machine, 0x80)
}

fn defi(marque: u8) -> DefiEcho {
    DefiEcho::depuis_octets([marque; 16])
}

/// Les racines que l'écho croit : une seule, `racine()`.
fn racines(n: Identifiant) -> Option<ClePublique> {
    (n == racine_id()).then(|| racine().publique())
}

fn personne(_: Identifiant) -> Option<ClePublique> {
    None
}

fn jeton_a(emis_a: u64) -> Jeton {
    Jeton::emettre(
        &racine(),
        moi(),
        machine().publique(),
        lui(),
        sondeur().publique(),
        emis_a,
    )
    .unwrap()
}

fn jeton() -> Jeton {
    jeton_a(MAINTENANT)
}

/// Un jeton signé par la racine, dont on choisit chaque champ — pour ce
/// qu'une racine n'émettrait jamais.
fn jeton_forge(cible_cle: [u8; 32], emis_a: u64, expire_a: u64) -> Jeton {
    let contenu: Vec<u8> = [
        &[VERSION_JETON][..],
        racine_id().octets(),
        moi().octets(),
        &cible_cle,
        lui().octets(),
        &sondeur().publique().octets(),
        &emis_a.to_be_bytes(),
        &expire_a.to_be_bytes(),
    ]
    .concat();
    let contenu: [u8; 129] = contenu.try_into().unwrap();
    let signature = racine().signer_echo(DomaineEcho::Jeton, &contenu);
    let mut octets = contenu.to_vec();
    octets.extend_from_slice(signature.octets());
    Jeton::lire(&octets).unwrap()
}

fn sonde_annuaire(emise_a: u64) -> SondeAnnuaire {
    SondeAnnuaire::signer(defi(1), racine_id(), moi(), emise_a, &racine()).unwrap()
}

fn source() -> SocketAddr {
    "[2001:db8::1c2d]:41877".parse().unwrap()
}

// ── Le tri de la socket du bail ─────────────────────────────────────────────

#[test]
fn le_premier_octet_trie_l_echo_du_quic() {
    for octet in 0x04..=0x0F {
        assert!(est_de_l_echo(octet), "{octet:#04x} est de l'écho");
    }
    // Un paquet QUIC v1 a toujours le bit 0x40 posé.
    for octet in [0x00, 0x03, 0x10, 0x40, 0x41, 0xC0, 0xFF] {
        assert!(!est_de_l_echo(octet), "{octet:#04x} n'est pas de l'écho");
    }
    assert!(est_de_l_echo(VERSION));
}

// ── Les adresses ────────────────────────────────────────────────────────────

#[test]
fn une_ipv4_s_enfouit_et_se_relit_en_ipv4() {
    let vue: SocketAddr = "203.0.113.7:53211".parse().unwrap();
    let adresse = Adresse::depuis_source(vue);
    let octets = adresse.octets();
    assert_eq!(&octets[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
    assert_eq!(&octets[12..16], &[203, 0, 113, 7]);
    assert_eq!(&octets[16..], &53211_u16.to_be_bytes());
    let relue = Adresse::depuis_octets(&octets).unwrap();
    assert_eq!(relue, adresse);
    assert_eq!(relue.source(), vue);
}

#[test]
fn une_ipv6_se_relit_telle_quelle_sans_portee() {
    let vue: SocketAddr = "[fe80::1%3]:6630".parse().unwrap();
    let relue = Adresse::depuis_octets(&Adresse::depuis_source(vue).octets()).unwrap();
    assert_eq!(
        relue.source(),
        "[fe80::1]:6630".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn le_port_nul_est_refuse() {
    let mut octets = Adresse::depuis_source(source()).octets();
    octets[ADRESSE_OCTETS - 2..].fill(0);
    assert_eq!(Adresse::depuis_octets(&octets), Err(Refus::PortNul));
}

// ── L'en-tête et la longueur ────────────────────────────────────────────────

#[test]
fn l_en_tete_refuse_dans_l_ordre_de_la_lecture() {
    // Rien du tout.
    assert_eq!(
        SondeAnnuaire::lire(&[]),
        Err(Refus::Longueur {
            attendue: REQUETE_OCTETS,
            obtenue: 0
        })
    );
    // Un paquet QUIC : pas de l'écho, quelle que soit sa longueur.
    assert_eq!(
        SondeAnnuaire::lire(&[0x40]),
        Err(Refus::PasDeLEcho { premier: 0x40 })
    );
    // Une version suivante, une version réservée.
    assert_eq!(
        Reponse::lire(&[0x0B, GENRE_REPONSE]),
        Err(Refus::Version { premier: 0x0B })
    );
    assert_eq!(
        Reponse::lire(&[0x04]),
        Err(Refus::Version { premier: 0x04 })
    );
    // La bonne version, et rien après.
    assert_eq!(
        Reponse::lire(&[VERSION]),
        Err(Refus::Longueur {
            attendue: REPONSE_OCTETS,
            obtenue: 1
        })
    );
    // Un autre genre.
    assert_eq!(
        Reponse::lire(&[VERSION, GENRE_SONDE_ANNUAIRE]),
        Err(Refus::Genre {
            genre: GENRE_SONDE_ANNUAIRE
        })
    );
    // Le bon genre, trop court puis trop long.
    let mut octets = sonde_annuaire(MAINTENANT).octets().to_vec();
    octets.pop();
    assert_eq!(
        SondeAnnuaire::lire(&octets),
        Err(Refus::Longueur {
            attendue: REQUETE_OCTETS,
            obtenue: REQUETE_OCTETS - 1
        })
    );
    octets.extend_from_slice(&[0, 0]);
    assert_eq!(
        SondeAnnuaire::lire(&octets),
        Err(Refus::Longueur {
            attendue: REQUETE_OCTETS,
            obtenue: REQUETE_OCTETS + 1
        })
    );
}

#[test]
fn le_bourrage_doit_etre_fait_de_zeros() {
    let mut octets = sonde_annuaire(MAINTENANT).octets();
    octets[REQUETE_OCTETS - 1] = 1;
    assert_eq!(SondeAnnuaire::lire(&octets), Err(Refus::Bourrage));

    let mut octets = SondeJeton::signer(defi(2), jeton(), &sondeur()).octets();
    octets[2 + 16 + JETON_OCTETS + 64] = 0x80;
    assert_eq!(SondeJeton::lire(&octets), Err(Refus::Bourrage));
}

#[test]
fn la_sonde_munie_d_un_jeton_refuse_son_en_tete_et_son_jeton() {
    assert_eq!(
        SondeJeton::lire(&[VERSION, GENRE_SONDE_ANNUAIRE]),
        Err(Refus::Genre {
            genre: GENRE_SONDE_ANNUAIRE
        })
    );
    let mut octets = SondeJeton::signer(defi(2), jeton(), &sondeur()).octets();
    octets[2 + 16] = 0x02;
    assert_eq!(
        SondeJeton::lire(&octets),
        Err(Refus::VersionDeJeton { version: 0x02 })
    );
}

// ── Le jeton ────────────────────────────────────────────────────────────────

#[test]
fn le_jeton_se_relit_et_dit_ce_qu_il_porte() {
    let jeton = jeton();
    let relu = Jeton::lire(&jeton.octets()).unwrap();
    assert_eq!(relu, jeton);
    assert_eq!(relu.racine(), racine_id());
    assert_eq!(relu.cible(), moi());
    assert_eq!(relu.cle_cible(), machine().publique());
    assert_eq!(relu.sondeur(), lui());
    assert_eq!(relu.cle_sondeur(), sondeur().publique());
    assert_eq!(relu.emis_a(), MAINTENANT);
    assert_eq!(relu.expire_a(), MAINTENANT + DUREE_JETON_MS);
    let hex = jeton.hex();
    assert_eq!(hex.as_str().len(), JETON_HEX_OCTETS);
    assert_eq!(format!("{hex:?}"), hex.as_str());
    assert_eq!(Jeton::lire_hex(hex.as_str()).unwrap(), jeton);
}

#[test]
fn le_jeton_refuse_ce_qui_n_est_pas_lui() {
    assert_eq!(
        Jeton::lire(&[VERSION_JETON; 3]),
        Err(Refus::Longueur {
            attendue: JETON_OCTETS,
            obtenue: 3
        })
    );
    let mut octets = jeton().octets();
    octets[0] = 0x02;
    assert_eq!(
        Jeton::depuis_octets(&octets),
        Err(Refus::VersionDeJeton { version: 0x02 })
    );

    // Trente-deux octets qui ne sont pas un point de la courbe.
    let pas_un_point = [0x02_u8; 32];
    assert!(ClePublique::depuis_octets(pas_un_point).is_err());
    let mut octets = jeton().octets();
    octets[33..65].copy_from_slice(&pas_un_point);
    assert_eq!(Jeton::depuis_octets(&octets), Err(Refus::CleInvalide));
    let mut octets = jeton().octets();
    octets[81..113].copy_from_slice(&pas_un_point);
    assert_eq!(Jeton::depuis_octets(&octets), Err(Refus::CleInvalide));
}

#[test]
fn le_jeton_en_hexadecimal_refuse_une_longueur_ou_un_chiffre() {
    assert_eq!(
        Jeton::lire_hex("00"),
        Err(Refus::Longueur {
            attendue: JETON_HEX_OCTETS,
            obtenue: 2
        })
    );
    let bon = jeton().hex();
    for (position, fautif) in [(0, 'g'), (1, 'G'), (JETON_HEX_OCTETS - 1, ' ')] {
        let mut texte: Vec<char> = bon.as_str().chars().collect();
        texte[position] = fautif;
        let texte: String = texte.into_iter().collect();
        assert_eq!(Jeton::lire_hex(&texte), Err(Refus::Hexadecimal));
    }
    // Majuscules et minuscules mêlées : le même jeton.
    let mele: String = bon
        .as_str()
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    assert_eq!(Jeton::lire_hex(&mele).unwrap(), jeton());
}

#[test]
fn le_jeton_refuse_un_identifiant_du_mauvais_genre() {
    let annuaire = id(Genre::Annuaire, 1);
    let emettre = |cible, sondeur| {
        Jeton::emettre(
            &racine(),
            cible,
            machine().publique(),
            sondeur,
            sondeur_cle(),
            MAINTENANT,
        )
    };
    assert_eq!(
        emettre(annuaire, lui()),
        Err(MauvaisGenre {
            obtenu: Genre::Annuaire
        })
    );
    assert_eq!(
        emettre(moi(), id(Genre::Utilisateur, 1)),
        Err(MauvaisGenre {
            obtenu: Genre::Utilisateur
        })
    );
}

fn sondeur_cle() -> ClePublique {
    sondeur().publique()
}

#[test]
fn l_echo_croit_un_jeton_juste_a_deux_minutes_pres() {
    let jeton = jeton();
    let ma_cle = machine().publique();
    let verifier = |maintenant| jeton.verifier(moi(), &ma_cle, &racines, maintenant);
    assert_eq!(verifier(MAINTENANT), Ok(()));
    // Expiré, mais dans la tolérance ; puis au-delà.
    let expire = jeton.expire_a();
    assert_eq!(verifier(expire + FENETRE_HORLOGE_MS), Ok(()));
    assert_eq!(
        verifier(expire + FENETRE_HORLOGE_MS + 1),
        Err(RefusJeton::Expire)
    );
    // Émis dans l'avenir de l'écho, dans la tolérance ; puis au-delà.
    assert_eq!(verifier(MAINTENANT - FENETRE_HORLOGE_MS), Ok(()));
    assert_eq!(
        verifier(MAINTENANT - FENETRE_HORLOGE_MS - 1),
        Err(RefusJeton::PasEncoreEmis)
    );
}

#[test]
fn l_echo_ne_croit_pas_un_jeton_pour_un_autre() {
    let jeton = jeton();
    let ma_cle = machine().publique();
    // Une autre machine.
    assert_eq!(
        jeton.verifier(lui(), &ma_cle, &racines, MAINTENANT),
        Err(RefusJeton::AutreCible)
    );
    // Cette machine, ré-enrôlée sous une autre clé : le jeton meurt avec
    // l'ancienne.
    assert_eq!(
        jeton.verifier(moi(), &cle(0x55).publique(), &racines, MAINTENANT),
        Err(RefusJeton::AutreCible)
    );
    // Une racine qu'il ne connaît pas.
    assert_eq!(
        jeton.verifier(moi(), &ma_cle, &personne, MAINTENANT),
        Err(RefusJeton::RacineInconnue)
    );
    // Une racine qu'il connaît, sous une autre clé.
    assert_eq!(
        jeton.verifier(moi(), &ma_cle, &|_| Some(cle(0x66).publique()), MAINTENANT),
        Err(RefusJeton::Signature)
    );
}

#[test]
fn l_echo_refuse_une_duree_qu_aucune_racine_ne_donne() {
    let ma_cle = machine().publique();
    let octets = ma_cle.octets();
    for (emis, expire) in [
        (MAINTENANT, MAINTENANT),
        (MAINTENANT, MAINTENANT - 1),
        (MAINTENANT, MAINTENANT + DUREE_JETON_MS + 1),
    ] {
        assert_eq!(
            jeton_forge(octets, emis, expire).verifier(moi(), &ma_cle, &racines, MAINTENANT),
            Err(RefusJeton::Duree),
            "émis {emis}, expire {expire}"
        );
    }
    // La durée exacte passe.
    assert_eq!(
        jeton_forge(octets, MAINTENANT, MAINTENANT + DUREE_JETON_MS).verifier(
            moi(),
            &ma_cle,
            &racines,
            MAINTENANT
        ),
        Ok(())
    );
}

#[test]
fn chaque_champ_du_jeton_est_signe() {
    let ma_cle = machine().publique();
    let bon = jeton().octets();
    // Chaque octet signé, sauf ceux dont un changement se refuse AVANT la
    // signature (la version, la cible et sa clé) ou ne forme plus une clé :
    // la racine, le sondeur et sa clé, les deux dates.
    for position in (1..17).chain(65..129) {
        let mut octets = bon;
        octets[position] ^= 0x01;
        let Ok(jeton) = Jeton::depuis_octets(&octets) else {
            continue;
        };
        let resultat = jeton.verifier(moi(), &ma_cle, &|_| Some(racine().publique()), MAINTENANT);
        assert!(
            matches!(
                resultat,
                Err(RefusJeton::Signature | RefusJeton::Duree | RefusJeton::Expire)
            ),
            "l'octet {position} du jeton n'est pas signé : {resultat:?}"
        );
    }
    // La signature elle-même.
    let mut octets = bon;
    octets[JETON_OCTETS - 1] ^= 0x01;
    let jeton = Jeton::depuis_octets(&octets).unwrap();
    assert!(!jeton.signature_tient(&racine().publique()));
}

// ── La sonde d'annuaire ─────────────────────────────────────────────────────

#[test]
fn la_sonde_d_annuaire_se_relit_et_dit_ce_qu_elle_porte() {
    let sonde = sonde_annuaire(MAINTENANT);
    let relue = SondeAnnuaire::lire(&sonde.octets()).unwrap();
    assert_eq!(relue, sonde);
    assert_eq!(relue.defi(), defi(1));
    assert_eq!(relue.annuaire(), racine_id());
    assert_eq!(relue.cible(), moi());
    assert_eq!(relue.emise_a(), MAINTENANT);
    assert!(relue.signature_tient(&racine().publique()));
    assert!(!relue.signature_tient(&machine().publique()));
}

#[test]
fn la_sonde_d_annuaire_refuse_un_identifiant_du_mauvais_genre() {
    assert_eq!(
        SondeAnnuaire::signer(defi(1), moi(), moi(), MAINTENANT, &racine()),
        Err(MauvaisGenre {
            obtenu: Genre::Machine
        })
    );
    assert_eq!(
        SondeAnnuaire::signer(defi(1), racine_id(), racine_id(), MAINTENANT, &racine()),
        Err(MauvaisGenre {
            obtenu: Genre::Annuaire
        })
    );
}

#[test]
fn l_echo_accepte_la_sonde_de_son_annuaire_a_deux_minutes_pres() {
    for emise_a in [
        MAINTENANT,
        MAINTENANT - FENETRE_HORLOGE_MS,
        MAINTENANT + FENETRE_HORLOGE_MS,
    ] {
        let acceptee = sonde_annuaire(emise_a)
            .accepter(moi(), &racines, MAINTENANT)
            .unwrap();
        assert_eq!(acceptee.defi(), defi(1));
        assert_eq!(acceptee.sondeur(), racine_id());
    }
}

#[test]
fn l_echo_se_tait_devant_une_sonde_d_annuaire_qu_il_ne_croit_pas() {
    let sonde = sonde_annuaire(MAINTENANT);
    assert_eq!(
        sonde.accepter(lui(), &racines, MAINTENANT),
        Err(RefusSonde::AutreCible)
    );
    assert_eq!(
        sonde.accepter(moi(), &personne, MAINTENANT),
        Err(RefusSonde::AnnuaireInconnu)
    );
    assert_eq!(
        sonde.accepter(moi(), &|_| Some(cle(0x66).publique()), MAINTENANT),
        Err(RefusSonde::Signature)
    );
    // Authentique, mais hors de la fenêtre : c'est l'horloge qui dérive.
    for emise_a in [
        MAINTENANT - FENETRE_HORLOGE_MS - 1,
        MAINTENANT + FENETRE_HORLOGE_MS + 1,
    ] {
        assert_eq!(
            sonde_annuaire(emise_a).accepter(moi(), &racines, MAINTENANT),
            Err(RefusSonde::HorsFenetre)
        );
    }
}

#[test]
fn chaque_champ_de_la_sonde_d_annuaire_est_signe() {
    let bon = sonde_annuaire(MAINTENANT).octets();
    // Le défi, l'annuaire (dont la clé est cherchée par un tricheur qui la
    // rend quand même), la date — et la signature elle-même.
    for position in (2..34).chain(50..58).chain(58..122) {
        let mut octets = bon;
        octets[position] ^= 0x01;
        let sonde = SondeAnnuaire::lire(&octets).unwrap();
        assert!(
            !sonde.signature_tient(&racine().publique()),
            "l'octet {position} de la sonde n'est pas signé"
        );
    }
}

// ── La sonde munie d'un jeton ───────────────────────────────────────────────

#[test]
fn la_sonde_munie_d_un_jeton_se_relit() {
    let sonde = SondeJeton::signer(defi(2), jeton(), &sondeur());
    let relue = SondeJeton::lire(&sonde.octets()).unwrap();
    assert_eq!(relue, sonde);
    assert_eq!(relue.defi(), defi(2));
    assert_eq!(relue.jeton(), &jeton());
    assert!(relue.signature_tient());
}

#[test]
fn l_echo_accepte_le_porteur_du_jeton_et_de_sa_cle() {
    let sonde = SondeJeton::signer(defi(2), jeton(), &sondeur());
    let acceptee = sonde
        .accepter(moi(), &machine().publique(), &racines, MAINTENANT)
        .unwrap();
    assert_eq!(acceptee.sondeur(), lui());
    assert_eq!(acceptee.defi(), defi(2));
}

#[test]
fn un_jeton_intercepte_ne_sert_a_rien_sans_la_cle_qu_il_nomme() {
    // Un tiers a lu le jeton sur le fil, et signe avec SA clé.
    let volee = SondeJeton::signer(defi(2), jeton(), &cle(0x77));
    assert_eq!(
        volee.accepter(moi(), &machine().publique(), &racines, MAINTENANT),
        Err(RefusSonde::SignatureDuSondeur)
    );
    // Et un jeton que l'écho ne croit pas n'est pas sauvé par une bonne
    // signature.
    let sonde = SondeJeton::signer(defi(2), jeton(), &sondeur());
    assert_eq!(
        sonde.accepter(moi(), &machine().publique(), &personne, MAINTENANT),
        Err(RefusSonde::Jeton(RefusJeton::RacineInconnue))
    );
    // Le défi est signé : un défi changé en chemin ne vérifie plus.
    let mut octets = sonde.octets();
    octets[2] ^= 0x01;
    assert!(!SondeJeton::lire(&octets).unwrap().signature_tient());
}

// ── L'écho, d'un datagramme à sa décision ───────────────────────────────────

#[test]
fn l_echo_decide_d_un_datagramme_quelle_que_soit_la_sonde() {
    let ma_cle = machine().publique();
    let annuaire = sonde_annuaire(MAINTENANT).octets();
    let par_jeton = SondeJeton::signer(defi(2), jeton(), &sondeur()).octets();

    let acceptee = accepter(&annuaire, moi(), &ma_cle, &racines, &personne, MAINTENANT).unwrap();
    assert_eq!(acceptee.sondeur(), racine_id());
    let acceptee = accepter(&par_jeton, moi(), &ma_cle, &personne, &racines, MAINTENANT).unwrap();
    assert_eq!(acceptee.sondeur(), lui());

    // Chacune sous la règle qui lui revient : l'annuaire du bail ne délivre
    // pas de jeton, et une racine qui sonde n'est pas crue comme émettrice.
    assert_eq!(
        accepter(&annuaire, moi(), &ma_cle, &personne, &racines, MAINTENANT),
        Err(RefusRequete::Refusee(RefusSonde::AnnuaireInconnu))
    );
    assert_eq!(
        accepter(&par_jeton, moi(), &ma_cle, &racines, &personne, MAINTENANT),
        Err(RefusRequete::Refusee(RefusSonde::Jeton(
            RefusJeton::RacineInconnue
        )))
    );

    // Illisibles : une réponse, une sonde tronquée de chaque genre.
    let reponse = acceptee.repondre(source(), &machine()).octets();
    assert_eq!(
        accepter(&reponse, moi(), &ma_cle, &racines, &racines, MAINTENANT),
        Err(RefusRequete::Illisible(Refus::Genre {
            genre: GENRE_REPONSE
        }))
    );
    assert_eq!(
        accepter(
            &par_jeton[..200],
            moi(),
            &ma_cle,
            &racines,
            &racines,
            MAINTENANT
        ),
        Err(RefusRequete::Illisible(Refus::Longueur {
            attendue: REQUETE_OCTETS,
            obtenue: 200
        }))
    );
    assert_eq!(
        accepter(
            &[VERSION, GENRE_SONDE_JETON],
            moi(),
            &ma_cle,
            &racines,
            &racines,
            MAINTENANT
        ),
        Err(RefusRequete::Illisible(Refus::Longueur {
            attendue: REQUETE_OCTETS,
            obtenue: 2
        }))
    );
}

// ── La réponse ──────────────────────────────────────────────────────────────

#[test]
fn la_reponse_se_relit_et_se_verifie() {
    let acceptee = SondeJeton::signer(defi(2), jeton(), &sondeur())
        .accepter(moi(), &machine().publique(), &racines, MAINTENANT)
        .unwrap();
    let reponse = acceptee.repondre(source(), &machine());
    let relue = Reponse::lire(&reponse.octets()).unwrap();
    assert_eq!(relue, reponse);
    assert_eq!(relue.defi(), defi(2));
    assert_eq!(relue.machine(), moi());
    assert_eq!(relue.adresse().source(), source());
    assert_eq!(relue.sondeur(), lui().octets());
    assert_eq!(
        relue.verifier(&defi(2), moi(), lui(), &jeton().cle_cible()),
        Ok(())
    );
}

#[test]
fn le_sondeur_dit_pourquoi_une_reponse_ne_prouve_rien() {
    let reponse = Reponse::signer(
        defi(2),
        moi(),
        Adresse::depuis_source(source()),
        lui(),
        &machine(),
    )
    .unwrap();
    let ma = machine().publique();
    assert_eq!(
        reponse.verifier(&defi(3), moi(), lui(), &ma),
        Err(RefusReponse::AutreDefi)
    );
    // Une preuve faite pour un autre ne se présente pas comme la sienne.
    assert_eq!(
        reponse.verifier(&defi(2), moi(), racine_id(), &ma),
        Err(RefusReponse::AutreSondeur)
    );
    assert_eq!(
        reponse.verifier(&defi(2), id(Genre::Machine, 0x99), lui(), &ma),
        Err(RefusReponse::AutreMachine)
    );
    // Quelqu'un d'autre répond à cette adresse : une autre clé.
    assert_eq!(
        reponse.verifier(&defi(2), moi(), lui(), &cle(0x66).publique()),
        Err(RefusReponse::Signature)
    );
}

#[test]
fn chaque_champ_de_la_reponse_est_signe() {
    let reponse = Reponse::signer(
        defi(2),
        moi(),
        Adresse::depuis_source(source()),
        lui(),
        &machine(),
    )
    .unwrap();
    let bon = reponse.octets();
    for position in 2..REPONSE_OCTETS {
        let mut octets = bon;
        octets[position] ^= 0x01;
        let Ok(relue) = Reponse::lire(&octets) else {
            continue;
        };
        assert!(
            !relue.signature_tient(&machine().publique()),
            "l'octet {position} de la réponse n'est pas signé"
        );
    }
}

#[test]
fn la_reponse_refuse_un_port_nul_et_un_mauvais_genre() {
    let mut octets = Reponse::signer(
        defi(2),
        moi(),
        Adresse::depuis_source(source()),
        lui(),
        &machine(),
    )
    .unwrap()
    .octets();
    octets[2 + 16 + 16 + 16..2 + 16 + 16 + 18].fill(0);
    assert_eq!(Reponse::lire(&octets), Err(Refus::PortNul));

    let adresse = Adresse::depuis_source(source());
    assert_eq!(
        Reponse::signer(defi(2), racine_id(), adresse, lui(), &machine()),
        Err(MauvaisGenre {
            obtenu: Genre::Annuaire
        })
    );
    assert_eq!(
        Reponse::signer(defi(2), moi(), adresse, id(Genre::Service, 1), &machine()),
        Err(MauvaisGenre {
            obtenu: Genre::Service
        })
    );
    // Un annuaire sondeur est admis.
    assert!(Reponse::signer(defi(2), moi(), adresse, racine_id(), &machine()).is_ok());
}

// ── Pas d'amplification ─────────────────────────────────────────────────────

#[test]
fn une_reponse_est_toujours_plus_petite_qu_une_requete() {
    const { assert!(REPONSE_OCTETS < REQUETE_OCTETS) };
    assert_eq!(sonde_annuaire(MAINTENANT).octets().len(), REQUETE_OCTETS);
    assert_eq!(
        SondeJeton::signer(defi(2), jeton(), &sondeur())
            .octets()
            .len(),
        REQUETE_OCTETS
    );
}
