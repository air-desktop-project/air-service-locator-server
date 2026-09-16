//! L'ensemble accepte, et chacun des pas refuse — sur une chaîne fabriquée
//! sous la racine du banc.

mod forge;

use asl_keystore::{Demarrage, Niveau, Origine, Refus, case, description, verifier, x509};
use forge::{
    Banc, Cle, Condensat, EMPREINTE, PAQUET, Portrait, application, certificat, champ, entier,
    extensions_de_feuille, nul, racine_de_confiance,
};

/// Vérifie ce portrait sur la chaîne du banc.
fn verdict_de(banc: &Banc, portrait: &Portrait) -> Result<asl_keystore::Verdict, Refus> {
    let cle = banc.appareil.compresse();
    let racines = [banc.racine_der.as_slice()];
    verifier(&banc.case(portrait), &banc.attendu(&racines, &cle))
}

#[test]
fn une_chaine_coherente_certifie_la_cle_de_l_appareil() {
    let banc = Banc::nouveau();
    let portrait = Portrait::coherent(&banc.defi);
    let verdict = verdict_de(&banc, &portrait).unwrap_or_else(|refus| panic!("{refus}"));
    assert_eq!(&verdict.cle[..], &banc.appareil.point()[..]);
    assert_eq!(x509::compresser(&verdict.cle), banc.appareil.compresse());
    assert_eq!(verdict.niveau_attestation, Niveau::EnvironnementDeConfiance);
    assert_eq!(verdict.niveau_keymaster, Niveau::EnvironnementDeConfiance);
    assert_eq!(verdict.version, 3);
    assert_eq!(verdict.version_keymaster, 41);
    assert_eq!(verdict.version_os, Some(150_000));
    assert_eq!(verdict.correctif_os, Some(202_608));
    assert_eq!(verdict.correctif_fabricant, Some(20_260_805));
    assert_eq!(verdict.correctif_demarrage, Some(20_260_805));
    assert_eq!(verdict.version_du_paquet, 6);
    // Et le verdict se copie et se compare.
    assert_eq!(verdict.clone(), verdict);
}

#[test]
fn strongbox_vaut_le_tee_et_les_correctifs_se_lisent_aussi_cote_logiciel() {
    let banc = Banc::nouveau();
    let mut portrait = Portrait::coherent(&banc.defi);
    portrait.niveau_attestation = 2;
    portrait.niveau_keymaster = 2;
    // Les correctifs déplacés côté logiciel — un autre fabricant pourrait
    // les mettre là — se rendent quand même.
    let portrait = portrait
        .sans_materiel(705)
        .sans_materiel(706)
        .sans_materiel(718)
        .sans_materiel(719)
        .avec_logiciel(705, &entier(140_000))
        .avec_logiciel(706, &entier(202_507));
    let verdict = verdict_de(&banc, &portrait).unwrap_or_else(|refus| panic!("{refus}"));
    assert_eq!(verdict.niveau_attestation, Niveau::StrongBox);
    assert_eq!(verdict.niveau_keymaster, Niveau::StrongBox);
    assert_eq!(verdict.version_os, Some(140_000));
    assert_eq!(verdict.correctif_os, Some(202_507));
    assert_eq!(verdict.correctif_fabricant, None);
    assert_eq!(verdict.correctif_demarrage, None);
}

#[test]
fn l_application_se_lit_cote_materiel_a_defaut_du_logiciel() {
    let banc = Banc::nouveau();
    let portrait = Portrait::coherent(&banc.defi)
        .sans_logiciel(709)
        .avec_materiel(709, &application(&[(PAQUET, 7)], &[&EMPREINTE]));
    let verdict = verdict_de(&banc, &portrait).unwrap_or_else(|refus| panic!("{refus}"));
    assert_eq!(verdict.version_du_paquet, 7);
}

#[test]
fn notre_paquet_et_notre_empreinte_suffisent_parmi_d_autres() {
    let banc = Banc::nouveau();
    let portrait = Portrait::coherent(&banc.defi).avec_logiciel(
        709,
        &application(
            &[("org.autre.app", 1), (PAQUET, 8)],
            &[&[0x11; 32], &EMPREINTE],
        ),
    );
    let verdict = verdict_de(&banc, &portrait).unwrap_or_else(|refus| panic!("{refus}"));
    assert_eq!(verdict.version_du_paquet, 8);
}

#[test]
fn une_case_illisible_est_refusee_avec_sa_faute() {
    let banc = Banc::nouveau();
    let cle = banc.appareil.compresse();
    let racines = [banc.racine_der.as_slice()];
    assert_eq!(
        verifier(&[], &banc.attendu(&racines, &cle)),
        Err(Refus::Case(case::Faute::Vide))
    );
    assert_eq!(
        verifier(&[0x00, 0x05, 0x01], &banc.attendu(&racines, &cle)),
        Err(Refus::Case(case::Faute::Tronquee {
            rang: 0,
            annoncee: 5,
            restant: 1
        }))
    );
}

#[test]
fn sans_racine_ou_avec_une_racine_illisible_rien_ne_remonte() {
    let banc = Banc::nouveau();
    let cle = banc.appareil.compresse();
    let case = banc.case(&Portrait::coherent(&banc.defi));
    assert_eq!(
        verifier(&case, &banc.attendu(&[], &cle)),
        Err(Refus::SansRacine)
    );
    let racines: [&[u8]; 2] = [&banc.racine_der, b"pas un certificat"];
    assert_eq!(
        verifier(&case, &banc.attendu(&racines, &cle)),
        Err(Refus::RacineIllisible)
    );
}

#[test]
fn plusieurs_racines_et_la_bonne_n_est_pas_la_premiere() {
    let banc = Banc::nouveau();
    let autre = Banc::nouveau_sous(&[0x99; 32]);
    let cle = banc.appareil.compresse();
    let case = banc.case(&Portrait::coherent(&banc.defi));
    let racines = [autre.racine_der.as_slice(), banc.racine_der.as_slice()];
    verifier(&case, &banc.attendu(&racines, &cle)).expect("la seconde racine ancre");
    // Sous l'autre seule : rien. Elle porte le même nom que la nôtre, et
    // c'est la signature qui la démasque, pas le nom.
    let racines = [autre.racine_der.as_slice()];
    assert!(matches!(
        verifier(&case, &banc.attendu(&racines, &cle)),
        Err(Refus::Chaine(_))
    ));
}

#[test]
fn une_feuille_que_webpki_ne_lit_pas_est_refusee() {
    let banc = Banc::nouveau();
    let cle = banc.appareil.compresse();
    let racines = [banc.racine_der.as_slice()];
    let case = case::assembler(&[&[0x30, 0x00], &banc.tee_der]).expect("la case tient");
    assert_eq!(
        verifier(&case, &banc.attendu(&racines, &cle)),
        Err(Refus::FeuilleIllisible)
    );
}

#[test]
fn sans_intermediaire_ou_hors_validite_la_chaine_ne_remonte_pas() {
    let banc = Banc::nouveau();
    let cle = banc.appareil.compresse();
    let racines = [banc.racine_der.as_slice()];
    let feuille = banc.feuille(&Portrait::coherent(&banc.defi));
    let seule = case::assembler(&[&feuille]).expect("la case tient");
    assert!(matches!(
        verifier(&seule, &banc.attendu(&racines, &cle)),
        Err(Refus::Chaine(_))
    ));
    let mut avant = banc.attendu(&racines, &cle);
    avant.maintenant = 0;
    assert!(matches!(
        verifier(&banc.case_de(&feuille), &avant),
        Err(Refus::Chaine(webpki::Error::CertNotValidYet { .. }))
    ));
}

#[test]
fn la_racine_dans_la_case_est_sans_effet() {
    let banc = Banc::nouveau();
    let cle = banc.appareil.compresse();
    let racines = [banc.racine_der.as_slice()];
    let feuille = banc.feuille(&Portrait::coherent(&banc.defi));
    let entiere = case::assembler(&[
        &feuille,
        &banc.tee_der,
        &banc.intermediaire_der,
        &banc.racine_der,
    ])
    .expect("la case tient");
    let avec = verifier(&entiere, &banc.attendu(&racines, &cle)).expect("racine comprise");
    let sans =
        verifier(&banc.case_de(&feuille), &banc.attendu(&racines, &cle)).expect("racine omise");
    assert_eq!(avec, sans);
}

#[test]
fn une_feuille_bien_signee_mais_mal_formee_est_refusee() {
    // `webpki` accepte ce certificat — la signature est bonne —, mais notre
    // marcheur n'y trouve pas de clé P-256 : la clé est P-384.
    let banc = Banc::nouveau();
    let cle = banc.appareil.compresse();
    let racines = [banc.racine_der.as_slice()];
    let p384 = Cle::p384(&[0x55; 48]);
    let feuille = banc.feuille_de(&p384, Some(&Portrait::coherent(&banc.defi).encoder()));
    assert_eq!(
        verifier(&banc.case_de(&feuille), &banc.attendu(&racines, &cle)),
        Err(Refus::CleInattendue)
    );
}

#[test]
fn sans_extension_ou_avec_une_extension_illisible_rien_n_est_atteste() {
    let banc = Banc::nouveau();
    let cle = banc.appareil.compresse();
    let racines = [banc.racine_der.as_slice()];
    let sans = banc.feuille_de(&banc.appareil, None);
    assert_eq!(
        verifier(&banc.case_de(&sans), &banc.attendu(&racines, &cle)),
        Err(Refus::DescriptionAbsente)
    );
    let illisible = banc.feuille_de(&banc.appareil, Some(&[0x30, 0x01, 0xFF]));
    assert!(matches!(
        verifier(&banc.case_de(&illisible), &banc.attendu(&racines, &cle)),
        Err(Refus::DescriptionIllisible(description::Faute::Der(_)))
    ));
}

#[test]
fn une_autre_cle_ou_un_autre_defi_est_refuse() {
    let banc = Banc::nouveau();
    let racines = [banc.racine_der.as_slice()];
    let case = banc.case(&Portrait::coherent(&banc.defi));
    let autre_cle = Cle::p256(&[0x66; 32]).compresse();
    assert_eq!(
        verifier(&case, &banc.attendu(&racines, &autre_cle)),
        Err(Refus::CleDifferente)
    );
    let mut portrait = Portrait::coherent(&banc.defi);
    portrait.defi = b"un autre defi".to_vec();
    assert_eq!(verdict_de(&banc, &portrait), Err(Refus::DefiDifferent));
}

#[test]
fn une_attestation_ou_une_cle_logicielle_est_refusee() {
    let banc = Banc::nouveau();
    let mut portrait = Portrait::coherent(&banc.defi);
    portrait.niveau_attestation = 0;
    assert_eq!(
        verdict_de(&banc, &portrait),
        Err(Refus::AttestationLogicielle(Niveau::Logiciel))
    );
    let mut portrait = Portrait::coherent(&banc.defi);
    portrait.niveau_keymaster = 7;
    assert_eq!(
        verdict_de(&banc, &portrait),
        Err(Refus::CleLogicielle(Niveau::Autre(7)))
    );
}

#[test]
fn un_demarrage_qui_n_est_pas_verifie_et_verrouille_est_refuse() {
    let banc = Banc::nouveau();
    let portrait = Portrait::coherent(&banc.defi).sans_materiel(704);
    assert_eq!(
        verdict_de(&banc, &portrait),
        Err(Refus::RacineDeConfianceAbsente)
    );
    for (etat, attendu) in [
        (1, Demarrage::AutoSigne),
        (2, Demarrage::NonVerifie),
        (3, Demarrage::Echec),
        (9, Demarrage::Autre(9)),
    ] {
        let portrait =
            Portrait::coherent(&banc.defi).avec_materiel(704, &racine_de_confiance(true, etat));
        assert_eq!(
            verdict_de(&banc, &portrait),
            Err(Refus::DemarrageNonVerifie(attendu))
        );
    }
    let portrait =
        Portrait::coherent(&banc.defi).avec_materiel(704, &racine_de_confiance(false, 0));
    assert_eq!(
        verdict_de(&banc, &portrait),
        Err(Refus::AppareilDeverrouille)
    );
    // Un `rootOfTrust` côté logiciel ne compte pas.
    let portrait = Portrait::coherent(&banc.defi)
        .sans_materiel(704)
        .avec_logiciel(704, &racine_de_confiance(true, 0));
    assert_eq!(
        verdict_de(&banc, &portrait),
        Err(Refus::RacineDeConfianceAbsente)
    );
}

#[test]
fn une_cle_qui_n_est_pas_nee_dans_le_materiel_est_refusee() {
    let banc = Banc::nouveau();
    let portrait = Portrait::coherent(&banc.defi).sans_materiel(702);
    assert_eq!(verdict_de(&banc, &portrait), Err(Refus::OrigineAbsente));
    for (origine, attendu) in [
        (1, Origine::Derivee),
        (2, Origine::Importee),
        (3, Origine::Reservee),
        (4, Origine::ImporteeSurement),
        (5, Origine::Autre(5)),
    ] {
        let portrait = Portrait::coherent(&banc.defi).avec_materiel(702, &entier(origine));
        assert_eq!(
            verdict_de(&banc, &portrait),
            Err(Refus::OrigineInattendue(attendu))
        );
    }
}

#[test]
fn une_autre_app_est_refusee() {
    let banc = Banc::nouveau();
    let portrait = Portrait::coherent(&banc.defi).sans_logiciel(709);
    assert_eq!(verdict_de(&banc, &portrait), Err(Refus::ApplicationAbsente));
    let portrait = Portrait::coherent(&banc.defi)
        .avec_logiciel(709, &application(&[("org.autre.app", 6)], &[&EMPREINTE]));
    assert_eq!(verdict_de(&banc, &portrait), Err(Refus::AutrePaquet));
    let portrait = Portrait::coherent(&banc.defi)
        .avec_logiciel(709, &application(&[(PAQUET, 6)], &[&[0x11; 32]]));
    assert_eq!(verdict_de(&banc, &portrait), Err(Refus::AutreSignataire));
    // Un paquet sans aucune empreinte : personne ne l'a signé.
    let portrait =
        Portrait::coherent(&banc.defi).avec_logiciel(709, &application(&[(PAQUET, 6)], &[]));
    assert_eq!(verdict_de(&banc, &portrait), Err(Refus::AutreSignataire));
}

#[test]
fn les_balises_inconnues_sont_sautees_et_le_verdict_tient() {
    let banc = Banc::nouveau();
    let portrait = Portrait::coherent(&banc.defi)
        .avec_materiel(720, &nul())
        .avec_materiel(724, &entier(1))
        .avec_logiciel(4242, &champ(1, &entier(1)));
    verdict_de(&banc, &portrait).expect("ce qu'on ne connaît pas ne pèse pas");
}

#[test]
fn chaque_refus_se_dit_en_francais() {
    for refus in [
        Refus::Case(case::Faute::Vide),
        Refus::SansRacine,
        Refus::RacineIllisible,
        Refus::FeuilleIllisible,
        Refus::Chaine(webpki::Error::UnknownIssuer),
        Refus::CertificatIllisible,
        Refus::CleInattendue,
        Refus::DescriptionAbsente,
        Refus::DescriptionIllisible(description::Faute::Surplus),
        Refus::CleDifferente,
        Refus::DefiDifferent,
        Refus::AttestationLogicielle(Niveau::Logiciel),
        Refus::CleLogicielle(Niveau::Autre(3)),
        Refus::RacineDeConfianceAbsente,
        Refus::DemarrageNonVerifie(Demarrage::NonVerifie),
        Refus::AppareilDeverrouille,
        Refus::OrigineAbsente,
        Refus::OrigineInattendue(Origine::Importee),
        Refus::ApplicationAbsente,
        Refus::AutrePaquet,
        Refus::AutreSignataire,
    ] {
        let dit = refus.to_string();
        assert!(!dit.is_empty(), "{refus:?}");
        assert_eq!(refus.clone(), refus);
    }
    for niveau in [
        Niveau::Logiciel,
        Niveau::EnvironnementDeConfiance,
        Niveau::StrongBox,
        Niveau::Autre(4),
    ] {
        assert!(!niveau.to_string().is_empty());
    }
    for demarrage in [
        Demarrage::Verifie,
        Demarrage::AutoSigne,
        Demarrage::NonVerifie,
        Demarrage::Echec,
        Demarrage::Autre(4),
    ] {
        assert!(!demarrage.to_string().is_empty());
    }
    for origine in [
        Origine::Generee,
        Origine::Derivee,
        Origine::Importee,
        Origine::Reservee,
        Origine::ImporteeSurement,
        Origine::Autre(9),
    ] {
        assert!(!origine.to_string().is_empty());
    }
}

#[test]
fn une_feuille_sans_version_ni_extension_se_lit_comme_un_certificat_v1() {
    // Le marcheur accepte un certificat sans `[0] version` : pas de clé
    // attestée pour autant, faute d'extension — mais la forme est lue.
    let banc = Banc::nouveau();
    let feuille = certificat(
        9,
        "TEE du banc",
        "v1",
        &banc.appareil,
        &banc.tee,
        Condensat::Sha256,
        &extensions_de_feuille(None),
    );
    // Retire `[0] { INTEGER 2 }` — cinq octets en tête du TBS — et réécrit
    // les longueurs, pour un TBS de forme v1.
    let sans_version = forge::sans_version(&feuille);
    let lue = x509::lire(&sans_version).expect("un certificat v1 se lit");
    assert_eq!(lue.description, None);
    assert_eq!(lue.cle, &banc.appareil.point()[..]);
}
