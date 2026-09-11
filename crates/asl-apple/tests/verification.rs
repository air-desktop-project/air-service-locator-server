//! Chacun des neuf pas refuse, et l'ensemble accepte.

mod forge;

use asl_apple::{
    AAGUID_DEVELOPPEMENT, AAGUID_PRODUCTION, Attendu, Certifie, Environnement, RACINE_APPLE, Refus,
    verifier,
};
use forge::{Banc, IDENTIFIANT_APP, PENDANT, attestation, piece};
use sha2::{Digest, Sha256};

fn attendu<'a>(banc: &'a Banc) -> Attendu<'a> {
    Attendu {
        racine: &banc.racine,
        defi: &banc.defi,
        identifiant_app: IDENTIFIANT_APP,
        environnement: Environnement::Developpement,
        maintenant: PENDANT,
    }
}

#[test]
fn une_attestation_coherente_certifie_la_cle_de_la_feuille() {
    let banc = Banc::charger();
    let certifie = verifier(&banc.objet(), &attendu(&banc)).expect("tout est cohérent");
    assert_eq!(&certifie.cle[..], &banc.cle[..]);
    assert_eq!(
        &certifie.identifiant[..],
        Sha256::digest(&banc.cle).as_slice()
    );
    assert_eq!(
        certifie,
        Certifie {
            cle: banc.cle.as_slice().try_into().expect("65 octets"),
            identifiant: Sha256::digest(&banc.cle).into(),
        }
    );
}

#[test]
fn la_meme_feuille_passe_aussi_par_une_intermediaire_p256() {
    // Exerce le vérificateur ECDSA P-256 sur une signature de CERTIFICAT, et
    // pas seulement sur la clé de la feuille.
    let banc = Banc::charger();
    let objet = attestation(
        &[
            &piece("feuille-via-p256.der"),
            &piece("intermediaire-p256.der"),
        ],
        &banc.auth,
    );
    verifier(&objet, &attendu(&banc)).expect("la chaîne P-256 remonte aussi");
}

#[test]
fn des_octets_qui_ne_sont_pas_une_attestation_sont_une_faute_de_grammaire() {
    let banc = Banc::charger();
    assert!(matches!(
        verifier(&[0xff], &attendu(&banc)),
        Err(Refus::Grammaire(_))
    ));
}

#[test]
fn sans_le_drapeau_atteste_il_n_y_a_rien_a_certifier() {
    let banc = Banc::charger();
    let mut auth = banc.auth[..37].to_vec();
    auth[32] = 0;
    let objet = attestation(&[&banc.feuille, &banc.intermediaire], &auth);
    assert_eq!(
        verifier(&objet, &attendu(&banc)),
        Err(Refus::PasDeCleAttestee)
    );
}

#[test]
fn un_compteur_non_nul_n_est_pas_une_premiere_signature() {
    let banc = Banc::charger();
    let mut auth = banc.auth.clone();
    auth[36] = 1;
    let objet = attestation(&[&banc.feuille, &banc.intermediaire], &auth);
    assert_eq!(
        verifier(&objet, &attendu(&banc)),
        Err(Refus::Compteur { compteur: 1 })
    );
}

#[test]
fn une_attestation_de_developpement_est_refusee_en_production() {
    let banc = Banc::charger();
    let mut attendu = attendu(&banc);
    attendu.environnement = Environnement::Production;
    assert_eq!(verifier(&banc.objet(), &attendu), Err(Refus::Environnement));
    assert_eq!(Environnement::Production.aaguid(), AAGUID_PRODUCTION);
    assert_eq!(Environnement::Developpement.aaguid(), AAGUID_DEVELOPPEMENT);
}

#[test]
fn une_autre_app_est_refusee() {
    let banc = Banc::charger();
    let mut attendu = attendu(&banc);
    attendu.identifiant_app = "ABCDE12345.ch.narro.autre";
    assert_eq!(verifier(&banc.objet(), &attendu), Err(Refus::App));
}

#[test]
fn une_chaine_vide_ne_remonte_nulle_part() {
    let banc = Banc::charger();
    let objet = attestation(&[], &banc.auth);
    assert_eq!(verifier(&objet, &attendu(&banc)), Err(Refus::ChaineVide));
}

#[test]
fn une_racine_qui_n_est_pas_un_certificat_est_refusee() {
    let banc = Banc::charger();
    let mut attendu = attendu(&banc);
    attendu.racine = &[0x30, 0x00];
    assert_eq!(
        verifier(&banc.objet(), &attendu),
        Err(Refus::RacineIllisible)
    );
}

#[test]
fn une_feuille_qui_n_est_pas_un_certificat_est_refusee() {
    let banc = Banc::charger();
    let objet = attestation(&[&[0x30, 0x00], &banc.intermediaire], &banc.auth);
    assert_eq!(
        verifier(&objet, &attendu(&banc)),
        Err(Refus::FeuilleIllisible)
    );
}

#[test]
fn une_autre_racine_ne_reconnait_pas_la_chaine() {
    let banc = Banc::charger();
    let autre = piece("autre-racine.der");
    let mut attendu = attendu(&banc);
    attendu.racine = &autre;
    assert!(matches!(
        verifier(&banc.objet(), &attendu),
        Err(Refus::Chaine(_))
    ));
}

#[test]
fn la_vraie_racine_d_apple_se_lit_et_ne_reconnait_pas_le_banc() {
    // On ne peut pas éprouver une chaîne d'Apple. On peut éprouver que sa
    // racine est bien celle qu'Apple publie, et qu'elle sert d'ancre.
    assert_eq!(
        hex(&Sha256::digest(RACINE_APPLE)),
        "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"
    );
    let banc = Banc::charger();
    let mut attendu = attendu(&banc);
    attendu.racine = RACINE_APPLE;
    assert!(matches!(
        verifier(&banc.objet(), &attendu),
        Err(Refus::Chaine(_))
    ));
}

#[test]
fn la_validite_s_apprecie_a_l_instant_donne() {
    let banc = Banc::charger();
    for (quand, pourquoi) in [(0, "avant"), (5_000_000_000, "après")] {
        let mut attendu = attendu(&banc);
        attendu.maintenant = quand;
        assert!(
            matches!(verifier(&banc.objet(), &attendu), Err(Refus::Chaine(_))),
            "{pourquoi} la validité"
        );
    }
}

#[test]
fn sans_l_intermediaire_la_feuille_ne_remonte_pas() {
    let banc = Banc::charger();
    let objet = attestation(&[&banc.feuille], &banc.auth);
    assert!(matches!(
        verifier(&objet, &attendu(&banc)),
        Err(Refus::Chaine(_))
    ));
}

#[test]
fn au_plus_trois_intermediaires_sont_regardees() {
    // `asl-attest` borne `x5c` à quatre certificats : une feuille et trois
    // intermédiaires, jamais plus. La borne d'ici (trois cases, sans tas) est
    // donc exactement celle de la grammaire, et un cinquième certificat est
    // une faute de GRAMMAIRE avant d'être quoi que ce soit d'autre.
    let banc = Banc::charger();
    let objet = attestation(
        &[
            &banc.feuille,
            &banc.intermediaire,
            &banc.intermediaire,
            &banc.intermediaire,
            &banc.intermediaire,
        ],
        &banc.auth,
    );
    assert_eq!(
        verifier(&objet, &attendu(&banc)),
        Err(Refus::Grammaire(asl_attest::Erreur::TropDeCertificats {
            annonces: 5
        }))
    );
    let objet = attestation(
        &[
            &banc.feuille,
            &banc.intermediaire,
            &banc.intermediaire,
            &banc.intermediaire,
        ],
        &banc.auth,
    );
    verifier(&objet, &attendu(&banc)).expect("trois intermédiaires, dont la bonne");
}

#[test]
fn une_cle_hors_de_p256_est_refusee() {
    let banc = Banc::charger();
    let objet = attestation(
        &[&piece("feuille-p384.der"), &banc.intermediaire],
        &banc.auth,
    );
    assert_eq!(verifier(&objet, &attendu(&banc)), Err(Refus::CleInattendue));
}

#[test]
fn une_feuille_sans_l_extension_d_apple_est_refusee() {
    let banc = Banc::charger();
    let objet = attestation(
        &[&piece("feuille-sans-nonce.der"), &banc.intermediaire],
        &banc.auth,
    );
    assert_eq!(verifier(&objet, &attendu(&banc)), Err(Refus::NonceAbsent));
}

#[test]
fn un_autre_defi_donne_un_autre_nonce() {
    let banc = Banc::charger();
    let mut attendu = attendu(&banc);
    attendu.defi = b"un autre";
    assert_eq!(
        verifier(&banc.objet(), &attendu),
        Err(Refus::NonceDifferent)
    );
}

#[test]
fn un_identifiant_qui_n_est_pas_l_empreinte_de_la_cle_est_refuse() {
    // La feuille est bien signée, le nonce couvre bien ces données — mais ces
    // données nomment une clé qui n'est pas celle du certificat.
    let banc = Banc::charger();
    let objet = attestation(
        &[&piece("feuille-identifiant-faux.der"), &banc.intermediaire],
        &piece("auth-data-identifiant-faux.bin"),
    );
    assert_eq!(
        verifier(&objet, &attendu(&banc)),
        Err(Refus::IdentifiantDifferent)
    );
}

#[test]
fn chaque_refus_a_sa_phrase() {
    let refus = [
        Refus::Grammaire(asl_attest::Erreur::FormatInconnu),
        Refus::PasDeCleAttestee,
        Refus::Compteur { compteur: 3 },
        Refus::Environnement,
        Refus::App,
        Refus::ChaineVide,
        Refus::RacineIllisible,
        Refus::FeuilleIllisible,
        Refus::Chaine(webpki::Error::UnknownIssuer),
        Refus::CertificatIllisible,
        Refus::CleInattendue,
        Refus::NonceAbsent,
        Refus::NonceDifferent,
        Refus::IdentifiantDifferent,
    ];
    let mut phrases: Vec<String> = refus.iter().map(ToString::to_string).collect();
    assert!(phrases.iter().all(|p| !p.is_empty()));
    phrases.sort();
    phrases.dedup();
    assert_eq!(phrases.len(), refus.len(), "des phrases se répètent");
    assert_eq!(
        Refus::from(asl_attest::Erreur::FormatInconnu),
        Refus::Grammaire(asl_attest::Erreur::FormatInconnu)
    );
}

fn hex(octets: &[u8]) -> String {
    octets.iter().map(|o| format!("{o:02x}")).collect()
}
