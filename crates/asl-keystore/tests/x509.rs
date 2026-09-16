//! Le marcheur DER refuse tout ce qui n'a pas la forme, et ne panique jamais.
//!
//! Même méthode qu'`asl-apple` : plutôt qu'un cas écrit à la main par élément,
//! on prend une feuille RÉELLE — celle du Fairphone 5 — et on abîme chaque
//! octet, de plusieurs façons. Ce qui est affirmé : pas de panique, et soit un
//! refus nommé, soit une feuille dont la clé fait 65 octets. La couverture dit
//! si chaque refus a été atteint.

mod forge;

use std::path::PathBuf;

use asl_keystore::Refus;
use asl_keystore::x509::{Feuille, POINT_OCTETS, compresser, lire};
use forge::{Banc, Cle, OID_DESCRIPTION, Portrait, booleen, element, octets, oid, sequence};

fn feuille_reelle() -> Vec<u8> {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../docs/attestation/captures/keystore-fp5-2026-09-16/cert0.der");
    std::fs::read(&chemin).expect("la capture est dans le dépôt")
}

fn plausible(resultat: Result<Feuille<'_>, Refus>) {
    match resultat {
        Ok(feuille) => assert_eq!(feuille.cle.len(), POINT_OCTETS),
        Err(Refus::CertificatIllisible | Refus::CleInattendue) => {}
        Err(autre) => panic!("un refus qui n'est pas du marcheur : {autre:?}"),
    }
}

#[test]
fn chaque_prefixe_est_refuse_sans_panique() {
    let feuille = feuille_reelle();
    for n in 0..feuille.len() {
        assert!(
            matches!(lire(&feuille[..n]), Err(Refus::CertificatIllisible)),
            "tronquée à {n}"
        );
    }
}

#[test]
fn chaque_octet_abime_est_refuse_ou_lu_sans_panique() {
    let feuille = feuille_reelle();
    for i in 0..feuille.len() {
        for valeur in [feuille[i] ^ 0xFF, 0x00, 0x01, 0x7F, 0x80, 0x81, 0x82, 0xBF] {
            let mut abimee = feuille.clone();
            abimee[i] = valeur;
            plausible(lire(&abimee));
        }
    }
}

#[test]
fn une_cle_compressee_ou_d_une_autre_courbe_est_inattendue() {
    let banc = Banc::nouveau();
    let p384 = Cle::p384(&[0x55; 48]);
    assert_eq!(
        lire(&banc.feuille_de(&p384, None)),
        Err(Refus::CleInattendue)
    );
    // Un point compressé (33 octets) sous l'OID de P-256.
    let mut spki = banc.appareil.spki();
    let point = compresser(banc.appareil.point().as_slice().try_into().expect("65"));
    let bits = forge::bits(&point);
    let debut = spki.len() - 2 - POINT_OCTETS - 2;
    spki.truncate(debut);
    spki.extend_from_slice(&bits);
    // Réécrit la longueur de la SEQUENCE extérieure.
    let interieur = spki[2..].to_vec();
    let spki = sequence(&[&interieur]);
    let feuille = forge::certificat_depuis_spki(
        1,
        "TEE du banc",
        "Android Keystore Key",
        &spki,
        &banc.tee,
        forge::Condensat::Sha256,
        &forge::extensions_de_feuille(None),
    );
    assert_eq!(lire(&feuille), Err(Refus::CleInattendue));
}

#[test]
fn l_extension_se_lit_avec_ou_sans_drapeau_critique_et_les_autres_sont_sautees() {
    let banc = Banc::nouveau();
    let description = Portrait::coherent(&banc.defi).encoder();
    // Critique, et derrière une autre extension.
    let extensions = vec![
        sequence(&[
            &oid(&[0x55, 0x1D, 0x0F]),
            &booleen(true),
            &octets(&[0x03, 0x02, 0x07, 0x80]),
        ]),
        sequence(&[&oid(OID_DESCRIPTION), &booleen(true), &octets(&description)]),
    ];
    let feuille = forge::certificat(
        1,
        "TEE du banc",
        "Android Keystore Key",
        &banc.appareil,
        &banc.tee,
        forge::Condensat::Sha256,
        &extensions,
    );
    let lue = lire(&feuille).expect("elle se lit");
    assert_eq!(lue.description, Some(&description[..]));
    // Sans drapeau, c'est ce que la forge écrit d'habitude.
    let ordinaire = banc.feuille(&Portrait::coherent(&banc.defi));
    let lue = lire(&ordinaire).expect("elle se lit");
    assert_eq!(lue.description, Some(&description[..]));
    assert_eq!(lue.cle, &banc.appareil.point()[..]);
}

#[test]
fn un_identifiant_unique_d_emetteur_est_saute() {
    // `issuerUniqueID [1] IMPLICIT BIT STRING` entre le SPKI et les
    // extensions : le marcheur le passe, et trouve les extensions derrière.
    let banc = Banc::nouveau();
    let feuille = banc.feuille(&Portrait::coherent(&banc.defi));
    use asl_keystore::der;
    let (certificat, _) = der::attendu(&feuille, der::SEQUENCE).expect("un certificat");
    let (tbs, apres_tbs) = der::attendu(certificat, der::SEQUENCE).expect("un TBS");
    // Le TBS finit par `[3] extensions` : on insère `[1]` juste devant.
    let mut reste = tbs;
    let avant_extensions = loop {
        let (lu, suite) = der::element(reste).expect("un élément");
        if lu.balise == der::Balise::contextuelle(3) {
            break tbs.len() - reste.len();
        }
        reste = suite;
    };
    let mut nouveau_tbs = tbs[..avant_extensions].to_vec();
    nouveau_tbs.extend_from_slice(&element(&[0x81], &[0x00, 0xAB]));
    nouveau_tbs.extend_from_slice(&tbs[avant_extensions..]);
    let cert = sequence(&[&sequence(&[&nouveau_tbs]), apres_tbs]);
    let lue = lire(&cert).expect("le marcheur passe [1]");
    assert!(lue.description.is_some());
}

#[test]
fn compresser_dit_la_parite_de_y() {
    let mut point = [0x04; POINT_OCTETS];
    point[64] = 0x02;
    assert_eq!(compresser(&point)[0], 0x02);
    point[64] = 0x03;
    assert_eq!(compresser(&point)[0], 0x03);
    assert_eq!(&compresser(&point)[1..], &point[1..33]);
}
