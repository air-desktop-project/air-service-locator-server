//! Le marcheur DER refuse tout ce qui n'a pas la forme, et ne panique jamais.
//!
//! # POURQUOI DES MUTATIONS PLUTÔT QUE DES CAS ÉCRITS UN À UN
//!
//! Le marcheur descend dans une douzaine d'éléments, et chacun peut manquer,
//! être tronqué ou porter une autre balise. Écrire un certificat à la main pour
//! chaque cas serait long et, surtout, ne prouverait que ce qu'on a pensé à
//! écrire. On prend donc une feuille RÉELLE du banc et on abîme chaque octet,
//! de trois façons — ce qui atteint chaque élément par sa balise ET par sa
//! longueur.
//!
//! Ce qui est affirmé pour chaque mutation : pas de panique, et un résultat
//! qui est soit un refus nommé, soit une feuille dont la clé fait 65 octets.
//! La couverture, elle, dit si chaque refus a bien été atteint.

mod forge;

use asl_apple::Refus;
use asl_apple::x509::{Feuille, POINT_OCTETS, lire};
use forge::{Banc, certificat, der, enfants_du_certificat, piece};

fn plausible(resultat: Result<Feuille<'_>, Refus>) {
    match resultat {
        Ok(feuille) => {
            assert_eq!(feuille.cle.len(), POINT_OCTETS);
            assert!(feuille.nonce.is_none_or(|n| n.len() == 32));
        }
        Err(Refus::CertificatIllisible | Refus::CleInattendue) => {}
        Err(autre) => panic!("un refus qui n'est pas du marcheur : {autre:?}"),
    }
}

#[test]
fn la_feuille_du_banc_rend_sa_cle_et_son_nonce() {
    let banc = Banc::charger();
    let feuille = lire(&banc.feuille).expect("une feuille bien formée");
    assert_eq!(feuille.cle, banc.cle.as_slice());
    assert_eq!(feuille.nonce.map(<[u8]>::len), Some(32));
    let sans_nonce = piece("feuille-sans-nonce.der");
    let sans = lire(&sans_nonce).expect("bien formée aussi");
    assert_eq!(sans.nonce, None);
}

#[test]
fn chaque_prefixe_est_refuse_sans_panique() {
    let banc = Banc::charger();
    for n in 0..banc.feuille.len() {
        assert!(
            matches!(lire(&banc.feuille[..n]), Err(Refus::CertificatIllisible)),
            "tronquée à {n}"
        );
    }
}

#[test]
fn chaque_octet_abime_est_refuse_ou_lu_sans_panique() {
    let banc = Banc::charger();
    for i in 0..banc.feuille.len() {
        for valeur in [banc.feuille[i] ^ 0xFF, 0x00, 0x01, 0x7F, 0x80] {
            let mut abimee = banc.feuille.clone();
            abimee[i] = valeur;
            plausible(lire(&abimee));
        }
    }
}

#[test]
fn les_en_tetes_de_longueur_tronques_ou_reserves_sont_refuses() {
    for octets in [
        &[][..],
        &[0x30],
        &[0x30, 0x81],
        &[0x30, 0x82, 0x01],
        &[0x30, 0x83, 0x00, 0x00, 0x01],
        &[0x30, 0x80],
    ] {
        assert_eq!(
            lire(octets),
            Err(Refus::CertificatIllisible),
            "pour {octets:02x?}"
        );
    }
}

#[test]
fn un_certificat_v1_sans_champ_de_version_se_lit_aussi() {
    // La feuille du banc est v3, avec `[0] EXPLICIT version` en tête du TBS.
    // On la réécrit sans : le premier élément devient le numéro de série, et
    // c'est la branche que `openssl` ne produit jamais.
    let banc = Banc::charger();
    let [
        (debut_tbs, fin_tbs),
        (debut_alg, fin_alg),
        (debut_sig, fin_sig),
    ] = enfants_du_certificat(&banc.feuille);
    let (_, fin_version) = der(&banc.feuille, debut_tbs);
    let tbs_sans_version = &banc.feuille[fin_version..fin_tbs];
    // Les enfants sont réemballés avec leur en-tête : on recule de deux octets
    // seulement quand la longueur tient sur un octet.
    let algorithme = &banc.feuille[debut_alg - 2..fin_alg];
    let signature = &banc.feuille[debut_sig - 2..fin_sig];
    let v1 = certificat(tbs_sans_version, algorithme, signature);
    let feuille = lire(&v1).expect("la version est facultative");
    assert_eq!(feuille.cle, banc.cle.as_slice());
}
