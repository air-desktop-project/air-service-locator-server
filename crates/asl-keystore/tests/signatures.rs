//! Les cinq vérificateurs de `signature.rs` : chacun accepte une bonne
//! signature, et refuse une signature mal formée, une clé mal formée, une
//! signature fausse.
//!
//! `webpki` ne se trompe pas sur ces cas : c'est NOTRE code qui les lui rend,
//! et chacun est un chemin qu'un banc cohérent ne prend jamais.
//!
//! **RSA est éprouvé sous la racine RSA du banc** (`fixtures/racine-rsa.der`,
//! RSA-2048), et pas seulement sur la chaîne réelle : là, on peut abîmer la
//! signature et la clé, ce qu'on ne fait pas à la racine de Google.

mod forge;

use asl_keystore::{Attendu, Refus, case, verifier};
use forge::{
    Banc, Cle, Condensat, PENDANT, Portrait, SCALAIRE_SOUS_RSA, certificat, certificat_depuis_spki,
    extensions_d_autorite, extensions_de_feuille, piece,
};

/// Le 1er janvier 2027 : dans la validité des certificats RSA du banc, frappés
/// le 2026-09-16 pour dix ans.
const EN_2027: u64 = 1_798_761_600;

/// Une chaîne à éprouver : la feuille, son émettrice prise pour ancre, et
/// l'instant.
struct Epreuve {
    nom: &'static str,
    feuille: Vec<u8>,
    ancre: Vec<u8>,
    maintenant: u64,
}

fn verdict(epreuve: &Epreuve, feuille: &[u8], ancre: &[u8], banc: &Banc) -> Result<(), Refus> {
    let cle = banc.appareil.compresse();
    let racines = [ancre];
    let attendu = Attendu {
        maintenant: epreuve.maintenant,
        ..banc.attendu(&racines, &cle)
    };
    let case = case::assembler(&[feuille]).expect("la case tient");
    verifier(&case, &attendu).map(|_| ())
}

/// Les cinq chaînes, une par vérificateur : `(feuille, émettrice)`, la
/// feuille signée par l'émettrice avec l'algorithme qu'on veut éprouver.
fn epreuves(banc: &Banc) -> Vec<Epreuve> {
    let description = Portrait::coherent(&banc.defi).encoder();
    let feuille = |emetteur: &str, signataire: &Cle, condensat: Condensat| {
        certificat(
            1,
            emetteur,
            "Android Keystore Key",
            &banc.appareil,
            signataire,
            condensat,
            &extensions_de_feuille(Some(&description)),
        )
    };
    let autorite = |nom: &str, cle: &Cle, condensat: Condensat| {
        certificat(1, nom, nom, cle, cle, condensat, &extensions_d_autorite())
    };
    let p384 = Cle::p384(&[0x77; 48]);
    vec![
        Epreuve {
            nom: "P-256/SHA-256",
            feuille: feuille("TEE du banc", &banc.tee, Condensat::Sha256),
            ancre: banc.tee_der.clone(),
            maintenant: PENDANT,
        },
        Epreuve {
            nom: "P-256/SHA-384",
            feuille: feuille("TEE du banc", &banc.tee, Condensat::Sha384),
            ancre: autorite("TEE du banc", &banc.tee, Condensat::Sha384),
            maintenant: PENDANT,
        },
        Epreuve {
            nom: "P-384/SHA-256",
            feuille: feuille("Autorite P-384", &p384, Condensat::Sha256),
            ancre: autorite("Autorite P-384", &p384, Condensat::Sha256),
            maintenant: PENDANT,
        },
        Epreuve {
            nom: "P-384/SHA-384",
            feuille: feuille("Autorite P-384", &p384, Condensat::Sha384),
            ancre: autorite("Autorite P-384", &p384, Condensat::Sha384),
            maintenant: PENDANT,
        },
    ]
}

#[test]
fn une_feuille_bien_signee_remonte_a_son_emettrice_prise_pour_ancre() {
    // Le témoin : sans abîmer quoi que ce soit, les quatre chaînes ECDSA
    // passent quand l'émettrice sert d'ancre. Sans ce témoin, les refus
    // ci-dessous pourraient venir d'autre chose que de ce qu'on a abîmé.
    let banc = Banc::nouveau();
    for epreuve in epreuves(&banc) {
        verdict(&epreuve, &epreuve.feuille, &epreuve.ancre, &banc)
            .unwrap_or_else(|refus| panic!("{} : {refus}", epreuve.nom));
    }
}

/// Où commence, dans un certificat du banc, le BIT STRING de la signature :
/// c'est le dernier élément, et il commence par `03 <longueur> 00`.
fn debut_de_la_signature(cert: &[u8]) -> usize {
    use asl_keystore::der;
    let (certificat, _) = der::attendu(cert, der::SEQUENCE).expect("un certificat");
    let (_, apres_tbs) = der::attendu(certificat, der::SEQUENCE).expect("un TBS");
    let (_, apres_alg) = der::attendu(apres_tbs, der::SEQUENCE).expect("un algorithme");
    cert.len().saturating_sub(apres_alg.len())
}

#[test]
fn une_signature_qui_n_est_pas_du_der_est_refusee() {
    let banc = Banc::nouveau();
    for epreuve in epreuves(&banc) {
        let mut feuille = epreuve.feuille.clone();
        let debut = debut_de_la_signature(&feuille);
        // `03 len 00 30 …` : on change la balise de la SEQUENCE ECDSA.
        assert_eq!(feuille[debut + 3], 0x30, "{}", epreuve.nom);
        feuille[debut + 3] = 0x31;
        assert!(
            matches!(
                verdict(&epreuve, &feuille, &epreuve.ancre, &banc),
                Err(Refus::Chaine(_))
            ),
            "{}",
            epreuve.nom
        );
    }
}

#[test]
fn une_signature_fausse_mais_bien_formee_est_refusee() {
    let banc = Banc::nouveau();
    for epreuve in epreuves(&banc) {
        let mut feuille = epreuve.feuille.clone();
        let dernier = feuille.len() - 1;
        feuille[dernier] ^= 0x01;
        assert!(
            matches!(
                verdict(&epreuve, &feuille, &epreuve.ancre, &banc),
                Err(Refus::Chaine(_))
            ),
            "{}",
            epreuve.nom
        );
    }
}

/// Où commence, dans un certificat, le point public — l'octet `04` du point
/// non compressé, derrière `03 <longueur> 00`.
fn debut_du_point(cert: &[u8]) -> usize {
    (0..cert.len())
        .find(|&i| {
            matches!(
                cert.get(i..i.saturating_add(4)),
                Some([0x03, 0x42 | 0x62, 0x00, 0x04])
            )
        })
        .map(|i| i.saturating_add(3))
        .expect("un point public")
}

#[test]
fn une_cle_d_emettrice_qui_n_est_pas_un_point_est_refusee() {
    let banc = Banc::nouveau();
    for epreuve in epreuves(&banc) {
        let mut ancre = epreuve.ancre.clone();
        let point = debut_du_point(&ancre);
        ancre[point] = 0x05;
        assert!(
            matches!(
                verdict(&epreuve, &epreuve.feuille, &ancre, &banc),
                Err(Refus::Chaine(_))
            ),
            "{}",
            epreuve.nom
        );
    }
}

// ── RSA ─────────────────────────────────────────────────────────────────────

/// La chaîne sous la racine RSA : une feuille signée par l'intermédiaire
/// P-256 des `fixtures/`, lui-même signé en RSA/SHA-256 par la racine.
fn chaine_rsa(banc: &Banc) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let intermediaire = Cle::p256(&SCALAIRE_SOUS_RSA);
    let feuille = certificat(
        1,
        "Intermediaire sous RSA",
        "Android Keystore Key",
        &banc.appareil,
        &intermediaire,
        Condensat::Sha256,
        &extensions_de_feuille(Some(&Portrait::coherent(&banc.defi).encoder())),
    );
    (
        feuille,
        piece("intermediaire-sous-rsa.der"),
        piece("racine-rsa.der"),
    )
}

fn verdict_rsa(
    feuille: &[u8],
    intermediaire: &[u8],
    racine: &[u8],
    banc: &Banc,
) -> Result<(), Refus> {
    let cle = banc.appareil.compresse();
    let racines = [racine];
    let attendu = Attendu {
        maintenant: EN_2027,
        ..banc.attendu(&racines, &cle)
    };
    let case = case::assembler(&[feuille, intermediaire]).expect("la case tient");
    verifier(&case, &attendu).map(|_| ())
}

#[test]
fn une_chaine_sous_la_racine_rsa_du_banc_remonte() {
    let banc = Banc::nouveau();
    let (feuille, intermediaire, racine) = chaine_rsa(&banc);
    verdict_rsa(&feuille, &intermediaire, &racine, &banc)
        .unwrap_or_else(|refus| panic!("sous RSA : {refus}"));
}

#[test]
fn une_signature_rsa_fausse_est_refusee() {
    let banc = Banc::nouveau();
    let (feuille, mut intermediaire, racine) = chaine_rsa(&banc);
    // La signature RSA est le dernier BIT STRING de l'intermédiaire.
    let dernier = intermediaire.len() - 1;
    intermediaire[dernier] ^= 0x01;
    assert!(matches!(
        verdict_rsa(&feuille, &intermediaire, &racine, &banc),
        Err(Refus::Chaine(_))
    ));
}

#[test]
fn une_cle_rsa_qui_n_est_pas_du_pkcs1_est_refusee() {
    // La racine, avec son module abîmé : `RSAPublicKey` ne se lit plus. Rien
    // ne vérifie la signature d'une ancre, donc l'ancre reste « lisible » pour
    // `webpki` — c'est notre vérificateur qui la refuse.
    let banc = Banc::nouveau();
    let (feuille, intermediaire, mut racine) = chaine_rsa(&banc);
    // Le SPKI RSA : `30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 …`
    // — on cherche le `30 82 01 0a` de `RSAPublicKey` et on casse sa balise.
    let position = (0..racine.len())
        .find(|&i| racine.get(i..i + 4) == Some(&[0x30, 0x82, 0x01, 0x0A]))
        .expect("un RSAPublicKey de 2048 bits");
    racine[position] = 0x31;
    assert!(matches!(
        verdict_rsa(&feuille, &intermediaire, &racine, &banc),
        Err(Refus::Chaine(_))
    ));
}

#[test]
fn un_spki_que_personne_ne_tient_ne_signe_rien() {
    // Une émettrice dont le SPKI est écrit à la main, sans clé derrière : la
    // feuille est signée par le TEE, l'ancre annonce le point d'une autre
    // courbe sous l'OID de P-256 — `from_sec1_bytes` la refuse.
    let banc = Banc::nouveau();
    let mut spki = banc.tee.spki();
    let point = debut_du_point(&spki);
    spki[point + 1] ^= 0xFF;
    let ancre = certificat_depuis_spki(
        1,
        "TEE du banc",
        "TEE du banc",
        &spki,
        &banc.tee,
        Condensat::Sha256,
        &extensions_d_autorite(),
    );
    let epreuve = Epreuve {
        nom: "point hors courbe",
        feuille: banc.feuille(&Portrait::coherent(&banc.defi)),
        ancre,
        maintenant: PENDANT,
    };
    assert!(matches!(
        verdict(&epreuve, &epreuve.feuille, &epreuve.ancre, &banc),
        Err(Refus::Chaine(_))
    ));
}
