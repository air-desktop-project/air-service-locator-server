//! Les pièces commitées disent-elles ce que leur nom prétend ?
//!
//! Deux jeux de fichiers sortent de la forge et sont COMMITÉS, parce que la
//! cible de fuzz ne peut pas tirer la forge (elle vit dans les essais) :
//!
//! - `tests/fixtures/racine-du-banc.der`, `cle-du-banc.bin`, `defi-du-banc.bin`
//!   — ce que la cible épingle et attend ;
//! - `fuzz/seeds/keystore/*` — les graines, réelles et forgées.
//!
//! La forge est déterministe : ces essais vérifient que les fichiers sont
//! EXACTEMENT ce qu'elle produit aujourd'hui, et que chaque graine rend le
//! verdict de son nom. `check-fuzz.sh` compte les graines et ne les lit pas ;
//! une graine « acceptée » qui serait refusée laisserait la campagne partir
//! d'un refus, et la propriété centrale de la cible — « tout `Ok` rend la clé
//! du banc » — ne serait jamais mise à l'épreuve, faute d'`Ok`.
//!
//! Pour régénérer après un changement de la forge :
//! `cargo test -p asl-keystore --test graines -- --ignored ecrire`.

mod forge;

use std::fs;
use std::path::PathBuf;

use asl_keystore::{Attendu, Demarrage, Refus, case, verifier};
use forge::{Banc, Portrait, piece, racine_de_confiance};

fn chemin_de_graine(nom: &str) -> PathBuf {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../fuzz/seeds/keystore");
    chemin.push(nom);
    chemin
}

fn graine(nom: &str) -> Vec<u8> {
    let chemin = chemin_de_graine(nom);
    fs::read(&chemin).unwrap_or_else(|faute| panic!("graine {chemin:?} illisible : {faute}"))
}

fn capture(nom: &str) -> Vec<u8> {
    let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chemin.push("../../docs/attestation/captures/keystore-fp5-2026-09-16");
    chemin.push(nom);
    fs::read(&chemin).unwrap_or_else(|faute| panic!("capture {chemin:?} illisible : {faute}"))
}

/// Ce que la forge produit, nom par nom.
fn pieces_et_graines(banc: &Banc) -> Vec<(PathBuf, Vec<u8>)> {
    let fixtures = |nom: &str| {
        let mut chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        chemin.push("tests/fixtures");
        chemin.push(nom);
        chemin
    };
    let mut mauvais_defi = Portrait::coherent(&banc.defi);
    mauvais_defi.defi = b"un autre defi".to_vec();
    let non_verifie =
        Portrait::coherent(&banc.defi).avec_materiel(704, &racine_de_confiance(true, 2));
    let reelle: Vec<Vec<u8>> = (0..4).map(|i| capture(&format!("cert{i}.der"))).collect();
    let reelle: Vec<&[u8]> = reelle.iter().map(Vec::as_slice).collect();
    vec![
        (fixtures("racine-du-banc.der"), banc.racine_der.clone()),
        (
            fixtures("cle-du-banc.bin"),
            banc.appareil.compresse().to_vec(),
        ),
        (fixtures("defi-du-banc.bin"), banc.defi.clone()),
        (
            chemin_de_graine("reelle-entiere"),
            case::assembler(&reelle).expect("la case tient"),
        ),
        (
            chemin_de_graine("reelle-sans-racine"),
            case::assembler(&reelle[..3]).expect("la case tient"),
        ),
        (
            chemin_de_graine("banc-acceptee"),
            banc.case(&Portrait::coherent(&banc.defi)),
        ),
        (
            chemin_de_graine("refus-defi-faux"),
            banc.case(&mauvais_defi),
        ),
        (
            chemin_de_graine("refus-demarrage-non-verifie"),
            banc.case(&non_verifie),
        ),
        (
            chemin_de_graine("refus-case-tronquee"),
            vec![0x02, 0x00, 0x30, 0x00],
        ),
    ]
}

#[test]
fn les_pieces_commitees_sont_celles_que_la_forge_produit() {
    let banc = Banc::nouveau();
    for (chemin, attendu) in pieces_et_graines(&banc) {
        let lu = fs::read(&chemin).unwrap_or_else(|faute| panic!("{chemin:?} : {faute}"));
        assert_eq!(lu, attendu, "{chemin:?} n'est plus ce que la forge produit");
    }
}

#[test]
#[ignore = "écrit les pièces : à relancer quand la forge change"]
fn ecrire_les_pieces() {
    let banc = Banc::nouveau();
    for (chemin, octets) in pieces_et_graines(&banc) {
        fs::write(&chemin, octets).unwrap_or_else(|faute| panic!("{chemin:?} : {faute}"));
    }
}

#[test]
fn chaque_graine_rend_le_verdict_de_son_nom() {
    let banc = Banc::nouveau();
    let racine = piece("racine-du-banc.der");
    let cle: [u8; 33] = piece("cle-du-banc.bin").try_into().expect("33 octets");
    let racines = [racine.as_slice()];
    let attendu = banc.attendu(&racines, &cle);

    let verdict = verifier(&graine("banc-acceptee"), &attendu)
        .unwrap_or_else(|refus| panic!("banc-acceptee devrait passer, et rend {refus}"));
    assert_eq!(&verdict.cle[..], &banc.appareil.point()[..]);
    assert_eq!(
        verifier(&graine("refus-defi-faux"), &attendu),
        Err(Refus::DefiDifferent)
    );
    assert_eq!(
        verifier(&graine("refus-demarrage-non-verifie"), &attendu),
        Err(Refus::DemarrageNonVerifie(Demarrage::NonVerifie))
    );
    assert_eq!(
        verifier(&graine("refus-case-tronquee"), &attendu),
        Err(Refus::Case(case::Faute::Tronquee {
            rang: 0,
            annoncee: 512,
            restant: 2
        }))
    );

    // Les graines réelles, sous la racine de Google et au jour de la capture.
    let google = capture("cert3.der");
    let cert0 = capture("cert0.der");
    let feuille = asl_keystore::x509::lire(&cert0).expect("la feuille");
    let cle_reelle = asl_keystore::x509::compresser(feuille.cle.try_into().expect("65 octets"));
    let defi = capture("defi.bin");
    let empreinte: [u8; 32] = (0..32)
        .map(|i| {
            u8::from_str_radix(
                &"5ea316f1b50f2ce54b8225aba85ff5cc8238a710b8fae44b4f3a195aadeb5f68"
                    [2 * i..2 * i + 2],
                16,
            )
            .expect("hexadécimal")
        })
        .collect::<Vec<u8>>()
        .try_into()
        .expect("32 octets");
    let racines = [google.as_slice()];
    let reel = Attendu {
        racines: &racines,
        defi: &defi,
        cle: &cle_reelle,
        paquet: "org.airdesktop.servicelocator",
        empreinte: &empreinte,
        maintenant: 1_789_560_000,
    };
    for nom in ["reelle-entiere", "reelle-sans-racine"] {
        verifier(&graine(nom), &reel)
            .unwrap_or_else(|refus| panic!("{nom} devrait passer, et rend {refus}"));
    }
    // Et sous la racine du banc, les graines réelles sont refusées à la
    // chaîne : c'est ce que la cible verra d'elles.
    for nom in ["reelle-entiere", "reelle-sans-racine"] {
        assert!(matches!(
            verifier(&graine(nom), &attendu),
            Err(Refus::Chaine(_))
        ));
    }
}
